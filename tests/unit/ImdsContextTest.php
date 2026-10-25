<?php
/**
 * Unit tests for IMDS resolution outside admin/wp-cron contexts
 *
 * Instance-role credentials and the region must be resolved from IMDS in every
 * context (REST API, WP-CLI, frontend), not only when is_admin() or DOING_CRON is true.
 * The 'eventbridge_should_try_imds' filter can turn IMDS off.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

class ImdsContextTest extends TestCase
{
    /**
     * Transients returned by the get_transient() mock, keyed by transient name
     *
     * @var array
     */
    private $transients = array();

    /**
     * Whether the eventbridge_should_try_imds filter allows IMDS
     *
     * @var bool
     */
    private $allow_imds = true;

    /**
     * AWS_* environment variables removed for the test, restored in tearDown()
     *
     * @var array
     */
    private $saved_env = array();

    /**
     * error_log ini value restored in tearDown()
     *
     * @var string|false
     */
    private $saved_error_log = false;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        $this->transients = array();
        $this->allow_imds = true;

        // The plugin logs IMDS failures with error_log(). A test running in a separate process
        // fails on any stderr output, so discard the log while these tests run.
        $this->saved_error_log = ini_get('error_log');
        ini_set('error_log', '/dev/null');

        // Hide AWS_* credentials from the host environment so the instance role is the only source
        $this->saved_env = array();
        foreach (array('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN') as $name) {
            $this->saved_env[$name] = array(
                'getenv' => getenv($name),
                'env' => $_ENV[$name] ?? null,
                'server' => $_SERVER[$name] ?? null,
            );
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }

        // Mock WordPress functions BEFORE loading plugin file
        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('sanitize_text_field')->alias(function($str) {
            return strip_tags($str);
        });
        Functions\when('get_post_types')->justReturn([
            'post' => (object)['name' => 'post', 'label' => 'Posts'],
        ]);
        Functions\when('apply_filters')->alias(function($filter, $value) {
            if ($filter === 'eventbridge_should_try_imds') {
                return $this->allow_imds;
            }
            return $value;
        });
        Functions\when('wp_parse_args')->alias(function($args, $defaults) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            }
            if (is_array($args)) {
                return array_merge($defaults, $args);
            }
            return $defaults;
        });
        Functions\when('get_option')->justReturn(false);
        Functions\when('get_transient')->alias(function($name) {
            return array_key_exists($name, $this->transients) ? $this->transients[$name] : false;
        });
        Functions\when('set_transient')->alias(function($name, $value) {
            $this->transients[$name] = $value;
            return true;
        });
        Functions\when('delete_transient')->alias(function($name) {
            unset($this->transients[$name]);
            return true;
        });
        Functions\when('register_activation_hook')->justReturn(null);
        Functions\when('register_deactivation_hook')->justReturn(null);
        Functions\when('add_action')->justReturn(null);
        Functions\when('add_filter')->justReturn(null);
        // Mock wp_remote_request to prevent actual HTTP calls during plugin initialization
        Functions\when('wp_remote_request')->justReturn(
            new \WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('is_wp_error')->alias(function($thing) {
            return $thing instanceof \WP_Error;
        });
        // Neither admin nor wp-cron: the REST API / WP-CLI / frontend case
        Functions\when('is_admin')->justReturn(false);

        // Load the plugin file to get EventBridgePostEvents class (after mocks are set up)
        if (!class_exists('EventBridgePostEvents')) {
            require_once dirname(dirname(__DIR__)) . '/event-publisher-on-aws.php';
        }

        // Loading the plugin runs its constructor, which may cache an IMDS failure; start each test clean
        $this->transients = array();
    }

    protected function tearDown(): void
    {
        ini_set('error_log', $this->saved_error_log === false ? '' : $this->saved_error_log);

        foreach ($this->saved_env as $name => $saved) {
            if ($saved['getenv'] !== false) {
                putenv($name . '=' . $saved['getenv']);
            }
            if ($saved['env'] !== null) {
                $_ENV[$name] = $saved['env'];
            }
            if ($saved['server'] !== null) {
                $_SERVER[$name] = $saved['server'];
            }
        }

        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Call a private method on an EventBridgePostEvents instance created without its constructor
     *
     * @param string $method Method name
     * @return mixed
     */
    private function call_private($method)
    {
        $reflection = new \ReflectionClass('EventBridgePostEvents');
        $instance = $reflection->newInstanceWithoutConstructor();
        $target = $reflection->getMethod($method);
        $target->setAccessible(true);
        return $target->invoke($instance);
    }

    /**
     * Mock IMDS so that the token, role name and role credentials requests succeed
     */
    private function mock_imds_credentials_endpoint()
    {
        $credentials_body = json_encode([
            'AccessKeyId' => 'ASIAINSTANCEROLE',
            'SecretAccessKey' => 'instance-role-secret',
            'Token' => 'instance-role-token',
            'Expiration' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600),
        ]);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => 'imds-token',
        ]);
        Functions\when('wp_remote_get')->alias(function($url) use ($credentials_body) {
            $body = substr($url, -1) === '/' ? 'my-instance-role' : $credentials_body;
            return [
                'response' => ['code' => 200],
                'body' => $body,
            ];
        });
        Functions\when('wp_remote_retrieve_response_code')->alias(function($response) {
            return $response['response']['code'];
        });
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });
    }

    /**
     * Cached instance-role credentials are used outside admin/wp-cron
     */
    public function test_cached_instance_credentials_used_outside_admin_and_cron()
    {
        $this->assertFalse(defined('DOING_CRON'));

        $cached = [
            'AccessKeyId' => 'ASIACACHED',
            'SecretAccessKey' => 'cached-secret',
            'Token' => 'cached-token',
            'Expiration' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600),
        ];
        $this->transients[\EventBridgePostEvents::TRANSIENT_IMDS_CREDENTIALS] = $cached;

        $this->assertSame($cached, $this->call_private('get_instance_credentials'));
    }

    /**
     * Instance-role credentials are fetched from IMDS outside admin/wp-cron when nothing is cached
     */
    public function test_instance_credentials_fetched_from_imds_outside_admin_and_cron()
    {
        $this->mock_imds_credentials_endpoint();

        $credentials = $this->call_private('get_instance_credentials');

        $this->assertIsArray($credentials);
        $this->assertSame('ASIAINSTANCEROLE', $credentials['AccessKeyId']);
        $this->assertSame('instance-role-token', $credentials['Token']);
        $this->assertSame(
            $credentials,
            $this->transients[\EventBridgePostEvents::TRANSIENT_IMDS_CREDENTIALS]
        );
    }

    /**
     * get_aws_credentials() resolves the instance role outside admin/wp-cron
     *
     * Runs in a separate process because other tests define the AWS_EVENTBRIDGE_* constants,
     * which take precedence over the instance role and cannot be undefined.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_aws_credentials_resolve_instance_role_outside_admin_and_cron()
    {
        $this->mock_imds_credentials_endpoint();

        $credentials = $this->call_private('get_aws_credentials');

        $this->assertIsArray($credentials);
        $this->assertSame('instance_role', $credentials['source']);
        $this->assertSame('ASIAINSTANCEROLE', $credentials['access_key_id']);
        $this->assertSame('instance-role-token', $credentials['session_token']);
    }

    /**
     * The filter returning false skips IMDS, even when credentials are cached
     */
    public function test_filter_false_skips_instance_credentials()
    {
        $this->allow_imds = false;
        $this->transients[\EventBridgePostEvents::TRANSIENT_IMDS_CREDENTIALS] = [
            'AccessKeyId' => 'ASIACACHED',
            'SecretAccessKey' => 'cached-secret',
            'Token' => 'cached-token',
            'Expiration' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600),
        ];
        Functions\expect('wp_remote_get')->never();

        $this->assertNull($this->call_private('get_instance_credentials'));
    }

    /**
     * The region is detected from IMDS outside admin/wp-cron when the region cache has expired
     */
    public function test_region_detected_from_imds_outside_admin_and_cron()
    {
        $this->transients[\EventBridgePostEvents::TRANSIENT_IMDS_IDENTITY] = [
            'region' => 'ap-northeast-1',
        ];

        $region = $this->call_private('get_aws_region');

        $this->assertSame('ap-northeast-1', $region['region']);
        $this->assertSame('metadata', $region['source']);
        $this->assertSame(
            $region,
            $this->transients[\EventBridgePostEvents::TRANSIENT_CACHED_REGION]
        );
    }

    /**
     * The filter returning false skips IMDS region detection and falls back to us-east-1
     */
    public function test_filter_false_falls_back_to_default_region()
    {
        $this->allow_imds = false;
        $this->transients[\EventBridgePostEvents::TRANSIENT_IMDS_IDENTITY] = [
            'region' => 'ap-northeast-1',
        ];

        $region = $this->call_private('get_aws_region');

        $this->assertSame('us-east-1', $region['region']);
        $this->assertSame('fallback', $region['source']);
    }
}
