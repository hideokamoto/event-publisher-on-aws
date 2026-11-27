<?php
/**
 * Security-focused unit tests (IMDS path hardening, log redaction).
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class SecurityHardeningTest extends TestCase
{
    private $transients = array();

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        $this->transients = array();

        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('sanitize_text_field')->alias(function ($str) {
            return strip_tags($str);
        });
        Functions\when('get_post_types')->justReturn([
            'post' => (object) ['name' => 'post', 'label' => 'Posts'],
        ]);
        Functions\when('apply_filters')->returnArg();
        Functions\when('wp_parse_args')->alias(function ($args, $defaults) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            }
            if (is_array($args)) {
                return array_merge($defaults, $args);
            }
            return $defaults;
        });
        Functions\when('get_option')->alias(function ($name, $default = false) {
            return $default;
        });
        Functions\when('get_transient')->alias(function ($key) {
            return array_key_exists($key, $this->transients) ? $this->transients[$key] : false;
        });
        Functions\when('set_transient')->alias(function ($key, $value) {
            $this->transients[$key] = $value;
            return true;
        });
        Functions\when('delete_transient')->alias(function ($key) {
            unset($this->transients[$key]);
            return true;
        });
        Functions\when('wp_json_encode')->alias(function ($data) {
            return json_encode($data);
        });

        if (!class_exists('EventBridgePostEvents', false)) {
            require_once dirname(__DIR__, 2) . '/src/EventBridgePostEvents.php';
        }
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function call_private($method, ...$args)
    {
        $reflection = new \ReflectionClass('EventBridgePostEvents');
        $instance = $reflection->newInstanceWithoutConstructor();
        $target = $reflection->getMethod($method);
        return $target->invokeArgs($instance, $args);
    }

    public function test_is_valid_imds_iam_role_name_rejects_path_segments()
    {
        $this->assertFalse($this->call_private('is_valid_imds_iam_role_name', '../evil'));
        $this->assertFalse($this->call_private('is_valid_imds_iam_role_name', "role\ninjected"));
        $this->assertTrue($this->call_private('is_valid_imds_iam_role_name', 'my-instance-role'));
    }

    public function test_invalid_imds_role_name_skips_credential_fetch()
    {
        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => 'imds-token',
        ]);
        Functions\when('wp_remote_get')->alias(function ($url) {
            if (substr($url, -1) === '/') {
                return [
                    'response' => ['code' => 200],
                    'body' => '../../latest/meta-data/',
                ];
            }
            $this->fail('Credential URL must not be requested for an invalid role name: ' . $url);
        });
        Functions\when('wp_remote_retrieve_response_code')->alias(function ($response) {
            return $response['response']['code'];
        });
        Functions\when('wp_remote_retrieve_body')->alias(function ($response) {
            return $response['body'];
        });

        $this->assertNull($this->call_private('get_instance_credentials'));
    }

    public function test_format_log_context_value_redacts_sensitive_keys()
    {
        $this->assertSame(
            '[REDACTED]',
            $this->call_private('format_log_context_value', 'secret_access_key', 'super-secret')
        );
        $this->assertSame(
            '[REDACTED]',
            $this->call_private('format_log_context_value', 'session_token', 'tok-123')
        );
        $this->assertSame(
            'sync',
            $this->call_private('format_log_context_value', 'send_mode', 'sync')
        );
    }
}