<?php
/**
 * Integration tests bootstrap file
 *
 * Loads WordPress test library for integration testing.
 *
 * @package EventBridge_Post_Events
 */

// Try to find WordPress test library
$wp_tests_dir = getenv('WP_TESTS_DIR');

if (!$wp_tests_dir) {
    // Default path in wp-env
    $wp_tests_dir = '/var/www/html/wp-content/plugins/event-publisher-on-aws/vendor/wp-phpunit/wp-phpunit';
}

// Alternative: Check if running inside wp-env container
if (!file_exists($wp_tests_dir . '/includes/functions.php')) {
    // Try wp-env default location
    $wp_tests_dir = '/wordpress-phpunit';
}

if (!file_exists($wp_tests_dir . '/includes/functions.php')) {
    echo "WordPress test library not found. Make sure you're running tests inside wp-env container.\n";
    echo "Run: npm run test:integration\n";
    exit(1);
}

// Give access to tests_add_filter() function
require_once $wp_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin()
{
    // Define test credentials before plugin loads
    if (!defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID')) {
        define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'test-access-key-id');
    }
    if (!defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
        define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'test-secret-access-key');
    }
    if (!defined('EVENT_BRIDGE_REGION')) {
        define('EVENT_BRIDGE_REGION', 'us-east-1');
    }

    require dirname(dirname(__DIR__)) . '/event-publisher-on-aws.php';
}

tests_add_filter('muplugins_loaded', '_manually_load_plugin');

// Start up the WP testing environment
require $wp_tests_dir . '/includes/bootstrap.php';

/**
 * Base test case for integration tests
 */
abstract class EventBridge_Integration_Test_Case extends WP_UnitTestCase
{
    /**
     * Mock HTTP responses
     *
     * @var array
     */
    protected static $mock_responses = array();

    /**
     * Set up before class
     */
    public static function set_up_before_class()
    {
        parent::set_up_before_class();

        // Add filter to mock HTTP requests
        add_filter('pre_http_request', array(static::class, 'mock_http_request'), 10, 3);
    }

    /**
     * Tear down after class
     */
    public static function tear_down_after_class()
    {
        remove_filter('pre_http_request', array(static::class, 'mock_http_request'), 10);
        parent::tear_down_after_class();
    }

    /**
     * Set up before each test
     */
    public function set_up()
    {
        parent::set_up();
        self::$mock_responses = array();
    }

    /**
     * Mock HTTP request filter
     *
     * @param false|array|WP_Error $preempt Whether to preempt the response
     * @param array $args HTTP request arguments
     * @param string $url The request URL
     * @return false|array|WP_Error
     */
    public static function mock_http_request($preempt, $args, $url)
    {
        foreach (self::$mock_responses as $pattern => $response) {
            if (strpos($url, $pattern) !== false) {
                return $response;
            }
        }
        return $preempt;
    }

    /**
     * Add a mock HTTP response
     *
     * @param string $url_pattern URL pattern to match
     * @param array $response Response array
     */
    protected function mock_http_response($url_pattern, $response)
    {
        self::$mock_responses[$url_pattern] = $response;
    }

    /**
     * Create a successful EventBridge response
     *
     * @return array
     */
    protected function get_success_response()
    {
        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => json_encode(array(
                'FailedEntryCount' => 0,
                'Entries' => array(
                    array('EventId' => 'test-event-id-12345'),
                ),
            )),
        );
    }

    /**
     * Create a partial failure EventBridge response
     *
     * @return array
     */
    protected function get_partial_failure_response()
    {
        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => json_encode(array(
                'FailedEntryCount' => 1,
                'Entries' => array(
                    array(
                        'ErrorCode' => 'InternalException',
                        'ErrorMessage' => 'Internal service error',
                    ),
                ),
            )),
        );
    }

    /**
     * Create an authentication error response
     *
     * @return array
     */
    protected function get_auth_error_response()
    {
        return array(
            'response' => array(
                'code' => 403,
                'message' => 'Forbidden',
            ),
            'body' => json_encode(array(
                '__type' => 'AccessDeniedException',
                'message' => 'User is not authorized to perform events:PutEvents',
            )),
        );
    }

    /**
     * Create a throttling error response
     *
     * @return array
     */
    protected function get_throttling_response()
    {
        return array(
            'response' => array(
                'code' => 429,
                'message' => 'Too Many Requests',
            ),
            'body' => json_encode(array(
                '__type' => 'ThrottlingException',
                'message' => 'Rate exceeded',
            )),
        );
    }
}
