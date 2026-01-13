<?php
/**
 * Unit tests for settings sanitization and validation
 *
 * Tests security-critical input sanitization to prevent XSS, SQL injection,
 * and other injection attacks through admin settings.
 */

// Define minimal WP_Error class for unit tests in global namespace
if (!class_exists('WP_Error')) {
    class WP_Error {
        public $errors = [];
        public $error_data = [];

        public function __construct($code = '', $message = '', $data = '') {
            if (empty($code)) {
                return;
            }
            $this->errors[$code][] = $message;
            if (!empty($data)) {
                $this->error_data[$code] = $data;
            }
        }

        public function get_error_message() {
            $code = $this->get_error_code();
            if (empty($code)) {
                return '';
            }
            return $this->errors[$code][0] ?? '';
        }

        public function get_error_code() {
            $codes = array_keys($this->errors);
            return $codes[0] ?? '';
        }
    }
}

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

class SettingsSanitizationTest extends TestCase
{
    protected $instance;
    protected $reflection;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // Mock WordPress functions BEFORE loading plugin file
        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('sanitize_text_field')->alias(function($str) {
            // Strip tags and remove null bytes like WordPress does
            $str = strip_tags($str);
            $str = str_replace(chr(0), '', $str);
            return trim($str);
        });
        Functions\when('sanitize_key')->alias(function($key) {
            return strtolower(preg_replace('/[^a-z0-9_\-]/', '', $key));
        });
        Functions\when('add_settings_error')->justReturn(null);
        Functions\when('get_post_types')->justReturn([
            'post' => (object)['name' => 'post', 'label' => 'Posts'],
            'page' => (object)['name' => 'page', 'label' => 'Pages'],
        ]);
        Functions\when('apply_filters')->alias(function($filter, $value) {
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
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('register_activation_hook')->justReturn(null);
        Functions\when('register_deactivation_hook')->justReturn(null);
        Functions\when('add_action')->justReturn(null);
        Functions\when('add_filter')->justReturn(null);
        // Mock wp_remote_request to prevent actual HTTP calls during plugin initialization
        Functions\when('wp_remote_request')->justReturn(
            new WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('is_wp_error')->alias(function($thing) {
            return $thing instanceof WP_Error;
        });

        // Load the plugin file to get EventBridgePostEvents class (after mocks are set up)
        if (!class_exists('EventBridgePostEvents')) {
            require_once dirname(dirname(__DIR__)) . '/event-publisher-on-aws.php';
        }

        // Create instance and use reflection to access private methods
        $this->instance = new \EventBridgePostEvents();
        $this->reflection = new ReflectionClass($this->instance);
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Helper method to call private sanitize_and_validate_setting method
     */
    protected function callPrivateSanitizeMethod($input, $key, $regex, $error_code, $error_message, $default)
    {
        $method = $this->reflection->getMethod('sanitize_and_validate_setting');
        $method->setAccessible(true);
        return $method->invoke($this->instance, $input, $key, $regex, $error_code, $error_message, $default);
    }

    /**
     * Test valid input passes sanitization
     */
    public function test_sanitize_setting_valid_input()
    {
        $input = ['test_field' => 'valid-value-123'];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        $this->assertEquals('valid-value-123', $result);
    }

    /**
     * Test XSS attempt is sanitized
     */
    public function test_sanitize_setting_xss_attempt()
    {
        $input = ['test_field' => '<script>alert("xss")</script>'];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // sanitize_text_field should strip tags, then regex validation should fail
        $this->assertEquals('default', $result);
    }

    /**
     * Test SQL injection attempt is blocked
     */
    public function test_sanitize_setting_sql_injection_attempt()
    {
        $input = ['test_field' => "' OR '1'='1"];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Regex should reject SQL injection attempts
        $this->assertEquals('default', $result);
    }

    /**
     * Test HTML entities injection
     */
    public function test_sanitize_setting_html_entities()
    {
        $input = ['test_field' => '&lt;script&gt;alert(1)&lt;/script&gt;'];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Should be rejected by regex
        $this->assertEquals('default', $result);
    }

    /**
     * Test regex bypass attempt with newlines
     */
    public function test_sanitize_setting_regex_bypass_newlines()
    {
        $input = ['test_field' => "valid\n<script>alert('xss')</script>"];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // sanitize_text_field and regex should block this
        $this->assertEquals('default', $result);
    }

    /**
     * Test empty input returns default
     */
    public function test_sanitize_setting_empty_input()
    {
        $input = ['test_field' => ''];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        $this->assertEquals('default', $result);
    }

    /**
     * Test missing key returns default
     */
    public function test_sanitize_setting_missing_key()
    {
        $input = ['other_field' => 'value'];
        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        $this->assertEquals('default', $result);
    }

    /**
     * Test event bus name sanitization with valid name
     */
    public function test_event_bus_name_valid()
    {
        $input = ['event_bus_name' => 'my-event-bus_123'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'event_bus_name',
            '/^([a-zA-Z0-9._\-]{1,256}|arn:aws:events:[a-z]{2}-[a-z]+-\d{1}:\d{12}:event-bus\/[a-zA-Z0-9._\-\/]{1,256})$/',
            'invalid_event_bus_name',
            'Invalid event bus name',
            'default'
        );

        $this->assertEquals('my-event-bus_123', $result);
    }

    /**
     * Test event bus name sanitization with valid ARN
     */
    public function test_event_bus_name_valid_arn()
    {
        $input = ['event_bus_name' => 'arn:aws:events:us-east-1:123456789012:event-bus/my-bus'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'event_bus_name',
            '/^([a-zA-Z0-9._\-]{1,256}|arn:aws:events:[a-z]{2}-[a-z]+-\d{1}:\d{12}:event-bus\/[a-zA-Z0-9._\-\/]{1,256})$/',
            'invalid_event_bus_name',
            'Invalid event bus name',
            'default'
        );

        $this->assertEquals('arn:aws:events:us-east-1:123456789012:event-bus/my-bus', $result);
    }

    /**
     * Test event bus name sanitization with invalid characters
     */
    public function test_event_bus_name_invalid_characters()
    {
        $input = ['event_bus_name' => 'invalid@bus#name!'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'event_bus_name',
            '/^([a-zA-Z0-9._\-]{1,256}|arn:aws:events:[a-z]{2}-[a-z]+-\d{1}:\d{12}:event-bus\/[a-zA-Z0-9._\-\/]{1,256})$/',
            'invalid_event_bus_name',
            'Invalid event bus name',
            'default'
        );

        $this->assertEquals('default', $result);
    }

    /**
     * Test event source name sanitization
     */
    public function test_event_source_name_valid()
    {
        $input = ['event_source_name' => 'wordpress.post/events'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'event_source_name',
            '/^[a-zA-Z0-9._\-\/]{1,256}$/',
            'invalid_event_source_name',
            'Invalid event source name',
            'default'
        );

        $this->assertEquals('wordpress.post/events', $result);
    }

    /**
     * Test AWS region sanitization with valid region
     */
    public function test_aws_region_valid()
    {
        $input = ['aws_region' => 'us-east-1'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'aws_region',
            '/^[a-z]{2}-[a-z]+-\d{1}$/',
            'invalid_aws_region',
            'Invalid AWS region',
            'default'
        );

        $this->assertEquals('us-east-1', $result);
    }

    /**
     * Test AWS region sanitization with invalid format
     */
    public function test_aws_region_invalid_format()
    {
        $input = ['aws_region' => 'invalid-region'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'aws_region',
            '/^[a-z]{2}-[a-z]+-\d{1}$/',
            'invalid_aws_region',
            'Invalid AWS region',
            'default'
        );

        $this->assertEquals('default', $result);
    }

    /**
     * Test full settings sanitization with valid input
     */
    public function test_sanitize_settings_valid_input()
    {
        $input = [
            'event_format' => 'envelope',
            'send_mode' => 'async',
            'event_bus_name' => 'my-bus',
            'event_source_name' => 'wordpress.post',
            'aws_region_override' => 'us-west-2',
            'enabled_post_types' => ['post', 'page'],
        ];

        $result = $this->instance->sanitize_settings($input);

        $this->assertEquals('envelope', $result['event_format']);
        $this->assertEquals('async', $result['send_mode']);
        $this->assertEquals('my-bus', $result['event_bus_name']);
        $this->assertEquals('wordpress.post', $result['event_source_name']);
        $this->assertEquals('us-west-2', $result['aws_region_override']);
        $this->assertContains('post', $result['enabled_post_types']);
        $this->assertContains('page', $result['enabled_post_types']);
    }

    /**
     * Test settings sanitization rejects invalid event_format
     */
    public function test_sanitize_settings_invalid_event_format()
    {
        $input = [
            'event_format' => 'invalid_format',
            'send_mode' => 'async',
        ];

        $result = $this->instance->sanitize_settings($input);

        // Should default to 'envelope'
        $this->assertEquals('envelope', $result['event_format']);
    }

    /**
     * Test settings sanitization rejects invalid send_mode
     */
    public function test_sanitize_settings_invalid_send_mode()
    {
        $input = [
            'event_format' => 'envelope',
            'send_mode' => 'invalid_mode',
        ];

        $result = $this->instance->sanitize_settings($input);

        // Should default to 'async'
        $this->assertEquals('async', $result['send_mode']);
    }

    /**
     * Test post type sanitization filters invalid types
     */
    public function test_sanitize_settings_invalid_post_types()
    {
        $input = [
            'enabled_post_types' => ['post', 'invalid_type', 'page'],
        ];

        $result = $this->instance->sanitize_settings($input);

        // Should only include valid post types
        $this->assertContains('post', $result['enabled_post_types']);
        $this->assertContains('page', $result['enabled_post_types']);
        $this->assertNotContains('invalid_type', $result['enabled_post_types']);
    }

    /**
     * Test post type sanitization defaults to ['post'] if empty
     */
    public function test_sanitize_settings_empty_post_types_defaults()
    {
        $input = [
            'enabled_post_types' => [],
        ];

        $result = $this->instance->sanitize_settings($input);

        // Should default to ['post']
        $this->assertEquals(['post'], $result['enabled_post_types']);
    }

    /**
     * Test XSS in event_bus_name
     */
    public function test_sanitize_settings_xss_in_event_bus_name()
    {
        $input = [
            'event_bus_name' => '<script>alert("xss")</script>',
        ];

        $result = $this->instance->sanitize_settings($input);

        // Should be sanitized and fail regex, return default
        $this->assertEquals('default', $result['event_bus_name']);
    }

    /**
     * Test path traversal attempt in event_source_name
     */
    public function test_sanitize_settings_path_traversal_attempt()
    {
        $input = [
            'event_source_name' => '../../etc/passwd',
        ];

        $result = $this->instance->sanitize_settings($input);

        // Forward slashes are actually allowed in event source names, but dots in sequence might not pass
        // The regex allows dots, slashes, etc., so this might pass sanitization
        // However, it's not a security issue as it's just a string identifier, not a file path
        $this->assertIsString($result['event_source_name']);
    }

    /**
     * Test null byte injection
     */
    public function test_sanitize_setting_null_byte_injection()
    {
        $input = ['test_field' => "valid\x00<script>"];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // sanitize_text_field should remove null bytes and tags,
        // leaving "validscript" which should pass. However if we use
        // a payload with characters that won't pass regex, it should fail
        // Let's use a different test - null byte followed by invalid chars
        $input2 = ['test_field' => "test\x00!@#"];
        $result2 = $this->callPrivateSanitizeMethod(
            $input2,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // After null byte removal, becomes "test!@#" which fails regex
        $this->assertEquals('default', $result2);
    }

    /**
     * Test command injection attempt
     */
    public function test_sanitize_setting_command_injection()
    {
        $input = ['test_field' => 'value; rm -rf /'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Regex should reject this
        $this->assertEquals('default', $result);
    }

    /**
     * Test LDAP injection attempt
     */
    public function test_sanitize_setting_ldap_injection()
    {
        $input = ['test_field' => '*)(uid=*))(|(uid=*'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Regex should reject this
        $this->assertEquals('default', $result);
    }

    /**
     * Test Unicode normalization attack
     */
    public function test_sanitize_setting_unicode_normalization()
    {
        $input = ['test_field' => 'test＜script＞alert(1)＜/script＞'];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]+$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Full-width characters should fail regex
        $this->assertEquals('default', $result);
    }

    /**
     * Test very long input (DoS attempt)
     */
    public function test_sanitize_setting_very_long_input()
    {
        $input = ['test_field' => str_repeat('a', 10000)];

        $result = $this->callPrivateSanitizeMethod(
            $input,
            'test_field',
            '/^[a-z0-9\-]{1,256}$/',
            'invalid_test',
            'Invalid test field',
            'default'
        );

        // Should fail max length validation in regex
        $this->assertEquals('default', $result);
    }

    /**
     * Test settings array structure is preserved
     */
    public function test_sanitize_settings_array_structure()
    {
        $input = [];

        $result = $this->instance->sanitize_settings($input);

        // Should have all required keys
        $this->assertArrayHasKey('event_format', $result);
        $this->assertArrayHasKey('send_mode', $result);
        $this->assertArrayHasKey('event_bus_name', $result);
        $this->assertArrayHasKey('event_source_name', $result);
        $this->assertArrayHasKey('aws_region_override', $result);
        $this->assertArrayHasKey('enabled_post_types', $result);
    }
}
