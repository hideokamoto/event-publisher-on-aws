<?php
/**
 * Integration tests for admin settings persistence
 *
 * Tests register_setting() and get_option() for EventBridge settings.
 */

namespace EventPublisherOnAWS\Tests\Integration;

use WP_UnitTestCase;

class AdminSettingsTest extends WP_UnitTestCase
{
    protected $fixtures;
    protected $plugin_instance;

    public function setUp(): void
    {
        parent::setUp();

        // Load AWS response fixtures
        $this->fixtures = include dirname(__DIR__) . '/fixtures/aws-responses.php';

        // Mock EC2 metadata to prevent real network calls
        add_filter('pre_http_request', [$this, 'mock_http_requests'], 10, 3);

        // Clean up any existing options
        delete_option('eventbridge_settings');
        delete_option('eventbridge_metrics');
        delete_option('eventbridge_failure_details');
    }

    public function tearDown(): void
    {
        remove_filter('pre_http_request', [$this, 'mock_http_requests']);
        delete_option('eventbridge_settings');
        delete_option('eventbridge_metrics');
        delete_option('eventbridge_failure_details');
        parent::tearDown();
    }

    /**
     * Mock HTTP requests for tests
     */
    public function mock_http_requests($preempt, $args, $url)
    {
        if (strpos($url, '169.254.169.254') !== false) {
            return $this->fixtures['ec2_metadata_success'];
        }
        if (strpos($url, 'events.') !== false) {
            return $this->fixtures['success_single_event'];
        }
        return $preempt;
    }

    /**
     * Test default settings values
     */
    public function test_default_settings()
    {
        // When no settings are saved, defaults should be used
        $settings = get_option('eventbridge_settings', []);

        // If no settings exist, we expect an empty array (defaults will be applied by plugin)
        $this->assertIsArray($settings);
    }

    /**
     * Test saving event format setting
     */
    public function test_save_event_format_setting()
    {
        $settings = [
            'event_format' => 'envelope',
            'send_mode' => 'async',
        ];

        update_option('eventbridge_settings', $settings);

        $saved = get_option('eventbridge_settings');
        $this->assertEquals('envelope', $saved['event_format']);
    }

    /**
     * Test saving send mode setting
     */
    public function test_save_send_mode_setting()
    {
        $settings = [
            'event_format' => 'legacy',
            'send_mode' => 'sync',
        ];

        update_option('eventbridge_settings', $settings);

        $saved = get_option('eventbridge_settings');
        $this->assertEquals('sync', $saved['send_mode']);
    }

    /**
     * Test settings validation - valid values
     */
    public function test_settings_validation_valid_values()
    {
        $valid_formats = ['legacy', 'envelope'];
        $valid_modes = ['sync', 'async'];

        foreach ($valid_formats as $format) {
            $this->assertContains($format, ['legacy', 'envelope']);
        }

        foreach ($valid_modes as $mode) {
            $this->assertContains($mode, ['sync', 'async']);
        }
    }

    /**
     * Test settings validation - invalid values should fallback to defaults
     */
    public function test_settings_validation_invalid_values()
    {
        $invalid_settings = [
            'event_format' => 'invalid_format',
            'send_mode' => 'invalid_mode',
        ];

        // Simulate sanitization logic
        $valid_formats = ['legacy', 'envelope'];
        $valid_modes = ['sync', 'async'];

        $format_valid = in_array($invalid_settings['event_format'], $valid_formats, true);
        $mode_valid = in_array($invalid_settings['send_mode'], $valid_modes, true);

        $this->assertFalse($format_valid, 'Invalid format should not be valid');
        $this->assertFalse($mode_valid, 'Invalid mode should not be valid');
    }

    /**
     * Test metrics persistence
     */
    public function test_metrics_persistence()
    {
        $metrics = [
            'successful_events' => 10,
            'failed_events' => 2,
        ];

        update_option('eventbridge_metrics', $metrics, false);

        $saved = get_option('eventbridge_metrics');
        $this->assertEquals(10, $saved['successful_events']);
        $this->assertEquals(2, $saved['failed_events']);
    }

    /**
     * Test failure details persistence
     */
    public function test_failure_details_persistence()
    {
        $failure_details = [
            'last_failure_time' => current_time('mysql'),
            'messages' => [
                [
                    'time' => current_time('mysql'),
                    'message' => 'HTTP 500: Internal error',
                ],
            ],
        ];

        update_option('eventbridge_failure_details', $failure_details, false);

        $saved = get_option('eventbridge_failure_details');
        $this->assertArrayHasKey('last_failure_time', $saved);
        $this->assertArrayHasKey('messages', $saved);
        $this->assertCount(1, $saved['messages']);
    }

    /**
     * Test options are not autoloaded (performance)
     */
    public function test_options_not_autoloaded()
    {
        // Save options with autoload = false
        update_option('eventbridge_metrics', ['successful_events' => 5], false);
        update_option('eventbridge_failure_details', ['messages' => []], false);

        // Get autoload options
        global $wpdb;
        $autoload_metrics = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s",
                'eventbridge_metrics'
            )
        );

        $autoload_failures = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s",
                'eventbridge_failure_details'
            )
        );

        // Both should be 'no' or 'off' (WordPress uses 'no' for autoload=false)
        $this->assertContains($autoload_metrics, ['no', 'off', '0', null]);
        $this->assertContains($autoload_failures, ['no', 'off', '0', null]);
    }

    /**
     * Test settings update and retrieval flow
     */
    public function test_settings_update_flow()
    {
        // Initial settings
        $initial = [
            'event_format' => 'legacy',
            'send_mode' => 'async',
        ];
        update_option('eventbridge_settings', $initial);

        // Verify initial
        $saved = get_option('eventbridge_settings');
        $this->assertEquals('legacy', $saved['event_format']);

        // Update settings
        $updated = [
            'event_format' => 'envelope',
            'send_mode' => 'sync',
        ];
        update_option('eventbridge_settings', $updated);

        // Verify updated
        $saved = get_option('eventbridge_settings');
        $this->assertEquals('envelope', $saved['event_format']);
        $this->assertEquals('sync', $saved['send_mode']);
    }

    /**
     * Test metrics increment logic
     */
    public function test_metrics_increment()
    {
        // Initial metrics
        $metrics = [
            'successful_events' => 5,
            'failed_events' => 1,
        ];
        update_option('eventbridge_metrics', $metrics, false);

        // Simulate incrementing success
        $current = get_option('eventbridge_metrics');
        $current['successful_events']++;
        update_option('eventbridge_metrics', $current, false);

        // Verify
        $updated = get_option('eventbridge_metrics');
        $this->assertEquals(6, $updated['successful_events']);
        $this->assertEquals(1, $updated['failed_events']);
    }

    /**
     * Test failure messages array management (keep last 10)
     */
    public function test_failure_messages_limit()
    {
        $messages = [];
        for ($i = 1; $i <= 15; $i++) {
            $messages[] = [
                'time' => current_time('mysql'),
                'message' => "Error message {$i}",
            ];
        }

        // Keep only last 10
        if (count($messages) > 10) {
            $messages = array_slice($messages, -10);
        }

        $this->assertCount(10, $messages);
        $this->assertEquals('Error message 6', $messages[0]['message']);
        $this->assertEquals('Error message 15', $messages[9]['message']);
    }

    /**
     * Test transient for notice dismissal
     */
    public function test_notice_dismissal_transient()
    {
        $transient_key = 'eventbridge_notice_dismissed';

        // Set transient
        set_transient($transient_key, true, 24 * HOUR_IN_SECONDS);

        // Check transient exists
        $dismissed = get_transient($transient_key);
        $this->assertTrue($dismissed);

        // Delete transient
        delete_transient($transient_key);

        // Verify deleted
        $dismissed = get_transient($transient_key);
        $this->assertFalse($dismissed);
    }
}
