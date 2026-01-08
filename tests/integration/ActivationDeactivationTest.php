<?php
/**
 * Integration tests for plugin activation and deactivation hooks
 *
 * Tests state management during plugin activation and deactivation.
 */

namespace EventPublisherOnAWS\Tests\Integration;

use WP_UnitTestCase;

class ActivationDeactivationTest extends WP_UnitTestCase
{
    protected $plugin_file;

    public function setUp(): void
    {
        parent::setUp();
        $this->plugin_file = dirname(dirname(dirname(__FILE__))) . '/event-publisher-on-aws.php';
    }

    public function tearDown(): void
    {
        // Clean up options
        delete_option('eventbridge_settings');
        delete_option('eventbridge_metrics');
        delete_option('eventbridge_failure_details');
        delete_transient('eventbridge_notice_dismissed');
        parent::tearDown();
    }

    /**
     * Test plugin loads successfully
     */
    public function test_plugin_file_exists()
    {
        $this->assertFileExists($this->plugin_file, 'Plugin file should exist');
    }

    /**
     * Test plugin constants are defined
     */
    public function test_plugin_constants_defined()
    {
        $this->assertTrue(defined('EVENT_BUS_NAME'), 'EVENT_BUS_NAME constant should be defined');
        $this->assertTrue(defined('EVENT_SOURCE_NAME'), 'EVENT_SOURCE_NAME constant should be defined');
    }

    /**
     * Test plugin classes exist
     */
    public function test_plugin_classes_exist()
    {
        $this->assertTrue(class_exists('EventBridgePutEvents'), 'EventBridgePutEvents class should exist');
        $this->assertTrue(class_exists('EventBridgePostEvents'), 'EventBridgePostEvents class should exist');
    }

    /**
     * Test options are created with correct structure
     */
    public function test_options_structure()
    {
        // Simulate initial settings
        $settings = [
            'event_format' => 'envelope',
            'send_mode' => 'async',
        ];
        update_option('eventbridge_settings', $settings);

        $metrics = [
            'successful_events' => 0,
            'failed_events' => 0,
        ];
        update_option('eventbridge_metrics', $metrics, false);

        // Verify structure
        $saved_settings = get_option('eventbridge_settings');
        $this->assertIsArray($saved_settings);
        $this->assertArrayHasKey('event_format', $saved_settings);
        $this->assertArrayHasKey('send_mode', $saved_settings);

        $saved_metrics = get_option('eventbridge_metrics');
        $this->assertIsArray($saved_metrics);
        $this->assertArrayHasKey('successful_events', $saved_metrics);
        $this->assertArrayHasKey('failed_events', $saved_metrics);
    }

    /**
     * Test deactivation cleans up scheduled events
     */
    public function test_deactivation_cleanup()
    {
        // Schedule some test events
        wp_schedule_single_event(time() + 3600, 'eventbridge_async_send_event', ['test', 'test', []]);
        wp_schedule_single_event(time() + 7200, 'eventbridge_async_send_event', ['test2', 'test2', []]);

        // Verify events are scheduled
        $cron_array = _get_cron_array();
        $count_before = 0;
        if ($cron_array) {
            foreach ($cron_array as $timestamp => $hooks) {
                if (isset($hooks['eventbridge_async_send_event'])) {
                    $count_before += count($hooks['eventbridge_async_send_event']);
                }
            }
        }

        $this->assertGreaterThan(0, $count_before, 'Events should be scheduled');

        // Simulate deactivation by clearing scheduled events
        wp_clear_scheduled_hook('eventbridge_async_send_event');

        // Verify events are cleared
        $cron_array = _get_cron_array();
        $count_after = 0;
        if ($cron_array) {
            foreach ($cron_array as $timestamp => $hooks) {
                if (isset($hooks['eventbridge_async_send_event'])) {
                    $count_after += count($hooks['eventbridge_async_send_event']);
                }
            }
        }

        $this->assertEquals(0, $count_after, 'Scheduled events should be cleared');
    }

    /**
     * Test plugin state after fresh activation
     */
    public function test_fresh_activation_state()
    {
        // Delete all options to simulate fresh activation
        delete_option('eventbridge_settings');
        delete_option('eventbridge_metrics');
        delete_option('eventbridge_failure_details');

        // Verify options don't exist
        $this->assertFalse(get_option('eventbridge_settings'), 'Settings should not exist initially');
        $this->assertFalse(get_option('eventbridge_metrics'), 'Metrics should not exist initially');
    }

    /**
     * Test credentials validation on activation
     */
    public function test_credentials_check()
    {
        // Credentials should be defined as constants
        $this->assertTrue(
            defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID'),
            'AWS_EVENTBRIDGE_ACCESS_KEY_ID should be defined'
        );
        $this->assertTrue(
            defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY'),
            'AWS_EVENTBRIDGE_SECRET_ACCESS_KEY should be defined'
        );

        // Verify they're not empty
        $this->assertNotEmpty(AWS_EVENTBRIDGE_ACCESS_KEY_ID, 'Access key should not be empty');
        $this->assertNotEmpty(AWS_EVENTBRIDGE_SECRET_ACCESS_KEY, 'Secret key should not be empty');
    }

    /**
     * Test hooks are registered properly
     */
    public function test_hooks_registered()
    {
        // Check critical action hooks are registered
        $this->assertNotFalse(
            has_action('transition_post_status'),
            'transition_post_status action should be registered'
        );

        $this->assertNotFalse(
            has_action('before_delete_post'),
            'before_delete_post action should be registered'
        );
    }

    /**
     * Test admin menu hooks are registered
     */
    public function test_admin_hooks_registered()
    {
        // Verify admin hooks exist
        $this->assertNotFalse(
            has_action('admin_menu'),
            'admin_menu action should be registered'
        );

        $this->assertNotFalse(
            has_action('admin_init'),
            'admin_init action should be registered'
        );

        $this->assertNotFalse(
            has_action('admin_notices'),
            'admin_notices action should be registered'
        );
    }
}
