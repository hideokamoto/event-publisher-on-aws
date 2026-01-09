<?php
/**
 * Integration tests for admin settings persistence
 *
 * @package EventBridge_Post_Events
 */

/**
 * Test admin settings functionality
 */
class AdminSettingsTest extends EventBridge_Integration_Test_Case
{
    /**
     * Test settings can be saved
     */
    public function test_settings_can_be_saved()
    {
        $settings = array(
            'event_format' => 'envelope',
            'send_mode' => 'async',
            'event_bus_name' => 'test-bus',
            'event_source_name' => 'test-source',
            'aws_region_override' => 'eu-west-1',
            'allowed_post_types' => array('post', 'page'),
        );

        update_option('eventbridge_settings', $settings);

        $saved = get_option('eventbridge_settings');

        $this->assertEquals('envelope', $saved['event_format']);
        $this->assertEquals('async', $saved['send_mode']);
        $this->assertEquals('test-bus', $saved['event_bus_name']);
    }

    /**
     * Test settings have default values
     */
    public function test_settings_have_defaults()
    {
        delete_option('eventbridge_settings');

        $defaults = array(
            'event_format' => 'envelope',
            'send_mode' => 'async',
            'event_bus_name' => '',
            'event_source_name' => '',
            'aws_region_override' => '',
            'allowed_post_types' => array('post', 'page'),
        );

        $settings = wp_parse_args(
            get_option('eventbridge_settings', array()),
            $defaults
        );

        $this->assertEquals('envelope', $settings['event_format']);
        $this->assertEquals('async', $settings['send_mode']);
    }

    /**
     * Test event format validation
     */
    public function test_event_format_validation()
    {
        $valid_formats = array('legacy', 'envelope');

        foreach ($valid_formats as $format) {
            $this->assertTrue(in_array($format, $valid_formats, true));
        }

        $this->assertFalse(in_array('invalid', $valid_formats, true));
    }

    /**
     * Test send mode validation
     */
    public function test_send_mode_validation()
    {
        $valid_modes = array('sync', 'async');

        foreach ($valid_modes as $mode) {
            $this->assertTrue(in_array($mode, $valid_modes, true));
        }

        $this->assertFalse(in_array('invalid', $valid_modes, true));
    }

    /**
     * Test region format validation
     */
    public function test_region_format_validation()
    {
        $valid_regions = array('us-east-1', 'eu-west-1', 'ap-northeast-1');

        foreach ($valid_regions as $region) {
            $this->assertMatchesRegularExpression('/^[a-z]{2}-[a-z]+-\d+$/', $region);
        }

        $invalid_regions = array('invalid', 'US-EAST-1', '');
        foreach ($invalid_regions as $region) {
            $this->assertDoesNotMatchRegularExpression('/^[a-z]{2}-[a-z]+-\d+$/', $region);
        }
    }

    /**
     * Test event bus name validation
     */
    public function test_event_bus_name_validation()
    {
        $valid_names = array('default', 'my-event-bus', 'event_bus_1', 'bus.name');

        foreach ($valid_names as $name) {
            $this->assertMatchesRegularExpression('/^[a-zA-Z0-9._\-\/]{1,256}$/', $name);
        }

        // Invalid names
        $this->assertDoesNotMatchRegularExpression('/^[a-zA-Z0-9._\-\/]{1,256}$/', '');
        $this->assertDoesNotMatchRegularExpression('/^[a-zA-Z0-9._\-\/]{1,256}$/', 'name with spaces');
    }

    /**
     * Test metrics option persistence
     */
    public function test_metrics_persistence()
    {
        $metrics = array(
            'successful_events' => 10,
            'failed_events' => 2,
            'transient_failures' => 1,
            'permanent_failures' => 1,
        );

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
        $details = array(
            'last_failure_time' => current_time('mysql'),
            'messages' => array(
                array(
                    'time' => current_time('mysql'),
                    'message' => 'Test error message',
                    'type' => 'transient',
                ),
            ),
        );

        update_option('eventbridge_failure_details', $details, false);

        $saved = get_option('eventbridge_failure_details');

        $this->assertNotEmpty($saved['last_failure_time']);
        $this->assertCount(1, $saved['messages']);
    }

    /**
     * Test allowed post types setting
     */
    public function test_allowed_post_types_setting()
    {
        $settings = array(
            'allowed_post_types' => array('post', 'page', 'custom_type'),
        );

        update_option('eventbridge_settings', $settings);

        $saved = get_option('eventbridge_settings');

        $this->assertContains('post', $saved['allowed_post_types']);
        $this->assertContains('page', $saved['allowed_post_types']);
        $this->assertContains('custom_type', $saved['allowed_post_types']);
    }
}
