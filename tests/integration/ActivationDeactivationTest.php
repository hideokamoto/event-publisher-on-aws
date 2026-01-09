<?php
/**
 * Integration tests for plugin activation/deactivation hooks
 *
 * @package EventBridge_Post_Events
 */

/**
 * Test plugin activation and deactivation
 */
class ActivationDeactivationTest extends EventBridge_Integration_Test_Case
{
    /**
     * Test activation creates metrics option
     */
    public function test_activation_creates_metrics_option()
    {
        // Delete existing option
        delete_option('eventbridge_metrics');

        // Simulate activation
        eventbridge_activate();

        // Verify option was created
        $metrics = get_option('eventbridge_metrics');

        $this->assertIsArray($metrics);
        $this->assertEquals(0, $metrics['successful_events']);
        $this->assertEquals(0, $metrics['failed_events']);
    }

    /**
     * Test activation preserves existing metrics
     */
    public function test_activation_preserves_existing_metrics()
    {
        // Set existing metrics
        update_option('eventbridge_metrics', array(
            'successful_events' => 100,
            'failed_events' => 5,
            'transient_failures' => 3,
            'permanent_failures' => 2,
        ));

        // Simulate activation
        eventbridge_activate();

        // Verify metrics were preserved
        $metrics = get_option('eventbridge_metrics');

        $this->assertEquals(100, $metrics['successful_events']);
        $this->assertEquals(5, $metrics['failed_events']);
    }

    /**
     * Test deactivation clears scheduled events
     */
    public function test_deactivation_clears_scheduled_events()
    {
        // Schedule some events
        wp_schedule_single_event(time() + 3600, 'eventbridge_async_send_event', array('source', 'type', array()));

        // Verify event is scheduled
        $this->assertNotFalse(wp_next_scheduled('eventbridge_async_send_event', array('source', 'type', array())));

        // Simulate deactivation
        eventbridge_deactivate();

        // Verify events are cleared
        $this->assertFalse(wp_next_scheduled('eventbridge_async_send_event', array('source', 'type', array())));
    }

    /**
     * Test deactivation clears transients
     */
    public function test_deactivation_clears_transients()
    {
        // Set transients
        set_transient('eventbridge_notice_dismissed', true);
        set_transient('eventbridge_credential_notice_shown', true);
        set_transient('eventbridge_region_fallback_used', true);

        // Simulate deactivation
        eventbridge_deactivate();

        // Verify transients are cleared
        $this->assertFalse(get_transient('eventbridge_notice_dismissed'));
        $this->assertFalse(get_transient('eventbridge_credential_notice_shown'));
        $this->assertFalse(get_transient('eventbridge_region_fallback_used'));
    }

    /**
     * Test deactivation preserves metrics
     */
    public function test_deactivation_preserves_metrics()
    {
        // Set metrics
        update_option('eventbridge_metrics', array(
            'successful_events' => 50,
            'failed_events' => 2,
        ));

        // Simulate deactivation
        eventbridge_deactivate();

        // Verify metrics are preserved
        $metrics = get_option('eventbridge_metrics');
        $this->assertEquals(50, $metrics['successful_events']);
        $this->assertEquals(2, $metrics['failed_events']);
    }

    /**
     * Test deactivation preserves failure details
     */
    public function test_deactivation_preserves_failure_details()
    {
        // Set failure details
        update_option('eventbridge_failure_details', array(
            'last_failure_time' => '2024-01-15 12:00:00',
            'messages' => array(
                array('time' => '2024-01-15 12:00:00', 'message' => 'Test error'),
            ),
        ));

        // Simulate deactivation
        eventbridge_deactivate();

        // Verify failure details are preserved
        $details = get_option('eventbridge_failure_details');
        $this->assertNotEmpty($details);
        $this->assertEquals('2024-01-15 12:00:00', $details['last_failure_time']);
    }
}
