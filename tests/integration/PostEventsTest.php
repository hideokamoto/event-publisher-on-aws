<?php
/**
 * Integration tests for post event transitions
 *
 * @package EventBridgePostEvents
 */

if (class_exists('WP_UnitTestCase')) {

class PostEventsTest extends WP_UnitTestCase
{
    /**
     * Test post published event triggers
     */
    public function test_post_published_triggers_event()
    {
        // Create a post in draft status
        $post_id = $this->factory->post->create([
            'post_status' => 'draft',
            'post_type' => 'post',
            'post_title' => 'Test Post',
        ]);

        // Verify post was created
        $this->assertGreaterThan(0, $post_id);

        // Update post to published status
        wp_update_post([
            'ID' => $post_id,
            'post_status' => 'publish',
        ]);

        // Verify correlation ID was added
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertNotEmpty($correlation_id);

        // Verify event was scheduled
        $scheduled = wp_next_scheduled('eventbridge_async_send_event');
        $this->assertNotFalse($scheduled);
    }

    /**
     * Test post updated event triggers
     */
    public function test_post_updated_triggers_event()
    {
        // Create a published post
        $post_id = $this->factory->post->create([
            'post_status' => 'publish',
            'post_type' => 'post',
            'post_title' => 'Test Post',
        ]);

        // Clear any scheduled events
        wp_clear_scheduled_hook('eventbridge_async_send_event');

        // Update the post
        wp_update_post([
            'ID' => $post_id,
            'post_title' => 'Updated Test Post',
        ]);

        // Verify event was scheduled
        $scheduled = wp_next_scheduled('eventbridge_async_send_event');
        $this->assertNotFalse($scheduled);
    }

    /**
     * Test scheduled post triggers future event
     */
    public function test_scheduled_post_triggers_event()
    {
        // Create a scheduled post
        $future_date = date('Y-m-d H:i:s', strtotime('+1 day'));
        $post_id = $this->factory->post->create([
            'post_status' => 'future',
            'post_type' => 'post',
            'post_title' => 'Scheduled Post',
            'post_date' => $future_date,
        ]);

        // Verify correlation ID was added
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertNotEmpty($correlation_id);
    }

    /**
     * Test post deletion triggers event
     */
    public function test_post_deletion_triggers_event()
    {
        // Create a post
        $post_id = $this->factory->post->create([
            'post_status' => 'publish',
            'post_type' => 'post',
            'post_title' => 'Test Post to Delete',
        ]);

        // Get correlation ID before deletion
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertNotEmpty($correlation_id);

        // Clear scheduled events
        wp_clear_scheduled_hook('eventbridge_async_send_event');

        // Delete the post
        wp_delete_post($post_id, true);

        // Verify event was scheduled
        $scheduled = wp_next_scheduled('eventbridge_async_send_event');
        $this->assertNotFalse($scheduled);
    }

    /**
     * Test only allowed post types trigger events
     */
    public function test_only_allowed_post_types_trigger_events()
    {
        // Register a custom post type
        register_post_type('custom_type', [
            'public' => true,
        ]);

        // Create a custom post type post
        $post_id = $this->factory->post->create([
            'post_status' => 'publish',
            'post_type' => 'custom_type',
            'post_title' => 'Custom Type Post',
        ]);

        // Verify no correlation ID was added (not in allowed types)
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertEmpty($correlation_id);
    }

    /**
     * Test correlation ID persistence
     */
    public function test_correlation_id_persists_across_updates()
    {
        // Create a post
        $post_id = $this->factory->post->create([
            'post_status' => 'publish',
            'post_type' => 'post',
            'post_title' => 'Test Post',
        ]);

        // Get initial correlation ID
        $initial_correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertNotEmpty($initial_correlation_id);

        // Update the post
        wp_update_post([
            'ID' => $post_id,
            'post_title' => 'Updated Title',
        ]);

        // Get correlation ID after update
        $updated_correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        // Verify correlation ID is the same
        $this->assertEquals($initial_correlation_id, $updated_correlation_id);
    }
}

}
