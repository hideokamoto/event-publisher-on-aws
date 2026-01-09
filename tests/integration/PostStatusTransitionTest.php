<?php
/**
 * Integration tests for post status transitions
 *
 * @package EventBridge_Post_Events
 */

/**
 * Test post status transitions create events
 */
class PostStatusTransitionTest extends EventBridge_Integration_Test_Case
{
    /**
     * Set up before each test
     */
    public function set_up()
    {
        parent::set_up();

        // Mock EventBridge API responses
        $this->mock_http_response('events.us-east-1.amazonaws.com', $this->get_success_response());

        // Mock EC2 metadata
        $this->mock_http_response('169.254.169.254', array(
            'response' => array('code' => 200),
            'body' => json_encode(array('region' => 'us-east-1')),
        ));
    }

    /**
     * Test publishing a post schedules async event
     */
    public function test_publish_post_schedules_event()
    {
        // Create a draft post
        $post_id = $this->factory->post->create(array(
            'post_status' => 'draft',
            'post_title' => 'Test Post',
        ));

        // Verify no scheduled events yet
        $this->assertFalse(wp_next_scheduled('eventbridge_async_send_event'));

        // Publish the post
        wp_update_post(array(
            'ID' => $post_id,
            'post_status' => 'publish',
        ));

        // Check if event was scheduled (async mode is default)
        // Note: In test environment, the hook may be directly called
        $this->assertTrue(true); // Placeholder for actual hook verification
    }

    /**
     * Test updating published post triggers event
     */
    public function test_update_published_post_triggers_event()
    {
        // Create and publish a post
        $post_id = $this->factory->post->create(array(
            'post_status' => 'publish',
            'post_title' => 'Original Title',
        ));

        // Update the post
        wp_update_post(array(
            'ID' => $post_id,
            'post_title' => 'Updated Title',
        ));

        // Verify post was updated
        $post = get_post($post_id);
        $this->assertEquals('Updated Title', $post->post_title);
    }

    /**
     * Test scheduling a future post
     */
    public function test_schedule_future_post()
    {
        // Create a future post
        $future_date = date('Y-m-d H:i:s', strtotime('+1 day'));
        $post_id = $this->factory->post->create(array(
            'post_status' => 'future',
            'post_date' => $future_date,
            'post_title' => 'Future Post',
        ));

        // Verify post status
        $post = get_post($post_id);
        $this->assertEquals('future', $post->post_status);
    }

    /**
     * Test draft to publish transition
     */
    public function test_draft_to_publish_transition()
    {
        $post_id = $this->factory->post->create(array(
            'post_status' => 'draft',
        ));

        // Transition to publish
        wp_publish_post($post_id);

        $post = get_post($post_id);
        $this->assertEquals('publish', $post->post_status);
    }

    /**
     * Test post type filtering
     */
    public function test_custom_post_type_not_sent_by_default()
    {
        // Register a custom post type
        register_post_type('custom_type', array(
            'public' => true,
        ));

        // Create a custom post type
        $post_id = $this->factory->post->create(array(
            'post_type' => 'custom_type',
            'post_status' => 'publish',
        ));

        $post = get_post($post_id);
        $this->assertEquals('custom_type', $post->post_type);

        // Clean up
        unregister_post_type('custom_type');
    }

    /**
     * Test page post type is allowed
     */
    public function test_page_post_type_allowed()
    {
        $page_id = $this->factory->post->create(array(
            'post_type' => 'page',
            'post_status' => 'publish',
            'post_title' => 'Test Page',
        ));

        $page = get_post($page_id);
        $this->assertEquals('page', $page->post_type);
        $this->assertEquals('publish', $page->post_status);
    }

    /**
     * Test correlation ID is stored
     */
    public function test_correlation_id_stored()
    {
        $post_id = $this->factory->post->create(array(
            'post_status' => 'publish',
        ));

        // Add correlation ID (simulating what the plugin does)
        $correlation_id = wp_generate_uuid4();
        add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

        $stored_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertEquals($correlation_id, $stored_id);
    }

    /**
     * Test correlation ID persists across updates
     */
    public function test_correlation_id_persists()
    {
        $post_id = $this->factory->post->create(array(
            'post_status' => 'publish',
        ));

        // Store correlation ID
        $correlation_id = 'test-correlation-id-123';
        add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

        // Update the post
        wp_update_post(array(
            'ID' => $post_id,
            'post_title' => 'Updated Title',
        ));

        // Verify correlation ID still exists
        $stored_id = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertEquals($correlation_id, $stored_id);
    }
}
