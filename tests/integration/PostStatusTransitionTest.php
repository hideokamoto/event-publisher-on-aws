<?php
/**
 * Integration tests for post status transitions
 *
 * Tests that events are properly created when posts transition between statuses.
 */

namespace EventPublisherOnAWS\Tests\Integration;

use WP_UnitTestCase;

class PostStatusTransitionTest extends WP_UnitTestCase
{
    protected $fixtures;

    public function setUp(): void
    {
        parent::setUp();

        // Load AWS response fixtures
        $this->fixtures = include dirname(__DIR__) . '/fixtures/aws-responses.php';

        // Mock HTTP requests to prevent real network calls
        add_filter('pre_http_request', [$this, 'mock_http_requests'], 10, 3);
    }

    public function tearDown(): void
    {
        remove_filter('pre_http_request', [$this, 'mock_http_requests']);
        parent::tearDown();
    }

    /**
     * Helper method to count scheduled eventbridge_async_send_event cron jobs
     *
     * @return int Number of scheduled events
     */
    private function count_scheduled_eventbridge_events()
    {
        $cron_array = _get_cron_array();
        $count = 0;
        if ($cron_array) {
            foreach ($cron_array as $timestamp => $hooks) {
                if (isset($hooks['eventbridge_async_send_event'])) {
                    $count += count($hooks['eventbridge_async_send_event']);
                }
            }
        }
        return $count;
    }

    /**
     * Mock HTTP requests for EC2 metadata service and EventBridge API
     */
    public function mock_http_requests($preempt, $args, $url)
    {
        // Mock EC2 metadata service
        if (strpos($url, '169.254.169.254') !== false) {
            return $this->fixtures['ec2_metadata_success'];
        }

        // Mock EventBridge API
        if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
            return $this->fixtures['success_single_event'];
        }

        return $preempt;
    }

    /**
     * Test that publishing a new post creates an event
     */
    public function test_publishing_new_post_creates_event()
    {
        $event_triggered = false;

        // Hook into async event scheduling
        add_action('eventbridge_async_send_event', function($source, $detailType, $detail) use (&$event_triggered) {
            $event_triggered = true;
            $this->assertEquals('post.published', $detailType);
            $this->assertArrayHasKey('id', $detail);
            $this->assertArrayHasKey('title', $detail);
        }, 10, 3);

        // Create and publish a post
        $post_id = $this->factory()->post->create([
            'post_title' => 'Test Post',
            'post_status' => 'publish',
        ]);

        $this->assertGreaterThan(0, $post_id);
        $this->assertTrue($event_triggered, 'Event should be triggered when post is published');
    }

    /**
     * Test that updating a published post creates an event
     */
    public function test_updating_published_post_creates_event()
    {
        // First create a published post
        $post_id = $this->factory()->post->create([
            'post_title' => 'Original Title',
            'post_status' => 'publish',
        ]);

        $event_triggered = false;
        $event_type = '';

        // Hook into async event scheduling
        add_action('eventbridge_async_send_event', function($source, $detailType, $detail) use (&$event_triggered, &$event_type) {
            $event_triggered = true;
            $event_type = $detailType;
        }, 10, 3);

        // Update the post
        wp_update_post([
            'ID' => $post_id,
            'post_title' => 'Updated Title',
        ]);

        $this->assertTrue($event_triggered, 'Event should be triggered when post is updated');
        $this->assertEquals('post.updated', $event_type);
    }

    /**
     * Test that transitioning from draft to publish creates correct event
     */
    public function test_draft_to_publish_transition()
    {
        // Create a draft post
        $post_id = $this->factory()->post->create([
            'post_title' => 'Draft Post',
            'post_status' => 'draft',
        ]);

        $event_detail_type = '';

        // Hook into async event scheduling
        add_action('eventbridge_async_send_event', function($source, $detailType, $detail) use (&$event_detail_type) {
            $event_detail_type = $detailType;
        }, 10, 3);

        // Publish the post
        wp_publish_post($post_id);

        $this->assertEquals('post.published', $event_detail_type, 'Should trigger post.published event');
    }

    /**
     * Test that deleting a post creates delete event
     */
    public function test_deleting_post_creates_event()
    {
        // Create a post
        $post_id = $this->factory()->post->create([
            'post_title' => 'Post to Delete',
            'post_status' => 'publish',
        ]);

        $delete_event_triggered = false;
        $deleted_post_id = null;

        // Hook into async event scheduling
        add_action('eventbridge_async_send_event', function($source, $detailType, $detail) use (&$delete_event_triggered, &$deleted_post_id) {
            if ($detailType === 'post.deleted') {
                $delete_event_triggered = true;
                $deleted_post_id = $detail['id'];
            }
        }, 10, 3);

        // Delete the post
        wp_delete_post($post_id, true);

        $this->assertTrue($delete_event_triggered, 'Delete event should be triggered');
        $this->assertEquals((string)$post_id, $deleted_post_id);
    }

    /**
     * Test that draft posts do not trigger events
     */
    public function test_draft_posts_do_not_trigger_events()
    {
        $event_triggered = false;

        add_action('eventbridge_async_send_event', function() use (&$event_triggered) {
            $event_triggered = true;
        }, 10, 3);

        // Create a draft post (should not trigger event)
        $post_id = $this->factory()->post->create([
            'post_title' => 'Draft Post',
            'post_status' => 'draft',
        ]);

        $this->assertGreaterThan(0, $post_id);
        $this->assertFalse($event_triggered, 'Draft posts should not trigger events');
    }

    /**
     * Test async event scheduling via wp_schedule_single_event
     */
    public function test_async_event_scheduling()
    {
        // Get current scheduled events count
        $initial_count = $this->count_scheduled_eventbridge_events();

        // Create a published post
        $post_id = $this->factory()->post->create([
            'post_title' => 'Test Post for Async',
            'post_status' => 'publish',
        ]);

        // Verify post was created
        $this->assertGreaterThan(0, $post_id, 'Post should be created');
        $post = get_post($post_id);
        $this->assertNotNull($post, 'Post should exist');
        $this->assertEquals('publish', $post->post_status, 'Post should be published');

        // Check that event was scheduled
        $new_count = $this->count_scheduled_eventbridge_events();

        $this->assertGreaterThan($initial_count, $new_count, 'Async event should be scheduled');
    }

    /**
     * Test correlation ID generation and persistence
     */
    public function test_correlation_id_persistence()
    {
        $post_id = $this->factory()->post->create([
            'post_title' => 'Test Correlation ID',
            'post_status' => 'publish',
        ]);

        // Get correlation ID
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        $this->assertNotEmpty($correlation_id, 'Correlation ID should be generated');
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
            $correlation_id,
            'Correlation ID should be a valid UUID'
        );

        // Update post and verify correlation ID remains the same
        wp_update_post([
            'ID' => $post_id,
            'post_title' => 'Updated Title',
        ]);

        $correlation_id_after = get_post_meta($post_id, '_event_correlation_id', true);
        $this->assertEquals($correlation_id, $correlation_id_after, 'Correlation ID should persist across updates');
    }
}
