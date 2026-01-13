<?php
/**
 * Integration tests for core EventBridge event sending functionality
 *
 * Tests the EventBridgePutEvents::sendEvent() method with various scenarios
 * including success, retries, error handling, and payload validation.
 */

namespace EventPublisherOnAWS\Tests\Integration;

use WP_UnitTestCase;

class EventSendingTest extends WP_UnitTestCase
{
    protected $fixtures;

    public function setUp(): void
    {
        parent::setUp();

        // Load AWS response fixtures
        $this->fixtures = include dirname(__DIR__) . '/fixtures/aws-responses.php';
    }

    public function tearDown(): void
    {
        remove_all_filters('pre_http_request');
        parent::tearDown();
    }

    /**
     * Test successful event sending with real payload
     */
    public function test_send_event_success_with_real_payload()
    {
        // Mock successful response
        add_filter('pre_http_request', function($preempt, $args, $url) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test Post',
                'status' => 'publish',
                'author' => 'admin',
            ]
        );

        $this->assertTrue($result['success'], 'Event should be sent successfully');
        $this->assertNull($result['error']);
        $this->assertIsArray($result['response']);
        $this->assertEquals(0, $result['response']['FailedEntryCount']);
    }

    /**
     * Test event sending with Unicode characters
     */
    public function test_send_event_with_unicode_characters()
    {
        add_filter('pre_http_request', function($preempt, $args, $url) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test 日本語 中文 한글 Русский العربية',
                'content' => 'Unicode content: ✓ ☆ ♥ ♣ ♠ ♦ © ® ™',
                'emoji' => '😀 🎉 🚀 ❤️',
            ]
        );

        $this->assertTrue($result['success'], 'Event with Unicode should be sent successfully');
        $this->assertNull($result['error']);
    }

    /**
     * Test event sending with large payload (approaching size limit)
     */
    public function test_send_event_with_large_payload()
    {
        add_filter('pre_http_request', function($preempt, $args, $url) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        // Create a large but valid payload (~100KB)
        $largeContent = str_repeat('Lorem ipsum dolor sit amet, consectetur adipiscing elit. ', 2000);

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test Post with Large Content',
                'content' => $largeContent,
                'meta' => array_fill(0, 100, 'metadata value'),
            ]
        );

        $this->assertTrue($result['success'], 'Event with large payload should be sent successfully');
        $this->assertNull($result['error']);
    }

    /**
     * Test event sending exceeding 256KB size limit
     */
    public function test_send_event_exceeding_size_limit()
    {
        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        // Create payload exceeding 256KB
        // Each character is 1 byte, so we need 300KB of content
        $massiveContent = str_repeat('A', 300 * 1024);

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test Post',
                'content' => $massiveContent,
            ]
        );

        $this->assertFalse($result['success'], 'Event exceeding 256KB should fail');
        $this->assertStringContainsString('exceeds 256KB limit', $result['error']);
        $this->assertFalse($result['is_transient'], 'Size limit error should not be transient');
    }

    /**
     * Test retry logic on HTTP 500 error
     */
    public function test_send_event_retry_on_500_error()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                // First 3 attempts return 500, then success
                if ($attempt_count < 3) {
                    return $this->fixtures['http_500_error'];
                } else {
                    return $this->fixtures['success_single_event'];
                }
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success'], 'Event should succeed after retries');
        $this->assertEquals(3, $attempt_count, 'Should retry and succeed on 3rd attempt');
    }

    /**
     * Test no retry on HTTP 400 error (permanent failure)
     */
    public function test_send_event_no_retry_on_400_error()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                return $this->fixtures['http_400_bad_request'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertFalse($result['success'], 'Event should fail on 400 error');
        $this->assertEquals(1, $attempt_count, 'Should not retry on 400 error');
        $this->assertStringContainsString('HTTP 400', $result['error']);
    }

    /**
     * Test retry on HTTP 429 throttling error
     */
    public function test_send_event_throttling_backoff()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                // First 2 attempts throttled, then success
                if ($attempt_count < 3) {
                    return $this->fixtures['http_429_throttling'];
                } else {
                    return $this->fixtures['success_single_event'];
                }
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success'], 'Event should succeed after throttling retries');
        $this->assertEquals(3, $attempt_count, 'Should retry throttling errors');
    }

    /**
     * Test retry exhaustion after max attempts
     */
    public function test_send_event_max_retry_exhaustion()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                // Always return 500 to exhaust retries
                return $this->fixtures['http_500_error'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertFalse($result['success'], 'Event should fail after max retries');
        $this->assertEquals(4, $attempt_count, 'Should attempt 4 times (initial + 3 retries)');
        $this->assertTrue($result['is_transient'], 'HTTP 500 errors should be marked as transient');
    }

    /**
     * Test network error retry
     */
    public function test_send_event_network_error_retry()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                // First 2 attempts network error, then success
                if ($attempt_count < 3) {
                    return $this->fixtures['network_timeout'];
                } else {
                    return $this->fixtures['success_single_event'];
                }
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success'], 'Event should succeed after network error retries');
        $this->assertEquals(3, $attempt_count, 'Should retry network errors');
    }

    /**
     * Test partial failure handling
     */
    public function test_send_event_partial_failure()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                return $this->fixtures['partial_failure'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertFalse($result['success'], 'Partial failure should be treated as failure');
        $this->assertStringContainsString('Partial failure', $result['error']);
        $this->assertEquals(4, $attempt_count, 'Should retry partial failures');
        $this->assertTrue($result['is_transient'], 'Partial failures should be marked as transient');
    }

    /**
     * Test HTTP 403 access denied (not retryable)
     */
    public function test_send_event_access_denied_no_retry()
    {
        $attempt_count = 0;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$attempt_count) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                $attempt_count++;
                return $this->fixtures['http_403_access_denied'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertFalse($result['success'], 'Access denied should fail');
        $this->assertEquals(1, $attempt_count, 'Should not retry 403 errors');
        $this->assertStringContainsString('HTTP 403', $result['error']);
    }

    /**
     * Test event sending with session token (IAM role credentials)
     */
    public function test_send_event_with_session_token()
    {
        add_filter('pre_http_request', function($preempt, $args, $url) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                // Verify session token is in headers
                $this->assertArrayHasKey('X-Amz-Security-Token', $args['headers']);
                $this->assertEquals('test-session-token', $args['headers']['X-Amz-Security-Token']);
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1',
            'test-session-token'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success'], 'Event with session token should succeed');
    }

    /**
     * Test event sending to custom event bus
     */
    public function test_send_event_to_custom_event_bus()
    {
        add_filter('pre_http_request', function($preempt, $args, $url) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                // Verify event bus name in payload
                $payload = json_decode($args['body'], true);
                $this->assertEquals('custom-event-bus', $payload['Entries'][0]['EventBusName']);
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1',
            null,
            'custom-event-bus'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success'], 'Event to custom bus should succeed');
    }

    /**
     * Test event sending validates signature correctly
     */
    public function test_send_event_signature_validation()
    {
        $signature_verified = false;

        add_filter('pre_http_request', function($preempt, $args, $url) use (&$signature_verified) {
            if (strpos($url, 'events.') !== false && strpos($url, '.amazonaws.com') !== false) {
                // Verify Authorization header exists and has correct format
                $this->assertArrayHasKey('Authorization', $args['headers']);
                $auth_header = $args['headers']['Authorization'];

                $this->assertStringStartsWith('AWS4-HMAC-SHA256 Credential=', $auth_header);
                $this->assertStringContainsString('SignedHeaders=', $auth_header);
                $this->assertStringContainsString('Signature=', $auth_header);

                $signature_verified = true;
                return $this->fixtures['success_single_event'];
            }
            return $preempt;
        }, 10, 3);

        $client = new \EventBridgePutEvents(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test Post']
        );

        $this->assertTrue($result['success']);
        $this->assertTrue($signature_verified, 'Signature should be verified');
    }
}
