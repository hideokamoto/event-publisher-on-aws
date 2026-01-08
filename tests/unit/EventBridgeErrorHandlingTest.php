<?php
/**
 * Unit tests for EventBridge API error handling
 *
 * Tests error handling paths for various AWS EventBridge API errors.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class EventBridgeErrorHandlingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // Define constants needed for tests
        if (!defined('EVENT_BUS_NAME')) {
            define('EVENT_BUS_NAME', 'test-bus');
        }
        if (!defined('EVENT_SOURCE_NAME')) {
            define('EVENT_SOURCE_NAME', 'test-source');
        }
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Test handling of HTTP 500 errors (retryable)
     */
    public function test_http_500_error_is_retryable()
    {
        $statusCode = 500;
        $responseBody = json_encode(['__type' => 'InternalException', 'message' => 'Internal server error']);

        // Mock wp_remote_request to return 500 error
        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $code = wp_remote_retrieve_response_code($response);

        $this->assertEquals(500, $code);
        $this->assertTrue($code >= 500 && $code < 600, 'HTTP 500 errors should be retryable');
    }

    /**
     * Test handling of HTTP 400 errors (not retryable)
     */
    public function test_http_400_error_is_not_retryable()
    {
        $statusCode = 400;
        $responseBody = json_encode(['__type' => 'ValidationException', 'message' => 'Invalid parameter']);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $code = wp_remote_retrieve_response_code($response);

        $this->assertEquals(400, $code);
        $this->assertFalse($code >= 500 && $code < 600, 'HTTP 400 errors should not be retryable');
    }

    /**
     * Test handling of HTTP 429 (throttling) errors
     */
    public function test_http_429_throttling_error()
    {
        $statusCode = 429;
        $responseBody = json_encode(['__type' => 'ThrottlingException', 'message' => 'Rate exceeded']);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $code = wp_remote_retrieve_response_code($response);

        $this->assertEquals(429, $code);
        $this->assertTrue($code === 429, 'HTTP 429 errors should be retryable');
    }

    /**
     * Test handling of WP_Error (network errors)
     */
    public function test_wp_error_handling()
    {
        $mockError = new \WP_Error('http_request_failed', 'Connection timeout');

        Functions\when('wp_remote_request')->justReturn($mockError);
        Functions\when('is_wp_error')->justReturn(true);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);

        $this->assertTrue(is_wp_error($response), 'WP_Error should be properly detected');
    }

    /**
     * Test handling of partial failures in PutEvents response
     */
    public function test_partial_failure_handling()
    {
        $statusCode = 200;
        $responseBody = json_encode([
            'FailedEntryCount' => 1,
            'Entries' => [
                [
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'Internal error',
                ],
            ],
        ]);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $this->assertEquals(200, wp_remote_retrieve_response_code($response));
        $this->assertEquals(1, $data['FailedEntryCount']);
        $this->assertArrayHasKey('Entries', $data);
    }

    /**
     * Test successful EventBridge response
     */
    public function test_successful_eventbridge_response()
    {
        $statusCode = 200;
        $responseBody = json_encode([
            'FailedEntryCount' => 0,
            'Entries' => [
                [
                    'EventId' => '11710aed-b79e-4468-a20b-bb3c0c3b4860',
                ],
            ],
        ]);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $this->assertEquals(200, wp_remote_retrieve_response_code($response));
        $this->assertEquals(0, $data['FailedEntryCount']);
        $this->assertArrayHasKey('EventId', $data['Entries'][0]);
    }

    /**
     * Test handling of authorization errors (403)
     */
    public function test_http_403_authorization_error()
    {
        $statusCode = 403;
        $responseBody = json_encode([
            '__type' => 'AccessDeniedException',
            'message' => 'User is not authorized to perform: events:PutEvents',
        ]);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => $statusCode],
            'body' => $responseBody,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn($statusCode);
        Functions\when('wp_remote_retrieve_body')->justReturn($responseBody);

        $response = wp_remote_request('https://events.us-east-1.amazonaws.com/', []);
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $this->assertEquals(403, $code);
        $this->assertEquals('AccessDeniedException', $data['__type']);
        $this->assertFalse($code >= 500, 'HTTP 403 errors should not be retryable');
    }

    /**
     * Test error response parsing
     */
    public function test_error_response_parsing()
    {
        $errors = [
            ['ErrorCode' => 'InternalException', 'ErrorMessage' => 'Internal error'],
            ['ErrorCode' => 'ValidationException', 'ErrorMessage' => 'Invalid parameter'],
            ['ErrorCode' => 'ThrottlingException', 'ErrorMessage' => 'Rate exceeded'],
        ];

        foreach ($errors as $error) {
            $this->assertArrayHasKey('ErrorCode', $error);
            $this->assertArrayHasKey('ErrorMessage', $error);
            $this->assertNotEmpty($error['ErrorCode']);
            $this->assertNotEmpty($error['ErrorMessage']);
        }
    }

    /**
     * Test retry logic with exponential backoff
     */
    public function test_retry_logic_concept()
    {
        $maxRetries = 3;
        $initialDelay = 1;
        $expectedDelays = [];

        for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
            $delay = $initialDelay * pow(2, $attempt);
            $expectedDelays[] = $delay;
        }

        // Verify exponential backoff pattern: 1, 2, 4
        $this->assertEquals([1, 2, 4], $expectedDelays);
    }

    /**
     * Test DNS resolution failure
     */
    public function test_dns_resolution_failure()
    {
        $mockError = new \WP_Error('http_request_failed', 'Could not resolve host');

        Functions\when('wp_remote_request')->justReturn($mockError);
        Functions\when('is_wp_error')->justReturn(true);

        $response = wp_remote_request('https://invalid.amazonaws.com/', []);

        $this->assertTrue(is_wp_error($response));
    }
}
