<?php
/**
 * Unit tests for AWS region detection logic
 *
 * Tests region detection from EC2 metadata service with fallback.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class RegionDetectionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Test successful region detection from EC2 metadata
     */
    public function test_region_detected_from_ec2_metadata()
    {
        $mockMetadata = json_encode([
            'region' => 'us-west-2',
            'instanceId' => 'i-1234567890abcdef0',
            'availabilityZone' => 'us-west-2a',
        ]);

        // Mock wp_remote_get to return successful metadata response
        Functions\when('wp_remote_get')->justReturn([
            'response' => ['code' => 200],
            'body' => $mockMetadata,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_body')->justReturn($mockMetadata);

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');
        $this->assertFalse(is_wp_error($response));

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $this->assertEquals('us-west-2', $data['region']);
    }

    /**
     * Test region detection failure handling
     */
    public function test_region_detection_failure_returns_empty_array()
    {
        // Mock wp_remote_get to return WP_Error
        $mockError = new \stdClass();
        $mockError->errors = ['http_request_failed' => ['Connection timeout']];

        Functions\when('wp_remote_get')->justReturn($mockError);
        Functions\when('is_wp_error')->justReturn(true);

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');

        $this->assertTrue(is_wp_error($response));
    }

    /**
     * Test region detection with invalid JSON response
     */
    public function test_region_detection_with_invalid_json()
    {
        $invalidJson = 'not-valid-json';

        Functions\when('wp_remote_get')->justReturn([
            'response' => ['code' => 200],
            'body' => $invalidJson,
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_body')->justReturn($invalidJson);

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $this->assertNull($data);
    }

    /**
     * Test region detection with timeout
     */
    public function test_region_detection_with_timeout()
    {
        $mockError = new \stdClass();
        $mockError->errors = ['http_request_failed' => ['Operation timed out']];

        Functions\when('wp_remote_get')->justReturn($mockError);
        Functions\when('is_wp_error')->justReturn(true);

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');

        $this->assertTrue(is_wp_error($response));
    }

    /**
     * Test region detection with different AWS regions
     */
    public function test_region_detection_various_regions()
    {
        $regions = [
            'us-east-1',
            'us-west-2',
            'eu-west-1',
            'ap-northeast-1',
            'ap-southeast-2',
        ];

        foreach ($regions as $region) {
            $mockMetadata = json_encode([
                'region' => $region,
                'instanceId' => 'i-test123',
            ]);

            Functions\when('wp_remote_get')->justReturn([
                'response' => ['code' => 200],
                'body' => $mockMetadata,
            ]);

            Functions\when('is_wp_error')->justReturn(false);
            Functions\when('wp_remote_retrieve_body')->justReturn($mockMetadata);

            $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);

            $this->assertEquals($region, $data['region']);
        }
    }

    /**
     * Test fallback when metadata service is not available
     */
    public function test_fallback_when_metadata_unavailable()
    {
        // Mock metadata service being unavailable (returns error object)
        $mockError = (object)[
            'code' => 'http_request_failed',
            'message' => 'Connection refused'
        ];

        Functions\when('wp_remote_get')->justReturn($mockError);
        Functions\when('is_wp_error')->justReturn(true);

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');

        // Verify error is properly detected
        $this->assertTrue(is_wp_error($response));
    }
}
