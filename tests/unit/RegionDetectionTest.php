<?php

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

        require_once dirname(__DIR__) . '/support/load-src.php';

        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('delete_transient')->justReturn(true);
        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->alias(static function ($response) {
            return $response['response']['code'];
        });
        Functions\when('wp_remote_retrieve_body')->alias(static function ($response) {
            return $response['body'];
        });
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function test_region_detected_from_ec2_metadata(): void
    {
        $document = json_encode([
            'region' => 'us-west-2',
            'instanceId' => 'i-1234567890abcdef0',
        ]);

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => 'imds-token',
        ]);
        Functions\when('wp_remote_get')->justReturn([
            'response' => ['code' => 200],
            'body' => $document,
        ]);

        $identity = eventbridge_get_instance_identity_imdsv2(false);

        $this->assertSame('us-west-2', $identity['region'] ?? null);
    }

    public function test_imds_failure_returns_empty_array(): void
    {
        Functions\when('wp_remote_request')->justReturn(
            new \WP_Error('http_request_failed', 'timeout')
        );
        Functions\when('is_wp_error')->justReturn(true);

        $identity = eventbridge_get_instance_identity_imdsv2(false);

        $this->assertSame([], $identity);
    }
}