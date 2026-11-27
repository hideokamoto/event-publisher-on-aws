<?php

namespace EventPublisherOnAWS\Tests\Unit;

use EventBridgePutEvents;
use EventPublisherOnAWS\Tests\Support\ReflectionTestHelper;
use PHPUnit\Framework\TestCase;

class EventBridgeErrorHandlingTest extends TestCase
{
    use ReflectionTestHelper;

    private function makeClient(): EventBridgePutEvents
    {
        return new EventBridgePutEvents(
            'AKIATEST',
            'secret',
            'us-east-1',
            null,
            'default',
            null
        );
    }

    public function test_non_retryable_entry_stops_retries(): void
    {
        $client = $this->makeClient();
        $entries = [
            ['ErrorCode' => 'AccessDeniedException', 'ErrorMessage' => 'denied'],
        ];

        $this->assertFalse($this->invokePrivate($client, 'hasRetryableFailedEntry', [$entries]));
    }

    public function test_internal_failure_is_retryable(): void
    {
        $client = $this->makeClient();
        $entries = [
            ['ErrorCode' => 'InternalFailure', 'ErrorMessage' => 'try again'],
        ];

        $this->assertTrue($this->invokePrivate($client, 'hasRetryableFailedEntry', [$entries]));
    }

    public function test_malformed_entries_default_to_retry(): void
    {
        $client = $this->makeClient();

        $this->assertTrue($this->invokePrivate($client, 'hasRetryableFailedEntry', ['not-an-array']));
        $this->assertTrue($this->invokePrivate($client, 'hasRetryableFailedEntry', [[]]));
    }
}