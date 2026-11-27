<?php

namespace EventPublisherOnAWS\Tests\Unit;

use EventBridgePutEvents;
use EventPublisherOnAWS\Tests\Support\ReflectionTestHelper;
use PHPUnit\Framework\TestCase;

class SignatureV4Test extends TestCase
{
    use ReflectionTestHelper;

    private function makeClient(string $region = 'us-east-1'): EventBridgePutEvents
    {
        return new EventBridgePutEvents(
            'AKIATEST',
            'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            $region,
            null,
            'default',
            null
        );
    }

    public function test_signature_key_derivation_with_test_vectors(): void
    {
        $client = $this->makeClient('us-east-1');
        $signingKey = $this->invokePrivate($client, 'getSignatureKey', ['20150830']);

        $expectedHex = '629fa33a2f374c140cc9922ee83fba66654f052ebcca0fcc269210166ac2c618';
        $this->assertSame($expectedHex, bin2hex($signingKey));
    }

    public function test_signature_key_for_eventbridge_region(): void
    {
        $client = $this->makeClient('us-west-2');
        $signingKey = $this->invokePrivate($client, 'getSignatureKey', ['20240101']);

        $this->assertIsString($signingKey);
        $this->assertSame(32, strlen($signingKey));
    }
}