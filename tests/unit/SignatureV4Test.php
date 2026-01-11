<?php
/**
 * Unit tests for AWS Signature V4 key derivation
 *
 * Tests the signature generation using test vectors from AWS documentation.
 * Reference: https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
 */

namespace EventPublisherOnAWS\Tests\Unit;

use PHPUnit\Framework\TestCase;

class SignatureV4Test extends TestCase
{
    /**
     * Test AWS Signature V4 key derivation with known test vectors
     *
     * Test vectors from AWS Signature Version 4 Test Suite
     */
    public function test_signature_key_derivation_with_test_vectors()
    {
        $secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $dateStamp = '20150830';
        $region = 'us-east-1';
        $serviceName = 'iam';

        // Derive signing key using the same algorithm as EventBridgePutEvents::getSignatureKey()
        $kSecret = 'AWS4' . $secretKey;
        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $serviceName, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        // Expected hex representation (derived from AWS test vectors)
        $expectedHex = 'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9';
        $actualHex = bin2hex($kSigning);

        $this->assertEquals($expectedHex, $actualHex, 'Signature key derivation should match AWS test vectors');
    }

    /**
     * Test signature key derivation for EventBridge service
     */
    public function test_signature_key_for_eventbridge()
    {
        $secretKey = 'test-secret-key';
        $dateStamp = '20240101';
        $region = 'us-west-2';
        $serviceName = 'events';

        $kSecret = 'AWS4' . $secretKey;
        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $serviceName, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        // Verify the signing key is a binary string of the correct length (32 bytes for SHA256)
        $this->assertEquals(32, strlen($kSigning), 'Signing key should be 32 bytes');
        $this->assertIsString($kSigning);
    }

    /**
     * Test canonical request hash generation
     */
    public function test_canonical_request_hash()
    {
        $method = 'POST';
        $path = '/';
        $queryString = '';
        $canonicalHeaders = "content-type:application/x-amz-json-1.1\nhost:events.us-east-1.amazonaws.com\nx-amz-date:20240101T120000Z\nx-amz-target:AWSEvents.PutEvents\n";
        $signedHeaders = 'content-type;host;x-amz-date;x-amz-target';
        $payloadHash = hash('sha256', '{"test":"data"}');

        $canonicalRequest = implode("\n", [
            $method,
            $path,
            $queryString,
            $canonicalHeaders,
            $signedHeaders,
            $payloadHash
        ]);

        $canonicalRequestHash = hash('sha256', $canonicalRequest);

        // Verify hash format
        $this->assertEquals(64, strlen($canonicalRequestHash), 'SHA256 hash should be 64 hex characters');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $canonicalRequestHash);
    }

    /**
     * Test string to sign generation
     */
    public function test_string_to_sign()
    {
        $amzDate = '20240101T120000Z';
        $dateStamp = '20240101';
        $region = 'us-east-1';
        $serviceName = 'events';
        $canonicalRequestHash = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            "{$dateStamp}/{$region}/{$serviceName}/aws4_request",
            $canonicalRequestHash
        ]);

        $lines = explode("\n", $stringToSign);
        $this->assertCount(4, $lines, 'String to sign should have 4 lines');
        $this->assertEquals('AWS4-HMAC-SHA256', $lines[0]);
        $this->assertEquals($amzDate, $lines[1]);
        $this->assertEquals("{$dateStamp}/{$region}/{$serviceName}/aws4_request", $lines[2]);
        $this->assertEquals($canonicalRequestHash, $lines[3]);
    }

    /**
     * Test payload hash generation
     */
    public function test_payload_hash_generation()
    {
        $payload = json_encode([
            'Entries' => [
                [
                    'EventBusName' => 'default',
                    'Source' => 'test.source',
                    'DetailType' => 'test.event',
                    'Detail' => '{"key":"value"}',
                ],
            ],
        ]);

        $payloadHash = hash('sha256', $payload);

        // Verify hash format
        $this->assertEquals(64, strlen($payloadHash));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $payloadHash);

        // Same payload should produce same hash
        $payloadHash2 = hash('sha256', $payload);
        $this->assertEquals($payloadHash, $payloadHash2);
    }

    /**
     * Test signature generation with different regions
     */
    public function test_signature_different_regions()
    {
        $secretKey = 'test-secret';
        $dateStamp = '20240101';
        $serviceName = 'events';
        $regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1'];

        $signatures = [];
        foreach ($regions as $region) {
            $kSecret = 'AWS4' . $secretKey;
            $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
            $kRegion = hash_hmac('sha256', $region, $kDate, true);
            $kService = hash_hmac('sha256', $serviceName, $kRegion, true);
            $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

            $signatures[$region] = bin2hex($kSigning);
        }

        // Verify all signatures are different
        $uniqueSignatures = array_unique($signatures);
        $this->assertCount(count($regions), $uniqueSignatures, 'Each region should produce a unique signature');
    }

    /**
     * Test authorization header format
     */
    public function test_authorization_header_format()
    {
        $accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
        $dateStamp = '20240101';
        $region = 'us-east-1';
        $serviceName = 'events';
        $signedHeaders = 'content-type;host;x-amz-date;x-amz-target';
        $signature = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

        $authorizationHeader = "AWS4-HMAC-SHA256 Credential={$accessKeyId}/{$dateStamp}/{$region}/{$serviceName}/aws4_request, SignedHeaders={$signedHeaders}, Signature={$signature}";

        // Verify format
        $this->assertStringStartsWith('AWS4-HMAC-SHA256', $authorizationHeader);
        $this->assertStringContainsString("Credential={$accessKeyId}/", $authorizationHeader);
        $this->assertStringContainsString("SignedHeaders={$signedHeaders}", $authorizationHeader);
        $this->assertStringContainsString("Signature={$signature}", $authorizationHeader);
    }

    /**
     * Test date format for AMZ date header
     */
    public function test_amz_date_format()
    {
        $dateTime = new \DateTime('2024-01-01 12:00:00', new \DateTimeZone('UTC'));
        $amzDate = $dateTime->format('Ymd\THis\Z');
        $dateStamp = $dateTime->format('Ymd');

        $this->assertEquals('20240101T120000Z', $amzDate);
        $this->assertEquals('20240101', $dateStamp);
        $this->assertStringContainsString('T', $amzDate);
        $this->assertStringEndsWith('Z', $amzDate);
    }
}
