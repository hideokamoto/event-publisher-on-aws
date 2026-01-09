<?php
/**
 * Unit tests for AWS Signature V4 key derivation
 *
 * Tests use known test vectors from AWS documentation.
 *
 * @package EventBridge_Post_Events
 */

use Brain\Monkey;
use Brain\Monkey\Functions;

/**
 * Test AWS Signature V4 implementation
 */
class SignatureV4Test extends EventBridge_Unit_Test_Case
{
    /**
     * Test signature key derivation with AWS test vectors
     *
     * Test vectors from:
     * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
     */
    public function test_signature_key_derivation()
    {
        // AWS test vector values
        $secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $dateStamp = '20150830';
        $regionName = 'us-east-1';
        $serviceName = 'iam';

        $signingKey = $this->getSignatureKey($secretKey, $dateStamp, $regionName, $serviceName);

        // The signing key should not be false
        $this->assertNotFalse($signingKey);

        // The signing key should be a 32-byte binary string (SHA256)
        $this->assertEquals(32, strlen($signingKey));

        // Verify the hex representation matches AWS test vector
        // AWS provides: c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
        $expectedHex = 'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9';
        $this->assertEquals($expectedHex, bin2hex($signingKey));
    }

    /**
     * Test signature key derivation for EventBridge service
     */
    public function test_eventbridge_signature_key()
    {
        $secretKey = 'test-secret-key-12345';
        $dateStamp = '20240115';
        $regionName = 'ap-northeast-1';
        $serviceName = 'events';

        $signingKey = $this->getSignatureKey($secretKey, $dateStamp, $regionName, $serviceName);

        $this->assertNotFalse($signingKey);
        $this->assertEquals(32, strlen($signingKey));
    }

    /**
     * Test that different dates produce different keys
     */
    public function test_different_dates_different_keys()
    {
        $secretKey = 'test-secret-key';
        $regionName = 'us-east-1';
        $serviceName = 'events';

        $key1 = $this->getSignatureKey($secretKey, '20240101', $regionName, $serviceName);
        $key2 = $this->getSignatureKey($secretKey, '20240102', $regionName, $serviceName);

        $this->assertNotEquals($key1, $key2);
    }

    /**
     * Test that different regions produce different keys
     */
    public function test_different_regions_different_keys()
    {
        $secretKey = 'test-secret-key';
        $dateStamp = '20240101';
        $serviceName = 'events';

        $key1 = $this->getSignatureKey($secretKey, $dateStamp, 'us-east-1', $serviceName);
        $key2 = $this->getSignatureKey($secretKey, $dateStamp, 'eu-west-1', $serviceName);

        $this->assertNotEquals($key1, $key2);
    }

    /**
     * Test signature calculation
     */
    public function test_signature_calculation()
    {
        $secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $dateStamp = '20150830';
        $regionName = 'us-east-1';
        $serviceName = 'iam';

        $signingKey = $this->getSignatureKey($secretKey, $dateStamp, $regionName, $serviceName);

        // Test that we can sign a string
        $stringToSign = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\ntest-hash";
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        $this->assertNotEmpty($signature);
        $this->assertEquals(64, strlen($signature)); // SHA256 hex = 64 chars
    }

    /**
     * Test canonical request hash
     */
    public function test_canonical_request_hash()
    {
        $method = 'POST';
        $path = '/';
        $queryString = '';
        $headers = "content-type:application/x-amz-json-1.1\nhost:events.us-east-1.amazonaws.com\n";
        $signedHeaders = 'content-type;host';
        $payloadHash = hash('sha256', '{"test":"payload"}');

        $canonicalRequest = implode("\n", array(
            $method,
            $path,
            $queryString,
            $headers,
            $signedHeaders,
            $payloadHash
        ));

        $hash = hash('sha256', $canonicalRequest);

        $this->assertEquals(64, strlen($hash));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash);
    }

    /**
     * Test string to sign format
     */
    public function test_string_to_sign_format()
    {
        $algorithm = 'AWS4-HMAC-SHA256';
        $dateTime = '20240115T120000Z';
        $scope = '20240115/us-east-1/events/aws4_request';
        $canonicalHash = hash('sha256', 'test-canonical-request');

        $stringToSign = implode("\n", array(
            $algorithm,
            $dateTime,
            $scope,
            $canonicalHash
        ));

        $this->assertStringContainsString('AWS4-HMAC-SHA256', $stringToSign);
        $this->assertStringContainsString('20240115T120000Z', $stringToSign);
        $this->assertStringContainsString('aws4_request', $stringToSign);
    }

    /**
     * Implementation of getSignatureKey matching the plugin
     */
    private function getSignatureKey($secretKey, $dateStamp, $regionName, $serviceName)
    {
        $kSecret = 'AWS4' . $secretKey;

        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        if ($kDate === false) {
            return false;
        }

        $kRegion = hash_hmac('sha256', $regionName, $kDate, true);
        if ($kRegion === false) {
            return false;
        }

        $kService = hash_hmac('sha256', $serviceName, $kRegion, true);
        if ($kService === false) {
            return false;
        }

        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        if ($kSigning === false) {
            return false;
        }

        return $kSigning;
    }
}
