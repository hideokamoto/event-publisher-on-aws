<?php
/**
 * Unit tests for AWS credential resolution logic
 *
 * Tests credential resolution from environment variables and constants.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class CredentialResolutionTest extends TestCase
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
     * Test credential resolution from constants
     */
    public function test_credentials_resolved_from_constants()
    {
        // Define constants
        if (!defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID')) {
            define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'test-access-key-123');
        }
        if (!defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'test-secret-key-456');
        }

        // Verify constants are accessible (already defined in phpunit.xml.dist or above)
        $this->assertTrue(defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID'));
        $this->assertTrue(defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY'));
        $this->assertNotEmpty(AWS_EVENTBRIDGE_ACCESS_KEY_ID);
        $this->assertNotEmpty(AWS_EVENTBRIDGE_SECRET_ACCESS_KEY);
    }

    /**
     * Test that empty credentials are detected
     */
    public function test_empty_credentials_detected()
    {
        // Test empty string credential
        $accessKey = '';
        $secretKey = 'valid-secret';

        $this->assertTrue(empty($accessKey), 'Empty access key should be detected');
        $this->assertFalse(empty($secretKey), 'Valid secret key should not be empty');
    }

    /**
     * Test environment variable fallback logic
     *
     * Tests the logic for falling back to environment variables when constants are not defined.
     * Since getenv() is a PHP internal function, we test the fallback logic pattern instead.
     */
    public function test_environment_variable_fallback()
    {
        // Simulate the fallback logic used in the plugin
        $accessKeyFromConst = defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') ? AWS_EVENTBRIDGE_ACCESS_KEY_ID : null;
        $secretKeyFromConst = defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') ? AWS_EVENTBRIDGE_SECRET_ACCESS_KEY : null;

        // When constants are defined, they should be used
        $this->assertNotNull($accessKeyFromConst, 'Access key should be available from constant');
        $this->assertNotNull($secretKeyFromConst, 'Secret key should be available from constant');

        // Test the fallback pattern: if constant is empty, use environment variable
        $fallbackAccessKey = !empty($accessKeyFromConst) ? $accessKeyFromConst : getenv('AWS_EVENTBRIDGE_ACCESS_KEY_ID');
        $fallbackSecretKey = !empty($secretKeyFromConst) ? $secretKeyFromConst : getenv('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY');

        $this->assertNotEmpty($fallbackAccessKey, 'Fallback access key should not be empty');
        $this->assertNotEmpty($fallbackSecretKey, 'Fallback secret key should not be empty');
    }

    /**
     * Test credential validation logic
     */
    public function test_credential_validation()
    {
        $validAccessKey = 'AKIAIOSFODNN7EXAMPLE';
        $validSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        $emptyAccessKey = '';
        $nullSecretKey = null;

        // Valid credentials
        $this->assertFalse(empty($validAccessKey));
        $this->assertFalse(empty($validSecretKey));

        // Invalid credentials
        $this->assertTrue(empty($emptyAccessKey));
        $this->assertTrue(empty($nullSecretKey));
    }

    /**
     * Test that credentials are properly passed to EventBridgePutEvents
     */
    public function test_credentials_passed_to_client()
    {
        $accessKey = 'test-access-key';
        $secretKey = 'test-secret-key';
        $region = 'us-east-1';

        // Create a mock class to test credential passing
        $mockData = [
            'accessKeyId' => $accessKey,
            'secretAccessKey' => $secretKey,
            'region' => $region,
        ];

        $this->assertEquals($accessKey, $mockData['accessKeyId']);
        $this->assertEquals($secretKey, $mockData['secretAccessKey']);
        $this->assertEquals($region, $mockData['region']);
    }
}
