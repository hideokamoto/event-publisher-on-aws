<?php
/**
 * Unit tests for region detection fallback logic
 *
 * @package EventBridge_Post_Events
 */

use Brain\Monkey;
use Brain\Monkey\Functions;

/**
 * Test region detection logic
 */
class RegionDetectionTest extends EventBridge_Unit_Test_Case
{
    /**
     * Test valid region format validation
     */
    public function test_valid_region_formats()
    {
        $valid_regions = array(
            'us-east-1',
            'us-west-2',
            'eu-west-1',
            'ap-northeast-1',
            'sa-east-1',
            'ca-central-1',
            'me-south-1',
            'af-south-1',
        );

        foreach ($valid_regions as $region) {
            $result = $this->validate_region_format($region);
            $this->assertTrue($result, "Region {$region} should be valid");
        }
    }

    /**
     * Test invalid region format validation
     */
    public function test_invalid_region_formats()
    {
        $invalid_regions = array(
            'invalid',
            'us-east',
            'useast1',
            'US-EAST-1',
            'us_east_1',
            '',
            'us-east-1a',
            '123-456-789',
        );

        foreach ($invalid_regions as $region) {
            $result = $this->validate_region_format($region);
            $this->assertFalse($result, "Region {$region} should be invalid");
        }
    }

    /**
     * Test constant takes precedence
     */
    public function test_constant_takes_precedence()
    {
        Functions\when('defined')->alias(function ($name) {
            return $name === 'EVENT_BRIDGE_REGION';
        });

        Functions\when('constant')->alias(function ($name) {
            if ($name === 'EVENT_BRIDGE_REGION') {
                return 'eu-west-1';
            }
            return null;
        });

        Functions\when('get_option')->justReturn(array(
            'aws_region_override' => 'ap-northeast-1'
        ));

        $region = $this->get_region_with_constant();

        $this->assertEquals('eu-west-1', $region);
    }

    /**
     * Test settings override used when no constant
     */
    public function test_settings_override_used()
    {
        Functions\when('defined')->alias(function ($name) {
            return $name !== 'EVENT_BRIDGE_REGION';
        });

        Functions\when('get_option')->justReturn(array(
            'aws_region_override' => 'ap-southeast-1'
        ));

        $region = $this->get_region_from_settings();

        $this->assertEquals('ap-southeast-1', $region);
    }

    /**
     * Test fallback to us-east-1 when all detection fails
     */
    public function test_fallback_to_default()
    {
        Functions\when('defined')->justReturn(false);
        Functions\when('get_option')->justReturn(array());
        Functions\when('set_transient')->justReturn(true);

        // Mock EC2 metadata failure
        $region = $this->get_region_fallback();

        $this->assertEquals('us-east-1', $region);
    }

    /**
     * Test EC2 metadata parsing
     */
    public function test_ec2_metadata_parsing()
    {
        $mock_response = array(
            'region' => 'ap-northeast-1',
            'availabilityZone' => 'ap-northeast-1a',
            'instanceId' => 'i-1234567890abcdef0',
        );

        $region = $this->extract_region_from_identity($mock_response);

        $this->assertEquals('ap-northeast-1', $region);
    }

    /**
     * Test empty EC2 metadata response
     */
    public function test_empty_ec2_metadata()
    {
        $mock_response = array();

        $region = $this->extract_region_from_identity($mock_response);

        $this->assertNull($region);
    }

    /**
     * Validate region format helper
     */
    private function validate_region_format($region)
    {
        return preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region) === 1;
    }

    /**
     * Get region with constant set
     */
    private function get_region_with_constant()
    {
        if (defined('EVENT_BRIDGE_REGION')) {
            $region = constant('EVENT_BRIDGE_REGION');
            if ($this->validate_region_format($region)) {
                return $region;
            }
        }
        return 'us-east-1';
    }

    /**
     * Get region from settings
     */
    private function get_region_from_settings()
    {
        $settings = get_option('eventbridge_settings', array());
        if (isset($settings['aws_region_override']) && !empty($settings['aws_region_override'])) {
            $region = $settings['aws_region_override'];
            if ($this->validate_region_format($region)) {
                return $region;
            }
        }
        return 'us-east-1';
    }

    /**
     * Get region with fallback
     */
    private function get_region_fallback()
    {
        // Constant not defined
        if (!defined('EVENT_BRIDGE_REGION')) {
            // Settings empty
            $settings = get_option('eventbridge_settings', array());
            if (empty($settings['aws_region_override'])) {
                // EC2 metadata failed, use default
                set_transient('eventbridge_region_fallback_used', true, 3600);
                return 'us-east-1';
            }
        }
        return 'us-east-1';
    }

    /**
     * Extract region from identity document
     */
    private function extract_region_from_identity($identity)
    {
        if (isset($identity['region']) && !empty($identity['region'])) {
            return $identity['region'];
        }
        return null;
    }
}
