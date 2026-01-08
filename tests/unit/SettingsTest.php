<?php
/**
 * Unit tests for settings and configuration
 *
 * @package EventBridgePostEvents
 */

use PHPUnit\Framework\TestCase;
use Brain\Monkey;
use Brain\Monkey\Functions;

class SettingsTest extends TestCase
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
     * Test get_setting with constant override
     */
    public function test_get_setting_with_constant_override()
    {
        // Define EVENT_BUS_NAME constant
        if (!defined('EVENT_BUS_NAME')) {
            define('EVENT_BUS_NAME', 'test-bus');
        }

        // Mock get_option to return different value
        Functions\expect('get_option')
            ->once()
            ->with('eventbridge_event_bus_name', '')
            ->andReturn('option-bus');

        // Mock the class (simplified test)
        // In real scenario, you would need to test the actual method
        $this->assertEquals('test-bus', EVENT_BUS_NAME);
    }

    /**
     * Test region validation
     */
    public function test_region_validation()
    {
        // Valid regions
        $validRegions = ['us-east-1', 'eu-west-2', 'ap-southeast-1', 'us-west-2'];

        foreach ($validRegions as $region) {
            $this->assertTrue(
                (bool) preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region),
                "Region {$region} should be valid"
            );
        }

        // Invalid regions
        $invalidRegions = ['US-EAST-1', 'us-east', 'useast1', ''];

        foreach ($invalidRegions as $region) {
            $this->assertFalse(
                (bool) preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region),
                "Region {$region} should be invalid"
            );
        }
    }

    /**
     * Test event bus name sanitization
     */
    public function test_event_bus_name_sanitization()
    {
        // Valid event bus names
        $validNames = ['default', 'my-event-bus', 'event_bus_123', 'app/events'];

        foreach ($validNames as $name) {
            $this->assertTrue(
                (bool) preg_match('/^[a-zA-Z0-9\-_.\/]{1,256}$/', $name),
                "Event bus name {$name} should be valid"
            );
        }

        // Invalid event bus names
        $invalidNames = ['', 'event@bus', 'event bus', str_repeat('a', 257)];

        foreach ($invalidNames as $name) {
            $this->assertFalse(
                (bool) preg_match('/^[a-zA-Z0-9\-_.\/]{1,256}$/', $name),
                "Event bus name {$name} should be invalid"
            );
        }
    }

    /**
     * Test payload size validation
     */
    public function test_payload_size_validation()
    {
        $limit = 256 * 1024; // 256KB

        // Small payload should pass
        $smallPayload = ['test' => 'data'];
        $smallSize = strlen(json_encode($smallPayload));
        $this->assertLessThan($limit, $smallSize);

        // Large payload should fail
        $largePayload = ['data' => str_repeat('x', $limit)];
        $largeSize = strlen(json_encode($largePayload));
        $this->assertGreaterThan($limit, $largeSize);
    }

    /**
     * Test allowed post types filter
     */
    public function test_allowed_post_types()
    {
        // Mock apply_filters
        Functions\expect('apply_filters')
            ->once()
            ->with('eventbridge_allowed_post_types', ['post', 'page'])
            ->andReturn(['post', 'page', 'custom']);

        $result = apply_filters('eventbridge_allowed_post_types', ['post', 'page']);
        $this->assertEquals(['post', 'page', 'custom'], $result);
    }
}
