<?php
/**
 * Unit tests for EventBridge payload validation logic
 *
 * Tests the encode_and_validate() method indirectly through sendEvent()
 * to verify JSON encoding, size validation, and error handling.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class PayloadValidationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // Mock WordPress functions BEFORE loading plugin file
        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('wp_parse_args')->alias(function($args, $defaults) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            }
            if (is_array($args)) {
                return array_merge($defaults, $args);
            }
            return $defaults;
        });
        Functions\when('get_option')->justReturn(false);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('register_activation_hook')->justReturn(null);
        Functions\when('register_deactivation_hook')->justReturn(null);
        Functions\when('add_action')->justReturn(null);
        Functions\when('add_filter')->justReturn(null);
        Functions\when('sanitize_text_field')->alias(function($str) {
            return strip_tags($str);
        });
        Functions\when('get_post_types')->justReturn([
            'post' => (object)['name' => 'post', 'label' => 'Posts'],
        ]);
        Functions\when('apply_filters')->alias(function($filter, $value) {
            return $value;
        });
        // Mock wp_remote_request to prevent actual HTTP calls during plugin initialization
        Functions\when('wp_remote_request')->justReturn(
            new \WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('is_wp_error')->alias(function($thing) {
            return $thing instanceof \WP_Error;
        });
        Functions\when('is_admin')->justReturn(false);

        // Load the plugin file to get EventBridgePutEvents class (after mocks are set up)
        if (!class_exists('EventBridgePutEvents')) {
            require_once dirname(dirname(__DIR__)) . '/event-publisher-on-aws.php';
        }
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Test successful JSON encoding of valid data
     */
    public function test_encode_and_validate_success()
    {
        // Mock wp_json_encode to use native json_encode
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        // Mock wp_remote_request to return success
        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Valid Post',
                'content' => 'Test content',
            ]
        );

        $this->assertTrue($result['success']);
        $this->assertNull($result['error']);
    }

    /**
     * Test JSON encoding failure with invalid UTF-8
     */
    public function test_encode_and_validate_invalid_utf8()
    {
        // Mock wp_json_encode to simulate failure
        Functions\when('wp_json_encode')->justReturn(false);

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        // Invalid UTF-8 will cause JSON encoding to fail
        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test',
            ]
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Failed to JSON encode', $result['error']);
        $this->assertStringContainsString('Detail field', $result['error']);
    }

    /**
     * Test payload size validation with exact 256KB limit
     */
    public function test_encode_and_validate_at_size_limit()
    {
        // Mock wp_json_encode to use native json_encode
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        // Create payload that will exceed 256KB limit when wrapped in envelope
        // EventBridge envelope adds overhead with JSON structure
        $content = str_repeat('A', 260 * 1024);

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Large Post',
                'content' => $content,
            ]
        );

        // This should fail as the envelope will exceed 256KB
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('exceeds 256KB limit', $result['error']);
    }

    /**
     * Test payload with special characters and escaping
     */
    public function test_encode_and_validate_special_characters()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test "quotes" and \'apostrophes\'',
                'content' => "Line 1\nLine 2\tTabbed\r\nWindows newline",
                'special' => '<script>alert("xss")</script>',
                'backslash' => 'Path\\to\\file',
            ]
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test payload with null values
     */
    public function test_encode_and_validate_null_values()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'title' => 'Test Post',
                'optional_field' => null,
                'empty_string' => '',
            ]
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test payload with deeply nested data
     */
    public function test_encode_and_validate_deeply_nested_data()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        // Create deeply nested structure
        $nested = [
            'id' => '123',
            'meta' => [
                'level1' => [
                    'level2' => [
                        'level3' => [
                            'level4' => [
                                'level5' => 'deep value',
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            $nested
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test payload with array of objects
     */
    public function test_encode_and_validate_array_of_objects()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'tags' => [
                    ['id' => 1, 'name' => 'Tag 1'],
                    ['id' => 2, 'name' => 'Tag 2'],
                    ['id' => 3, 'name' => 'Tag 3'],
                ],
                'categories' => [
                    ['id' => 10, 'name' => 'Category A'],
                    ['id' => 20, 'name' => 'Category B'],
                ],
            ]
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test payload with numeric types
     */
    public function test_encode_and_validate_numeric_types()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => 123,  // integer
                'price' => 19.99,  // float
                'count' => 0,  // zero
                'negative' => -42,  // negative
                'large_number' => 9999999999,  // large int
            ]
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test payload with boolean values
     */
    public function test_encode_and_validate_boolean_values()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        Functions\when('wp_remote_request')->justReturn([
            'response' => ['code' => 200],
            'body' => json_encode([
                'FailedEntryCount' => 0,
                'Entries' => [['EventId' => 'test-event-id']],
            ]),
        ]);

        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(200);
        Functions\when('wp_remote_retrieve_body')->alias(function($response) {
            return $response['body'];
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '123',
                'is_published' => true,
                'is_draft' => false,
                'has_featured_image' => true,
            ]
        );

        $this->assertTrue($result['success']);
    }

    /**
     * Test envelope encoding failure
     */
    public function test_envelope_encoding_failure()
    {
        $call_count = 0;

        // Mock wp_json_encode to fail on second call (envelope encoding)
        Functions\when('wp_json_encode')->alias(function($data) use (&$call_count) {
            $call_count++;
            if ($call_count === 1) {
                // First call (detail) succeeds
                return json_encode($data);
            } else {
                // Second call (envelope) fails
                return false;
            }
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '123', 'title' => 'Test']
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Failed to JSON encode', $result['error']);
        $this->assertStringContainsString('EventBridge envelope', $result['error']);
    }

    /**
     * Test that error includes post ID in error message
     */
    public function test_error_message_includes_post_id()
    {
        Functions\when('wp_json_encode')->justReturn(false);

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            ['id' => '456', 'title' => 'Test']
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('PostID=456', $result['error']);
    }

    /**
     * Test that error includes detail type in error message
     */
    public function test_error_message_includes_detail_type()
    {
        Functions\when('wp_json_encode')->justReturn(false);

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        $result = $client->sendEvent(
            'wordpress.post',
            'post.deleted',
            ['id' => '123', 'title' => 'Test']
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('DetailType=post.deleted', $result['error']);
    }

    /**
     * Test size limit error message includes details
     */
    public function test_size_limit_error_includes_details()
    {
        Functions\when('wp_json_encode')->alias(function($data) {
            return json_encode($data);
        });

        $client = new \EventBridgePutEvents(
            'test-access-key',
            'test-secret-key',
            'us-east-1'
        );

        // Create oversized payload
        $content = str_repeat('A', 300 * 1024);

        $result = $client->sendEvent(
            'wordpress.post',
            'post.published',
            [
                'id' => '789',
                'content' => $content,
            ]
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('PostID=789', $result['error']);
        $this->assertStringContainsString('EnvelopeSize=', $result['error']);
        $this->assertStringContainsString('DetailSize=', $result['error']);
        $this->assertStringContainsString('bytes', $result['error']);
    }
}
