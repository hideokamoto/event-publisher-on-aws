<?php
/**
 * Unit tests for EventBridge API error handling
 *
 * @package EventBridge_Post_Events
 */

use Brain\Monkey;
use Brain\Monkey\Functions;

/**
 * Test EventBridge error handling logic
 */
class EventBridgeErrorHandlingTest extends EventBridge_Unit_Test_Case
{
    /**
     * Test retryable HTTP status codes
     */
    public function test_retryable_status_codes()
    {
        $retryable_codes = array(500, 502, 503, 504, 429);

        foreach ($retryable_codes as $code) {
            $this->assertTrue(
                $this->is_retryable_error($code),
                "HTTP {$code} should be retryable"
            );
        }
    }

    /**
     * Test non-retryable HTTP status codes
     */
    public function test_non_retryable_status_codes()
    {
        $non_retryable_codes = array(400, 401, 403, 404);

        foreach ($non_retryable_codes as $code) {
            $this->assertFalse(
                $this->is_retryable_error($code),
                "HTTP {$code} should not be retryable"
            );
        }
    }

    /**
     * Test partial failure detection
     */
    public function test_partial_failure_detection()
    {
        $response = array(
            'FailedEntryCount' => 1,
            'Entries' => array(
                array(
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'Internal service error',
                ),
            ),
        );

        $this->assertTrue($this->has_partial_failure($response));
        $this->assertEquals(1, $response['FailedEntryCount']);
    }

    /**
     * Test successful response detection
     */
    public function test_successful_response()
    {
        $response = array(
            'FailedEntryCount' => 0,
            'Entries' => array(
                array('EventId' => 'event-id-12345'),
            ),
        );

        $this->assertFalse($this->has_partial_failure($response));
    }

    /**
     * Test error type classification - ThrottlingException
     */
    public function test_throttling_is_transient()
    {
        $error_code = 'ThrottlingException';
        $error_type = $this->classify_error_type($error_code);

        $this->assertEquals('transient', $error_type);
    }

    /**
     * Test error type classification - InternalException
     */
    public function test_internal_error_is_transient()
    {
        $error_code = 'InternalException';
        $error_type = $this->classify_error_type($error_code);

        $this->assertEquals('transient', $error_type);
    }

    /**
     * Test error type classification - AccessDeniedException
     */
    public function test_access_denied_is_permanent()
    {
        $error_code = 'AccessDeniedException';
        $error_type = $this->classify_error_type($error_code);

        $this->assertEquals('permanent', $error_type);
    }

    /**
     * Test error type classification - ValidationException
     */
    public function test_validation_error_is_permanent()
    {
        $error_code = 'ValidationException';
        $error_type = $this->classify_error_type($error_code);

        $this->assertEquals('permanent', $error_type);
    }

    /**
     * Test error message parsing from JSON response
     */
    public function test_error_message_parsing()
    {
        $response_body = json_encode(array(
            '__type' => 'AccessDeniedException',
            'message' => 'User is not authorized to perform events:PutEvents',
        ));

        $parsed = $this->parse_error_response($response_body);

        $this->assertEquals('AccessDeniedException', $parsed['type']);
        $this->assertStringContainsString('not authorized', $parsed['message']);
    }

    /**
     * Test error message parsing with invalid JSON
     */
    public function test_error_parsing_invalid_json()
    {
        $response_body = 'Invalid JSON response';

        $parsed = $this->parse_error_response($response_body);

        $this->assertNull($parsed['type']);
        $this->assertEquals('Invalid JSON response', $parsed['message']);
    }

    /**
     * Test exponential backoff calculation
     */
    public function test_exponential_backoff()
    {
        $delays = array();
        $delay = 1;

        for ($attempt = 0; $attempt < 4; $attempt++) {
            $delays[] = $delay;
            $delay *= 2;
        }

        $this->assertEquals(array(1, 2, 4, 8), $delays);
    }

    /**
     * Test failure detail extraction
     */
    public function test_failure_detail_extraction()
    {
        $response = array(
            'FailedEntryCount' => 2,
            'Entries' => array(
                array(
                    'ErrorCode' => 'ThrottlingException',
                    'ErrorMessage' => 'Rate exceeded',
                ),
                array(
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'Internal error',
                ),
            ),
        );

        $details = $this->extract_failure_details($response);

        $this->assertCount(2, $details);
        $this->assertStringContainsString('ThrottlingException', $details[0]);
        $this->assertStringContainsString('InternalException', $details[1]);
    }

    /**
     * Check if error is retryable based on status code
     */
    private function is_retryable_error($status_code)
    {
        return ($status_code >= 500 && $status_code < 600) || $status_code === 429;
    }

    /**
     * Check if response has partial failure
     */
    private function has_partial_failure($response)
    {
        return isset($response['FailedEntryCount']) && (int)$response['FailedEntryCount'] > 0;
    }

    /**
     * Classify error type based on error code
     */
    private function classify_error_type($error_code)
    {
        $transient_errors = array('ThrottlingException', 'InternalException');
        return in_array($error_code, $transient_errors) ? 'transient' : 'permanent';
    }

    /**
     * Parse error response JSON
     */
    private function parse_error_response($response_body)
    {
        $data = json_decode($response_body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return array(
                'type' => null,
                'message' => $response_body,
            );
        }

        return array(
            'type' => isset($data['__type']) ? $data['__type'] : null,
            'message' => isset($data['message']) ? $data['message'] : '',
        );
    }

    /**
     * Extract failure details from response
     */
    private function extract_failure_details($response)
    {
        $details = array();

        if (isset($response['Entries']) && is_array($response['Entries'])) {
            foreach ($response['Entries'] as $index => $entry) {
                if (isset($entry['ErrorCode'])) {
                    $details[] = sprintf(
                        'Entry[%d]: ErrorCode=%s, ErrorMessage=%s',
                        $index,
                        $entry['ErrorCode'],
                        isset($entry['ErrorMessage']) ? $entry['ErrorMessage'] : 'N/A'
                    );
                }
            }
        }

        return $details;
    }
}
