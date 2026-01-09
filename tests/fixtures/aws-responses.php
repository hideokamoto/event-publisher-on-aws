<?php
/**
 * Test fixtures for AWS API responses
 *
 * @package EventBridge_Post_Events
 */

/**
 * AWS Response Fixtures
 */
class AWSResponseFixtures
{
    /**
     * Get successful PutEvents response
     *
     * @param int $entry_count Number of entries
     * @return array
     */
    public static function success_response($entry_count = 1)
    {
        $entries = array();
        for ($i = 0; $i < $entry_count; $i++) {
            $entries[] = array('EventId' => 'event-id-' . uniqid());
        }

        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => json_encode(array(
                'FailedEntryCount' => 0,
                'Entries' => $entries,
            )),
        );
    }

    /**
     * Get partial failure response
     *
     * @param int $failed_count Number of failed entries
     * @param string $error_code Error code for failed entries
     * @return array
     */
    public static function partial_failure_response($failed_count = 1, $error_code = 'InternalException')
    {
        $entries = array();
        for ($i = 0; $i < $failed_count; $i++) {
            $entries[] = array(
                'ErrorCode' => $error_code,
                'ErrorMessage' => 'Internal service error',
            );
        }

        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => json_encode(array(
                'FailedEntryCount' => $failed_count,
                'Entries' => $entries,
            )),
        );
    }

    /**
     * Get access denied response
     *
     * @return array
     */
    public static function access_denied_response()
    {
        return array(
            'response' => array(
                'code' => 403,
                'message' => 'Forbidden',
            ),
            'body' => json_encode(array(
                '__type' => 'AccessDeniedException',
                'message' => 'User: arn:aws:iam::123456789012:user/test is not authorized to perform: events:PutEvents on resource: arn:aws:events:us-east-1:123456789012:event-bus/default',
            )),
        );
    }

    /**
     * Get invalid signature response
     *
     * @return array
     */
    public static function invalid_signature_response()
    {
        return array(
            'response' => array(
                'code' => 403,
                'message' => 'Forbidden',
            ),
            'body' => json_encode(array(
                '__type' => 'InvalidSignatureException',
                'message' => 'The request signature we calculated does not match the signature you provided.',
            )),
        );
    }

    /**
     * Get throttling response
     *
     * @return array
     */
    public static function throttling_response()
    {
        return array(
            'response' => array(
                'code' => 429,
                'message' => 'Too Many Requests',
            ),
            'body' => json_encode(array(
                '__type' => 'ThrottlingException',
                'message' => 'Rate exceeded',
            )),
        );
    }

    /**
     * Get internal error response
     *
     * @return array
     */
    public static function internal_error_response()
    {
        return array(
            'response' => array(
                'code' => 500,
                'message' => 'Internal Server Error',
            ),
            'body' => json_encode(array(
                '__type' => 'InternalException',
                'message' => 'Internal service error',
            )),
        );
    }

    /**
     * Get service unavailable response
     *
     * @return array
     */
    public static function service_unavailable_response()
    {
        return array(
            'response' => array(
                'code' => 503,
                'message' => 'Service Unavailable',
            ),
            'body' => json_encode(array(
                '__type' => 'ServiceUnavailableException',
                'message' => 'Service is temporarily unavailable',
            )),
        );
    }

    /**
     * Get validation error response
     *
     * @param string $message Validation error message
     * @return array
     */
    public static function validation_error_response($message = 'Invalid event bus name')
    {
        return array(
            'response' => array(
                'code' => 400,
                'message' => 'Bad Request',
            ),
            'body' => json_encode(array(
                '__type' => 'ValidationException',
                'message' => $message,
            )),
        );
    }

    /**
     * Get resource not found response
     *
     * @param string $resource_name Name of the resource
     * @return array
     */
    public static function resource_not_found_response($resource_name = 'event-bus/non-existent')
    {
        return array(
            'response' => array(
                'code' => 404,
                'message' => 'Not Found',
            ),
            'body' => json_encode(array(
                '__type' => 'ResourceNotFoundException',
                'message' => "Event bus {$resource_name} does not exist.",
            )),
        );
    }

    /**
     * Get EC2 metadata success response
     *
     * @param string $region AWS region
     * @return array
     */
    public static function ec2_metadata_response($region = 'us-east-1')
    {
        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => json_encode(array(
                'devpayProductCodes' => null,
                'marketplaceProductCodes' => null,
                'availabilityZone' => $region . 'a',
                'privateIp' => '10.0.0.100',
                'version' => '2017-09-30',
                'instanceId' => 'i-1234567890abcdef0',
                'billingProducts' => null,
                'instanceType' => 't2.micro',
                'accountId' => '123456789012',
                'imageId' => 'ami-12345678',
                'pendingTime' => '2024-01-15T10:00:00Z',
                'architecture' => 'x86_64',
                'kernelId' => null,
                'ramdiskId' => null,
                'region' => $region,
            )),
        );
    }

    /**
     * Get IMDSv2 token response
     *
     * @return array
     */
    public static function imdsv2_token_response()
    {
        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK',
            ),
            'body' => 'AQAAANt3rlbhE9hMkYqJVH2vHEKO_token_example_12345',
        );
    }

    /**
     * Get EC2 metadata timeout response (WP_Error)
     *
     * @return WP_Error
     */
    public static function ec2_metadata_timeout()
    {
        return new WP_Error('http_request_failed', 'Connection timed out after 5000 milliseconds');
    }

    /**
     * Get network error response (WP_Error)
     *
     * @return WP_Error
     */
    public static function network_error()
    {
        return new WP_Error('http_request_failed', 'cURL error 7: Failed to connect to events.us-east-1.amazonaws.com port 443');
    }
}
