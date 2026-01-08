<?php
/**
 * AWS EventBridge API response fixtures
 *
 * Mock responses for testing various scenarios.
 */

return [
    /**
     * Successful PutEvents response with single event
     */
    'success_single_event' => [
        'response' => ['code' => 200],
        'body' => json_encode([
            'FailedEntryCount' => 0,
            'Entries' => [
                [
                    'EventId' => '11710aed-b79e-4468-a20b-bb3c0c3b4860',
                ],
            ],
        ]),
    ],

    /**
     * Successful PutEvents response with multiple events
     */
    'success_multiple_events' => [
        'response' => ['code' => 200],
        'body' => json_encode([
            'FailedEntryCount' => 0,
            'Entries' => [
                ['EventId' => '11710aed-b79e-4468-a20b-bb3c0c3b4860'],
                ['EventId' => '22820bfe-c80f-5579-b31c-cc4d1d4c5971'],
                ['EventId' => '33930cgf-d91g-6680-c42d-dd5e2e5d6082'],
            ],
        ]),
    ],

    /**
     * Partial failure - some events succeeded, some failed
     */
    'partial_failure' => [
        'response' => ['code' => 200],
        'body' => json_encode([
            'FailedEntryCount' => 1,
            'Entries' => [
                [
                    'EventId' => '11710aed-b79e-4468-a20b-bb3c0c3b4860',
                ],
                [
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'An internal error occurred',
                ],
            ],
        ]),
    ],

    /**
     * Complete failure - all events failed
     */
    'complete_failure' => [
        'response' => ['code' => 200],
        'body' => json_encode([
            'FailedEntryCount' => 3,
            'Entries' => [
                [
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'An internal error occurred',
                ],
                [
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'An internal error occurred',
                ],
                [
                    'ErrorCode' => 'InternalException',
                    'ErrorMessage' => 'An internal error occurred',
                ],
            ],
        ]),
    ],

    /**
     * HTTP 500 - Internal Server Error (retryable)
     */
    'http_500_error' => [
        'response' => ['code' => 500],
        'body' => json_encode([
            '__type' => 'InternalException',
            'message' => 'An internal error occurred',
        ]),
    ],

    /**
     * HTTP 503 - Service Unavailable (retryable)
     */
    'http_503_error' => [
        'response' => ['code' => 503],
        'body' => json_encode([
            '__type' => 'ServiceUnavailableException',
            'message' => 'Service is temporarily unavailable',
        ]),
    ],

    /**
     * HTTP 429 - Throttling (retryable)
     */
    'http_429_throttling' => [
        'response' => ['code' => 429],
        'body' => json_encode([
            '__type' => 'ThrottlingException',
            'message' => 'Rate exceeded',
        ]),
    ],

    /**
     * HTTP 400 - Bad Request (not retryable)
     */
    'http_400_bad_request' => [
        'response' => ['code' => 400],
        'body' => json_encode([
            '__type' => 'ValidationException',
            'message' => 'Invalid parameter value',
        ]),
    ],

    /**
     * HTTP 403 - Access Denied (not retryable)
     */
    'http_403_access_denied' => [
        'response' => ['code' => 403],
        'body' => json_encode([
            '__type' => 'AccessDeniedException',
            'message' => 'User is not authorized to perform: events:PutEvents on resource',
        ]),
    ],

    /**
     * HTTP 404 - Not Found (not retryable)
     */
    'http_404_not_found' => [
        'response' => ['code' => 404],
        'body' => json_encode([
            '__type' => 'ResourceNotFoundException',
            'message' => 'Event bus does not exist',
        ]),
    ],

    /**
     * Network error - connection timeout
     */
    'network_timeout' => new WP_Error('http_request_failed', 'Connection timeout after 5000ms'),

    /**
     * Network error - DNS resolution failure
     */
    'dns_failure' => new WP_Error('http_request_failed', 'Could not resolve host: events.us-east-1.amazonaws.com'),

    /**
     * Network error - connection refused
     */
    'connection_refused' => new WP_Error('http_request_failed', 'Connection refused'),

    /**
     * EC2 metadata service response
     */
    'ec2_metadata_success' => [
        'response' => ['code' => 200],
        'body' => json_encode([
            'region' => 'us-west-2',
            'instanceId' => 'i-1234567890abcdef0',
            'availabilityZone' => 'us-west-2a',
            'instanceType' => 't2.micro',
            'accountId' => '123456789012',
        ]),
    ],

    /**
     * EC2 metadata service - timeout (not running on EC2)
     */
    'ec2_metadata_timeout' => new WP_Error('http_request_failed', 'Connection timeout'),
];
