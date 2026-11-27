<?php
class EventBridgePutEvents
{
    // AWS region format validation pattern
    // Supports standard regions (us-east-1) and GovCloud regions (us-gov-west-1)
    const REGION_FORMAT_REGEX = '/^[a-z]{2,3}(-[a-z]+)+-\d+$/';

    /**
     * PutEvents entry error codes that are not worth resending.
     *
     * Source: the EventBridge API model, shape PutEventsResultEntry, member ErrorCode
     * (Smithy shape com.amazonaws.eventbridge#PutEventsResultEntry; the same text ships
     * in botocore 1.43.108 as botocore/data/events/2015-10-07/service-2.json.gz). Its
     * documentation, quoted with the HTML tags removed and the lines rewrapped:
     *
     *   "The error code that indicates why the event submission failed.
     *    Retryable errors include:
     *      InternalFailure
     *        The request processing has failed because of an unknown error, exception or
     *        failure.
     *      ThrottlingException
     *        The request was denied due to request throttling.
     *    Non-retryable errors include:
     *      AccessDeniedException
     *        You do not have sufficient access to perform this action.
     *      InvalidAccountIdException
     *        The account ID provided is not valid.
     *      InvalidArgument
     *        A specified parameter is not valid.
     *      MalformedDetail
     *        The JSON provided is not valid.
     *      RedactionFailure
     *        Redacting the CloudTrail event failed.
     *      NotAuthorizedForSourceException
     *        You do not have permissions to publish events with this source onto this
     *        event bus.
     *      NotAuthorizedForDetailTypeException
     *        You do not have permissions to publish events with this detail type onto
     *        this event bus."
     *
     * Both lists say "include", so neither is exhaustive. Only the codes listed as
     * non-retryable stop the retry loop; any other code keeps being retried.
     */
    const NON_RETRYABLE_ENTRY_ERROR_CODES = array(
        'AccessDeniedException',
        'InvalidAccountIdException',
        'InvalidArgument',
        'MalformedDetail',
        'RedactionFailure',
        'NotAuthorizedForSourceException',
        'NotAuthorizedForDetailTypeException',
    );

    private $accessKeyId;
    private $secretAccessKey;
    private $sessionToken;
    private $region;
    private $endpoint;
    private $serviceName;
    private $eventBusName;
    private $logger;

    public function __construct($accessKeyId, $secretAccessKey, $region, $sessionToken = null, $eventBusName = 'default', $logger = null)
    {
        // Validate credential parameters
        if (empty($accessKeyId) || empty($secretAccessKey)) {
            throw new Exception('EventBridgePutEvents: Access key ID and secret access key cannot be empty');
        }

        // Validate region format (supports standard and GovCloud regions)
        if (empty($region) || !preg_match(self::REGION_FORMAT_REGEX, $region)) {
            $safe_region = is_string($region) ? sanitize_text_field($region) : '';
            throw new Exception(
                sprintf(
                    'EventBridgePutEvents: Invalid AWS region format: %s',
                    esc_html($safe_region)
                )
            );
        }

        $this->accessKeyId = $accessKeyId;
        $this->secretAccessKey = $secretAccessKey;
        $this->sessionToken = $sessionToken;
        $this->region = $region;
        $this->endpoint = 'events.' . $region . '.amazonaws.com';
        $this->serviceName = 'events';
        $this->eventBusName = $eventBusName;
        $this->logger = $logger;
    }

    public function sendEvent($source, $detailType, $detail)
    {
        $method = 'POST';
        $path = '/';

        // Encode Detail field using wp_json_encode and check for failures
        $detail_json = $this->encode_and_validate($detail, 'Detail field', $detailType, $detail);
        if (is_array($detail_json)) {
            return $detail_json; // Error response
        }

        // Build the EventBridge envelope
        $envelope = array(
            'Entries' => array(
                array(
                    'EventBusName' => $this->eventBusName,
                    'Source' => $source,
                    'DetailType' => $detailType,
                    'Detail' => $detail_json,
                ),
            ),
        );

        // Encode outer payload using wp_json_encode and check for failures
        $payload = $this->encode_and_validate($envelope, 'EventBridge envelope', $detailType, $detail);
        if (is_array($payload)) {
            return $payload; // Error response
        }

        $payload_size = strlen($payload);
        $max_payload_size = 256 * 1024; // 256KB in bytes

        if ($payload_size > $max_payload_size) {
            $postId = isset($detail['id']) ? $detail['id'] : 'N/A';
            $detail_size = strlen(wp_json_encode($detail));
            $errorMsg = sprintf(
                'EventBridge envelope exceeds 256KB limit: PostID=%s, EnvelopeSize=%d bytes, DetailSize=%d bytes, DetailType=%s',
                $postId,
                $payload_size,
                $detail_size,
                $detailType
            );
            error_log('[EventBridge] ' . $errorMsg);
            return array('success' => false, 'error' => $errorMsg, 'response' => null, 'is_transient' => false);
        }

        $now = new DateTime('now', new DateTimeZone('UTC'));
        $amzDate = $now->format('Ymd\THis\Z');
        $dateStamp = $now->format('Ymd');

        // Include session token in signature if present (for temporary credentials)
        if (!empty($this->sessionToken)) {
            $canonicalHeaders = "content-type:application/x-amz-json-1.1\nhost:{$this->endpoint}\nx-amz-date:{$amzDate}\nx-amz-security-token:{$this->sessionToken}\nx-amz-target:AWSEvents.PutEvents\n";
            $signedHeaders = 'content-type;host;x-amz-date;x-amz-security-token;x-amz-target';
        } else {
            $canonicalHeaders = "content-type:application/x-amz-json-1.1\nhost:{$this->endpoint}\nx-amz-date:{$amzDate}\nx-amz-target:AWSEvents.PutEvents\n";
            $signedHeaders = 'content-type;host;x-amz-date;x-amz-target';
        }
        $canonicalRequest = implode("\n", array(
            $method,
            $path,
            '',
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $payload)
        ));

        $canonicalRequestHash = hash('sha256', $canonicalRequest);
        $stringToSign = implode("\n", array(
            'AWS4-HMAC-SHA256',
            $amzDate,
            "{$dateStamp}/{$this->region}/{$this->serviceName}/aws4_request",
            $canonicalRequestHash
        ));

        $signingKey = $this->getSignatureKey($dateStamp);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        // Clear signing key from memory after use
        $signingKey = null;

        $authorizationHeader = "AWS4-HMAC-SHA256 Credential={$this->accessKeyId}/{$dateStamp}/{$this->region}/{$this->serviceName}/aws4_request, SignedHeaders={$signedHeaders}, Signature={$signature}";

        $headers = array(
            'Content-Type' => 'application/x-amz-json-1.1',
            'X-Amz-Date' => $amzDate,
            'X-Amz-Target' => 'AWSEvents.PutEvents',
            'Authorization' => $authorizationHeader,
        );

        // Add session token to headers if present (for temporary credentials)
        if (!empty($this->sessionToken)) {
            $headers['X-Amz-Security-Token'] = $this->sessionToken;
        }

        // Retry configuration
        $maxRetries = 3;
        $retryDelay = 1; // Initial delay in seconds
        $lastError = null;
        $lastResponseCode = null;
        $attemptsMade = 0; // Requests actually sent, reported in the failure log
        $isPartialFailureRetryable = true; // Set for each partial failure
        $timestamp = date('Y-m-d H:i:s');

        // Check if verbose logging is enabled (DRY principle)
        $verboseLogging = defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;

        // Extract post ID from detail if available (handle both legacy and envelope formats)
        $postId = $detail['id'] ?? ($detail['data']['id'] ?? 'N/A');

        // Retry loop with exponential backoff
        for ($attempt = 0; $attempt <= $maxRetries; $attempt++) {
            // Verbose logging for debugging
            if ($verboseLogging) {
                error_log(sprintf(
                    '[EventBridge] Attempt %d/%d - Sending event: DetailType=%s, PostID=%s, Region=%s, EventBus=%s, Timestamp=%s',
                    $attempt + 1,
                    $maxRetries + 1,
                    $detailType,
                    $postId,
                    $this->region,
                    $this->eventBusName,
                    $timestamp
                ));
            }

            $attemptsMade++;
            $response = wp_remote_request("https://{$this->endpoint}{$path}", array(
                'method' => $method,
                'headers' => $headers,
                'body' => $payload,
                'timeout' => 10,
                'sslverify' => true,
            ));

            // Check if wp_remote_request returned a WP_Error
            if (is_wp_error($response)) {
                $lastError = $response->get_error_message();
                $lastResponseCode = 'WP_Error';

                // Verbose logging for WP_Error
                if ($verboseLogging) {
                    error_log(sprintf(
                        '[EventBridge] WP_Error on attempt %d: %s',
                        $attempt + 1,
                        $lastError
                    ));
                }

                // Debug logging for retry attempts
                if ($this->logger && $attempt < $maxRetries) {
                    $this->logger->log_debug('EventBridge API retry due to network error', array(
                        'attempt' => $attempt + 1,
                        'max_retries' => $maxRetries + 1,
                        'error' => $lastError,
                        'retry_delay' => $retryDelay
                    ));
                }

                // Retry on WP_Error (network issues, etc.)
                if ($attempt < $maxRetries) {
                    sleep($retryDelay);
                    $retryDelay *= 2; // Exponential backoff
                    continue;
                }
            } else {
                // Check HTTP status code
                $statusCode = (int)wp_remote_retrieve_response_code($response);
                $lastResponseCode = $statusCode;
                $responseBody = wp_remote_retrieve_body($response);

                // Check if HTTP status code indicates an error (>= 400)
                if ($statusCode >= 400) {
                    $lastError = sprintf('HTTP %d: %s', $statusCode, $responseBody);

                    // Verbose logging for HTTP errors
                    if ($verboseLogging) {
                        error_log(sprintf(
                            '[EventBridge] HTTP error on attempt %d: Status=%d, Body=%s',
                            $attempt + 1,
                            $statusCode,
                            $responseBody
                        ));
                    }

                    // Determine if error is retryable (simplified logic)
                    $isRetryable = ($statusCode >= 500 && $statusCode < 600) || $statusCode === 429;

                    // Retry if error is retryable and we haven't exceeded max retries
                    if ($isRetryable && $attempt < $maxRetries) {
                        if ($verboseLogging) {
                            error_log(sprintf(
                                '[EventBridge] Retryable error detected. Waiting %d seconds before retry...',
                                $retryDelay
                            ));
                        }

                        // Debug logging for retry attempts
                        if ($this->logger) {
                            $this->logger->log_debug('EventBridge API retry due to retryable HTTP error', array(
                                'attempt' => $attempt + 1,
                                'max_retries' => $maxRetries + 1,
                                'http_code' => $statusCode,
                                'retry_delay' => $retryDelay
                            ));
                        }

                        sleep($retryDelay);
                        $retryDelay *= 2; // Exponential backoff
                        continue;
                    } elseif (!$isRetryable) {
                        // Permanent failure - don't retry
                        if ($verboseLogging) {
                            error_log(sprintf(
                                '[EventBridge] Permanent failure detected (HTTP %d). Not retrying.',
                                $statusCode
                            ));
                        }
                        break;
                    }
                } else {
                    // Success - status code is 2xx
                    $data = json_decode($responseBody, true);

                    // JSONデコードエラーのハンドリング
                    if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
                        $lastError = sprintf('Invalid JSON response: %s', json_last_error_msg());
                        $lastResponseCode = 'JSONError';

                        if ($verboseLogging) {
                            error_log(sprintf(
                                '[EventBridge] JSON decode error on attempt %d: %s, Body: %s',
                                $attempt + 1,
                                $lastError,
                                substr($responseBody, 0, 500)
                            ));
                        }

                        // JSONエラーは通常リトライ可能ではないので、ループを抜ける
                        break;
                    }

                    // Check for partial failures in PutEvents response
                    $failedCount = isset($data['FailedEntryCount']) ? (int)$data['FailedEntryCount'] : 0;

                    if ($failedCount > 0) {
                        // Partial failure detected
                        $failureDetails = array();
                        if (isset($data['Entries']) && is_array($data['Entries'])) {
                            foreach ($data['Entries'] as $index => $entry) {
                                if (isset($entry['ErrorCode'])) {
                                    $failureDetails[] = sprintf(
                                        'Entry[%d]: ErrorCode=%s, ErrorMessage=%s',
                                        $index,
                                        $entry['ErrorCode'],
                                        isset($entry['ErrorMessage']) ? $entry['ErrorMessage'] : 'N/A'
                                    );
                                }
                            }
                        }

                        $lastError = sprintf(
                            'Partial failure: %d/%d entries failed. Details: %s',
                            $failedCount,
                            count($data['Entries']),
                            implode('; ', $failureDetails)
                        );
                        $lastResponseCode = 'PartialFailure';

                        // Verbose logging for partial failure
                        if ($verboseLogging) {
                            error_log(sprintf(
                                '[EventBridge] Partial failure on attempt %d: FailedEntryCount=%d, Response=%s',
                                $attempt + 1,
                                $failedCount,
                                print_r($data, true)
                            ));
                        }

                        // Retry partial failures if retries remain, unless every failed entry
                        // has an error code that cannot succeed on retry
                        $isPartialFailureRetryable = $this->hasRetryableFailedEntry($data['Entries'] ?? null);

                        if (!$isPartialFailureRetryable) {
                            if ($verboseLogging) {
                                error_log('[EventBridge] Partial failure with a non-retryable error code. Not retrying.');
                            }
                            break;
                        }

                        if ($attempt < $maxRetries) {
                            if ($verboseLogging) {
                                error_log(sprintf(
                                    '[EventBridge] Retrying partial failure. Waiting %d seconds...',
                                    $retryDelay
                                ));
                            }

                            // Debug logging for retry attempts
                            if ($this->logger) {
                                $this->logger->log_debug('EventBridge API retry due to partial failure', array(
                                    'attempt' => $attempt + 1,
                                    'max_retries' => $maxRetries + 1,
                                    'failed_count' => $failedCount,
                                    'retry_delay' => $retryDelay
                                ));
                            }

                            sleep($retryDelay);
                            $retryDelay *= 2; // Exponential backoff
                            continue;
                        }

                        // No more retries - break and log final error
                        break;
                    }

                    // Complete success - all entries processed
                    if ($verboseLogging) {
                        error_log(sprintf(
                            '[EventBridge] Success on attempt %d: Status=%d, Response=%s',
                            $attempt + 1,
                            $statusCode,
                            print_r($data, true)
                        ));
                    }

                    // Return array format for metrics tracking compatibility
                    return array('success' => true, 'error' => null, 'response' => $data);
                }
            }
        }

        // Determine if the last error was transient based on response code
        $isLastErrorTransient = false;
        if (is_int($lastResponseCode)) {
            $isLastErrorTransient = ($lastResponseCode >= 500 && $lastResponseCode < 600) || $lastResponseCode === 429;
        } elseif ($lastResponseCode === 'WP_Error') {
            // WP_Error is considered transient
            $isLastErrorTransient = true;
        } elseif ($lastResponseCode === 'PartialFailure') {
            // A partial failure is transient unless its error code is non-retryable
            $isLastErrorTransient = $isPartialFailureRetryable;
        }

        // Retries exhausted or not attempted - log comprehensive error details (excluding sensitive event data)
        error_log(sprintf(
            '[EventBridge] FAILED after %d attempts - DetailType: %s, PostID: %s, LastError: %s, LastResponseCode: %s, IsTransient: %s, Region: %s, EventBus: %s, Timestamp: %s',
            $attemptsMade,
            $detailType,
            $postId,
            $lastError,
            $lastResponseCode,
            $isLastErrorTransient ? 'yes' : 'no',
            $this->region,
            $this->eventBusName,
            $timestamp
        ));

        // Return array format for metrics tracking compatibility
        return array('success' => false, 'error' => $lastError, 'response' => null, 'is_transient' => $isLastErrorTransient);
    }

    /**
     * Encode data to JSON and return error response if encoding fails
     *
     * @param mixed $data Data to encode
     * @param string $context Context description (e.g., "Detail field", "EventBridge envelope")
     * @param string $detailType Event detail type for error logging
     * @param array $detail Event detail for extracting post ID
     * @return array|string Array with error response if encoding fails, JSON string on success
     */
    private function encode_and_validate($data, $context, $detailType, $detail)
    {
        $json = wp_json_encode($data);
        if ($json === false) {
            $postId = isset($detail['id']) ? $detail['id'] : 'N/A';
            $errorMsg = sprintf(
                'Failed to JSON encode %s for DetailType=%s, PostID=%s',
                $context,
                $detailType,
                $postId
            );

            // Add additional context for Detail field
            if ($context === 'Detail field') {
                $errorMsg .= ' (possibly invalid UTF-8 or deeply nested data)';
            }

            error_log('[EventBridge] ' . $errorMsg);
            return array('success' => false, 'error' => $errorMsg, 'response' => null, 'is_transient' => false);
        }
        return $json;
    }

    /**
     * Whether a PutEvents response with FailedEntryCount > 0 is worth resending
     *
     * Returns false only when every failed entry (an entry with an ErrorCode) has a code
     * listed in NON_RETRYABLE_ENTRY_ERROR_CODES. Any other code, or a response with no
     * readable ErrorCode, keeps the previous behaviour of retrying.
     *
     * @param mixed $entries The Entries array from the PutEvents response
     * @return bool True if the request should be retried
     */
    private function hasRetryableFailedEntry($entries)
    {
        if (!is_array($entries)) {
            return true;
        }

        $foundFailedEntry = false;
        foreach ($entries as $entry) {
            if (!is_array($entry) || !isset($entry['ErrorCode'])) {
                continue;
            }
            $foundFailedEntry = true;
            if (!in_array($entry['ErrorCode'], self::NON_RETRYABLE_ENTRY_ERROR_CODES, true)) {
                return true;
            }
        }

        return !$foundFailedEntry;
    }

    private function getSignatureKey($dateStamp)
    {
        $kSecret = 'AWS4' . $this->secretAccessKey;

        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        $kService = hash_hmac('sha256', $this->serviceName, $kRegion, true);

        return hash_hmac('sha256', 'aws4_request', $kService, true);
    }
}
