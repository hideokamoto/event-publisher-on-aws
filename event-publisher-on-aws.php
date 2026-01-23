<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://example.com/eventbridge-post-events
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 2.0.0
Author: Your Name
Author URI: https://example.com
*/

// Define plugin file constant for reliable reference
if (!defined('EVENTBRIDGE_POST_EVENTS_FILE')) {
    define('EVENTBRIDGE_POST_EVENTS_FILE', __FILE__);
}

// Note: EVENT_BUS_NAME, EVENT_SOURCE_NAME, and EVENT_BRIDGE_REGION can be defined in wp-config.php
// to override admin settings. When not defined, admin settings will be used.

/**
 * Helper function to get IMDSv2 token
 * Used by both activation hook and main class
 *
 * @return string|null Token or null on failure
 */
function eventbridge_get_imds_token()
{
    $token_response = wp_remote_request('http://169.254.169.254/latest/api/token', array(
        'method' => 'PUT',
        'headers' => array('X-aws-ec2-metadata-token-ttl-seconds' => '21600'),
        'timeout' => 2,
    ));

    if (is_wp_error($token_response) || wp_remote_retrieve_response_code($token_response) !== 200) {
        return null;
    }

    $token = wp_remote_retrieve_body($token_response);
    return !empty($token) ? $token : null;
}

/**
 * Helper function to get instance identity using IMDSv2
 * Used by both activation hook and main class
 *
 * @param bool $use_cache Whether to use transient caching
 * @return array Instance identity data or empty array on failure
 */
function eventbridge_get_instance_identity_imdsv2($use_cache = true)
{
    $cache_key = 'eventbridge_imds_identity';
    $failed_cache_key = 'eventbridge_imds_failed';

    // Check cache if enabled
    if ($use_cache) {
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return $cached;
        }

        // Check failed cache to avoid repeated requests on non-EC2 environments
        if (get_transient($failed_cache_key) !== false) {
            return array();
        }
    }

    // Get IMDSv2 token
    $token = eventbridge_get_imds_token();
    if ($token === null) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300); // Cache failure for 5 minutes
        }
        return array();
    }

    // Fetch instance identity document with token
    $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
        'headers' => array('X-aws-ec2-metadata-token' => $token),
        'timeout' => 2,
    ));

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300);
        }
        return array();
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300);
        }
        return array();
    }

    // Cache successful result
    if ($use_cache) {
        set_transient($cache_key, $data, 3600); // Cache for 1 hour
    }

    return $data;
}

/**
 * Helper function to check if instance role credentials are available using IMDSv2
 * Used by activation hook to validate credential availability
 *
 * @return bool True if instance role credentials are available
 */
function eventbridge_check_instance_role_credentials()
{
    // Get IMDSv2 token
    $token = eventbridge_get_imds_token();
    if ($token === null) {
        return false;
    }

    // Try to get IAM role name
    $role_response = wp_remote_get('http://169.254.169.254/latest/meta-data/iam/security-credentials/', array(
        'headers' => array('X-aws-ec2-metadata-token' => $token),
        'timeout' => 2,
    ));

    if (is_wp_error($role_response) || wp_remote_retrieve_response_code($role_response) !== 200) {
        return false;
    }

    $role_name = trim(wp_remote_retrieve_body($role_response));
    return !empty($role_name);
}

class EventBridgePutEvents
{
    // AWS region format validation pattern
    // Supports standard regions (us-east-1) and GovCloud regions (us-gov-west-1)
    const REGION_FORMAT_REGEX = '/^[a-z]{2,3}(-[a-z]+)+-\d+$/';

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
            throw new Exception(sprintf('EventBridgePutEvents: Invalid AWS region format: %s', $region));
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

                        // Retry partial failures if retries remain
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
        } elseif ($lastResponseCode === 'WP_Error' || $lastResponseCode === 'PartialFailure') {
            // WP_Error and PartialFailure are considered transient
            $isLastErrorTransient = true;
        }

        // All retries exhausted - log comprehensive error details (excluding sensitive event data)
        error_log(sprintf(
            '[EventBridge] FAILED after %d attempts - DetailType: %s, PostID: %s, LastError: %s, LastResponseCode: %s, IsTransient: %s, Region: %s, EventBus: %s, Timestamp: %s',
            $maxRetries + 1,
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

    private function getSignatureKey($dateStamp)
    {
        $kSecret = 'AWS4' . $this->secretAccessKey;

        // Validate hash_hmac operations
        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        if ($kDate === false) {
            throw new Exception('Failed to generate date key in signature derivation');
        }

        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        if ($kRegion === false) {
            throw new Exception('Failed to generate region key in signature derivation');
        }

        $kService = hash_hmac('sha256', $this->serviceName, $kRegion, true);
        if ($kService === false) {
            throw new Exception('Failed to generate service key in signature derivation');
        }

        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        if ($kSigning === false) {
            throw new Exception('Failed to generate signing key in signature derivation');
        }

        // Clear intermediate sensitive values from memory
        $kSecret = null;
        $kDate = null;
        $kRegion = null;
        $kService = null;

        return $kSigning;
    }
}

class EventBridgePostEvents
{
    private $region;
    private $credentials;
    private $client;
    private $access_key;
    private $secret_key;
    private $session_token;
    private $credential_source;

    // In-memory counters for tracking metrics
    private $successful_events = 0;
    private $failed_events = 0;
    private $transient_failures = 0;
    private $permanent_failures = 0;

    // Region source tracking for admin notices
    private $region_source = null;

    // WordPress options keys for persistent storage (non-autoload for performance)
    const OPTION_METRICS = 'eventbridge_metrics';
    const OPTION_FAILURE_DETAILS = 'eventbridge_failure_details';
    const OPTION_SETTINGS = 'eventbridge_settings';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5; // Number of failures before showing admin notice

    // IMDS cache transient keys
    const TRANSIENT_IMDS_TOKEN = 'eventbridge_imds_token';
    const TRANSIENT_IMDS_IDENTITY = 'eventbridge_imds_identity';
    const TRANSIENT_IMDS_CREDENTIALS = 'eventbridge_imds_credentials';
    const TRANSIENT_IMDS_FAILED = 'eventbridge_imds_failed';
    const TRANSIENT_CACHED_REGION = 'eventbridge_cached_region';

    // IMDS configuration
    const IMDS_BASE_URL = 'http://169.254.169.254';
    const IMDS_TIMEOUT = 2;

    // IMDS cache durations
    const IMDS_TOKEN_CACHE_DURATION = 21000; // 5h50m (10 min before 6h expiry for safety)
    const IMDS_IDENTITY_CACHE_DURATION = 3600; // 1 hour for successful lookups
    const IMDS_FAILED_CACHE_DURATION = 300;    // 5 minutes for failed lookups
    const REGION_CACHE_DURATION = 86400;       // 24 hours for cached region from IMDS

    // Valid setting values
    const VALID_EVENT_FORMATS = array('envelope');
    const VALID_SEND_MODES = array('sync', 'async');
    const VALID_LOG_LEVELS = array('error', 'info', 'debug');

    // Logging constants
    const LOG_DIR_NAME = 'eventbridge-logs';

    // Settings defaults
    private $settings;

    /**
     * Get AWS credentials from environment variables, WordPress constants, or EC2 instance role
     * Resolution order: environment variables → WordPress constants → EC2 instance role → null
     *
     * @return array|null Array with 'access_key_id', 'secret_access_key', 'session_token' (optional), and 'source', or null if not available
     */
    private function get_aws_credentials()
    {
        // Check environment variables (getenv, $_ENV, $_SERVER)
        $env_access_key = $this->get_env_var('AWS_ACCESS_KEY_ID');
        $env_secret_key = $this->get_env_var('AWS_SECRET_ACCESS_KEY');
        $env_session_token = $this->get_env_var('AWS_SESSION_TOKEN');

        if (!empty($env_access_key) && !empty($env_secret_key)) {
            $this->log_debug('AWS credentials resolved from environment variables');

            $credentials = array(
                'access_key_id' => $env_access_key,
                'secret_access_key' => $env_secret_key,
                'source' => 'environment'
            );

            // Include session token if present (for temporary credentials)
            if (!empty($env_session_token)) {
                $credentials['session_token'] = $env_session_token;
            }

            return $credentials;
        }

        // Fallback to WordPress constants
        if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            $const_access_key = constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID');
            $const_secret_key = constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY');

            if (!empty($const_access_key) && !empty($const_secret_key)) {
                $this->log_debug('AWS credentials resolved from WordPress constants');

                return array(
                    'access_key_id' => $const_access_key,
                    'secret_access_key' => $const_secret_key,
                    'source' => 'constants'
                );
            }
        }

        // Fallback to EC2 instance role credentials
        $instance_creds = $this->get_instance_credentials();
        if ($instance_creds !== null) {
            $this->log_debug('AWS credentials resolved from EC2 instance role');

            return array(
                'access_key_id' => $instance_creds['AccessKeyId'],
                'secret_access_key' => $instance_creds['SecretAccessKey'],
                'session_token' => $instance_creds['Token'],
                'source' => 'instance_role'
            );
        }

        $this->log_error('AWS credentials could not be resolved from any source');
        return null;
    }

    /**
     * Get environment variable from getenv(), $_ENV, or $_SERVER
     * Handles cases where getenv() is disabled
     *
     * @param string $name Environment variable name
     * @return string|false Environment variable value or false if not found
     */
    private function get_env_var($name)
    {
        // Try getenv() first
        $value = getenv($name);
        if ($value !== false && $value !== '') {
            return $value;
        }

        // Fallback to $_ENV
        if (isset($_ENV[$name]) && $_ENV[$name] !== '') {
            return $_ENV[$name];
        }

        // Fallback to $_SERVER
        if (isset($_SERVER[$name]) && $_SERVER[$name] !== '') {
            return $_SERVER[$name];
        }

        return false;
    }

    /**
     * Validate and detect AWS region
     * Resolution order: EVENT_BRIDGE_REGION constant → cached region → EC2 metadata → 'us-east-1' default
     *
     * IMDS is only attempted in admin or wp-cron contexts. The detected region is cached for 24 hours
     * so frontend requests can use the cached value instead of falling back to 'us-east-1'.
     *
     * @return array Array with 'region' and 'source'
     */
    private function get_aws_region()
    {
        // Try EVENT_BRIDGE_REGION constant first (highest priority)
        if (defined('EVENT_BRIDGE_REGION')) {
            $region = constant('EVENT_BRIDGE_REGION');
            if ($this->validate_region_format($region)) {
                return array(
                    'region' => $region,
                    'source' => 'constant'
                );
            } else {
                error_log(sprintf(
                    '[EventBridge] EVENT_BRIDGE_REGION constant has invalid format: %s',
                    $region
                ));
            }
        }

        // Check cached region (from previous IMDS detection in admin/cron)
        $cached_region_data = get_transient(self::TRANSIENT_CACHED_REGION);
        if ($cached_region_data !== false && is_array($cached_region_data)) {
            if (isset($cached_region_data['region']) && $this->validate_region_format($cached_region_data['region'])) {
                return array(
                    'region' => $cached_region_data['region'],
                    'source' => $cached_region_data['source'] . '_cached'
                );
            } else {
                // Invalid cached region, delete it
                delete_transient(self::TRANSIENT_CACHED_REGION);
            }
        }

        // Only try IMDS in admin or wp-cron contexts to avoid frontend performance impact
        $should_try_imds = is_admin() || (defined('DOING_CRON') && DOING_CRON);

        if ($should_try_imds) {
            // Try EC2 instance metadata
            $identity = $this->get_instance_identity();
            if (isset($identity['region']) && !empty($identity['region'])) {
                $region = $identity['region'];
                if ($this->validate_region_format($region)) {
                    $region_data = array(
                        'region' => $region,
                        'source' => 'metadata'
                    );

                    // Cache the detected region for 24 hours so frontend can use it
                    set_transient(self::TRANSIENT_CACHED_REGION, $region_data, self::REGION_CACHE_DURATION);

                    return $region_data;
                } else {
                    error_log(sprintf(
                        '[EventBridge] Region from metadata has invalid format: %s',
                        $region
                    ));
                    // Delete any stale cache since detection returned invalid format
                    delete_transient(self::TRANSIENT_CACHED_REGION);
                }
            } else {
                // IMDS detection failed or returned empty, delete stale cache
                delete_transient(self::TRANSIENT_CACHED_REGION);
            }
        }

        // Fallback to us-east-1
        if (!$should_try_imds) {
            error_log('[EventBridge] Frontend request: Using fallback region us-east-1 (no cached region available)');
        } else {
            error_log('[EventBridge] IMDS detection failed: Using fallback region us-east-1');
        }
        return array(
            'region' => 'us-east-1',
            'source' => 'fallback'
        );
    }

    /**
     * Validate AWS region format using regex pattern
     *
     * @param string $region Region string to validate
     * @return bool True if valid, false otherwise
     */
    private function validate_region_format($region)
    {
        // AWS region format: 2-3 letter prefix, dash, geographic area, dash, number
        // Examples: us-east-1, eu-west-2, ap-southeast-1, us-gov-west-1
        return preg_match(EventBridgePutEvents::REGION_FORMAT_REGEX, $region) === 1;
    }

    public function __construct()
    {
        // Load settings first
        $this->load_settings();

        // Settings page - always register regardless of credentials
        add_action('admin_menu', array($this, 'add_settings_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));

        // Get AWS credentials using resolution order: env vars → constants → instance role
        $credentials = $this->get_aws_credentials();
        if ($credentials === null) {
            add_action('admin_notices', function() {
                ?>
                <div class="notice notice-error">
                    <p><?php esc_html_e('EventBridge Post Events: AWS credentials are not configured. Please set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), wp-config.php constants (AWS_EVENTBRIDGE_ACCESS_KEY_ID, AWS_EVENTBRIDGE_SECRET_ACCESS_KEY), or EC2 instance role.', 'eventbridge-post-events'); ?></p>
                </div>
                <?php
            });
            return;
        }

        // Store credential source
        $this->credential_source = $credentials['source'];

        // Get region using resolution order: constant → metadata → fallback
        $region_info = $this->get_aws_region();
        $this->region = $region_info['region'];
        $this->region_source = $region_info['source'];

        // Store credentials for lazy client initialization
        $this->access_key = $credentials['access_key_id'];
        $this->secret_key = $credentials['secret_access_key'];
        $this->session_token = isset($credentials['session_token']) ? $credentials['session_token'] : null;
        // Note: Client will be initialized after settings are loaded to get event_bus_name
        $this->client = null;

        // Log plugin initialization
        $this->log_info('EventBridge plugin initialized', array(
            'credential_source' => $this->credential_source,
            'region' => $this->region,
            'region_source' => $this->region_source
        ));

        // Load metrics from WordPress options
        $this->load_metrics();

        // 投稿を新規公開、更新した際のアクション
        add_action('transition_post_status', array($this, 'send_post_event'), 10, 3);

        // 投稿を削除した際のアクション
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);

        // 非同期EventBridge送信のアクションフック
        add_action('eventbridge_async_send_event', array($this, 'async_send_event'), 10, 3);

        // EventBridge送信失敗時のハンドラー
        add_action('eventbridge_send_failed', array($this, 'handle_send_failure'), 10, 3);

        // Admin notice for failures
        add_action('admin_notices', array($this, 'display_failure_notice'));

        // Admin notice for credential source and region fallback
        add_action('admin_notices', array($this, 'display_config_notice'));

        // Handle notice dismissal
        add_action('admin_init', array($this, 'handle_notice_dismissal'));
    }

    /**
     * Get the effective AWS region considering aws_region_override setting
     *
     * @return string The effective region to use
     */
    private function get_effective_region()
    {
        $region_override = $this->get_setting('aws_region_override');
        if (!empty($region_override)) {
            return $region_override;
        }
        return $this->region;
    }

    /**
     * Get EventBridge client (lazy initialization)
     *
     * @return EventBridgePutEvents
     */
    private function get_client()
    {
        if ($this->client === null) {
            $event_bus_name = $this->get_setting('event_bus_name');
            $effective_region = $this->get_effective_region();
            $this->client = new EventBridgePutEvents(
                $this->access_key,
                $this->secret_key,
                $effective_region,
                $this->session_token,
                $event_bus_name,
                $this
            );
        }
        return $this->client;
    }

    /**
     * Get default settings
     *
     * @return array Default settings
     */
    private function get_default_settings()
    {
        return array(
            'event_format' => 'envelope', // 'legacy' or 'envelope'
            'send_mode' => 'async',       // 'sync' or 'async'
            'event_bus_name' => 'default',
            'event_source_name' => 'wordpress',
            'aws_region_override' => '',
            'enabled_post_types' => array('post'), // Post types to send events for
            'enable_debug_logging' => false,
            'debug_log_level' => 'error',
        );
    }

    /**
     * Load settings from WordPress options
     */
    private function load_settings()
    {
        $this->settings = wp_parse_args(
            get_option(self::OPTION_SETTINGS, array()),
            $this->get_default_settings()
        );

        // Ensure enabled_post_types is always a valid array
        if (!isset($this->settings['enabled_post_types']) || !is_array($this->settings['enabled_post_types'])) {
            $this->settings['enabled_post_types'] = array('post');
        }
    }

    /**
     * Get a specific setting value with priority resolution
     * Priority order: non-empty constants first → WordPress options → default values
     *
     * @param string $key Setting key
     * @return mixed Setting value
     */
    public function get_setting($key)
    {
        // Map of setting keys to their corresponding constant names
        $constant_map = array(
            'event_bus_name' => 'EVENT_BUS_NAME',
            'event_source_name' => 'EVENT_SOURCE_NAME',
            'aws_region_override' => 'EVENT_BRIDGE_REGION',
        );

        // Check for constant overrides first (highest priority)
        // Only use constant if it's defined AND non-empty
        if (isset($constant_map[$key]) && defined($constant_map[$key])) {
            $constant_value = constant($constant_map[$key]);
            if (is_string($constant_value) && trim($constant_value) !== '') {
                return $constant_value;
            }
        }

        // Then check WordPress options (medium priority)
        if (isset($this->settings[$key])) {
            return $this->settings[$key];
        }

        // Finally fall back to defaults (lowest priority)
        $defaults = $this->get_default_settings();
        return isset($defaults[$key]) ? $defaults[$key] : null;
    }

    /**
     * Sanitize and validate a setting with regex pattern
     * Reduces duplication for event_bus_name, event_source_name, and aws_region_override
     *
     * @param array $input Raw input array
     * @param string $key Setting key
     * @param string $regex Validation regex pattern
     * @param string $error_code Error code for add_settings_error
     * @param string $error_message Error message
     * @param mixed $default Default value to use on failure
     * @return mixed Sanitized and validated value
     */
    private function sanitize_and_validate_setting($input, $key, $regex, $error_code, $error_message, $default)
    {
        if (isset($input[$key]) && !empty($input[$key])) {
            $value = sanitize_text_field($input[$key]);
            if (preg_match($regex, $value)) {
                return $value;
            } else {
                add_settings_error(
                    self::OPTION_SETTINGS,
                    $error_code,
                    $error_message
                );
                return $default;
            }
        }
        return $default;
    }

    /**
     * Add settings menu to WordPress admin
     */
    public function add_settings_menu()
    {
        add_options_page(
            __('EventBridge Settings', 'eventbridge-post-events'),
            __('EventBridge', 'eventbridge-post-events'),
            'manage_options',
            'eventbridge-settings',
            array($this, 'render_settings_page')
        );
    }

    /**
     * Enqueue admin styles for settings page
     *
     * @param string $hook The current admin page hook
     */
    public function enqueue_admin_styles($hook)
    {
        // Only load on our settings page
        if ($hook !== 'settings_page_eventbridge-settings') {
            return;
        }

        wp_enqueue_style(
            'eventbridge-admin-settings',
            plugin_dir_url(__FILE__) . 'assets/css/admin-settings.css',
            array(),
            '1.0.0'
        );
    }

    /**
     * Register settings with WordPress Settings API
     */
    public function register_settings()
    {
        register_setting(
            'eventbridge_settings_group',
            self::OPTION_SETTINGS,
            array($this, 'sanitize_settings')
        );

        // AWS Configuration Section
        add_settings_section(
            'eventbridge_aws_section',
            __('AWS Configuration', 'eventbridge-post-events'),
            array($this, 'render_aws_section_description'),
            'eventbridge-settings'
        );

        add_settings_field(
            'event_bus_name',
            __('Event Bus Name', 'eventbridge-post-events'),
            array($this, 'render_event_bus_name_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        add_settings_field(
            'event_source_name',
            __('Event Source Name', 'eventbridge-post-events'),
            array($this, 'render_event_source_name_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        add_settings_field(
            'aws_region_override',
            __('AWS Region Override', 'eventbridge-post-events'),
            array($this, 'render_aws_region_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        // Event Configuration Section
        add_settings_section(
            'eventbridge_main_section',
            __('Event Configuration', 'eventbridge-post-events'),
            array($this, 'render_section_description'),
            'eventbridge-settings'
        );

        add_settings_field(
            'send_mode',
            __('送信モード', 'eventbridge-post-events'),
            array($this, 'render_send_mode_field'),
            'eventbridge-settings',
            'eventbridge_main_section'
        );

        add_settings_field(
            'enabled_post_types',
            __('送信対象の投稿タイプ', 'eventbridge-post-events'),
            array($this, 'render_post_types_field'),
            'eventbridge-settings',
            'eventbridge_main_section'
        );

        // Debug Logging Section
        add_settings_section(
            'eventbridge_debug_section',
            __('Debug Logging', 'eventbridge-post-events'),
            null,
            'eventbridge-settings'
        );

        add_settings_field(
            'enable_debug_logging',
            __('Enable Debug Logging', 'eventbridge-post-events'),
            array($this, 'render_debug_logging_field'),
            'eventbridge-settings',
            'eventbridge_debug_section'
        );

        add_settings_field(
            'debug_log_level',
            __('Log Level', 'eventbridge-post-events'),
            array($this, 'render_log_level_field'),
            'eventbridge-settings',
            'eventbridge_debug_section'
        );

        // Handle test connection
        add_action('admin_post_eventbridge_test_connection', array($this, 'handle_test_connection'));

        // Handle metrics reset
        add_action('admin_post_eventbridge_reset_metrics', array($this, 'handle_reset_metrics'));

        // Handle clear logs
        add_action('admin_post_eventbridge_clear_logs', array($this, 'handle_clear_logs'));
    }

    /**
     * Sanitize settings before saving
     *
     * @param array $input Raw input
     * @return array Sanitized settings
     */
    public function sanitize_settings($input)
    {
        $sanitized = array();
        $defaults = $this->get_default_settings();

        // Always use envelope format
        $sanitized['event_format'] = 'envelope';

        // Sanitize send_mode
        $sanitized['send_mode'] = isset($input['send_mode']) && in_array($input['send_mode'], self::VALID_SEND_MODES, true)
            ? $input['send_mode']
            : $defaults['send_mode'];

        // Sanitize event_bus_name (preserve existing value if constant override is active and field is disabled)
        // Accepts either a simple name or an ARN: arn:aws:events:REGION:ACCOUNT:event-bus/NAME
        if (defined('EVENT_BUS_NAME') && !isset($input['event_bus_name'])) {
            // Field was disabled due to constant override - preserve existing stored value
            $sanitized['event_bus_name'] = isset($this->settings['event_bus_name']) ? $this->settings['event_bus_name'] : $defaults['event_bus_name'];
        } else {
            $sanitized['event_bus_name'] = $this->sanitize_and_validate_setting(
                $input,
                'event_bus_name',
                '/^([a-zA-Z0-9._\-]{1,256}|arn:aws:events:[a-z]{2,3}(-[a-z]+)+-\d+:\d{12}:event-bus\/[a-zA-Z0-9._\-\/]{1,256})$/',
                'invalid_event_bus_name',
                __('Event Bus Name must be a valid name (alphanumeric, hyphens, underscores, dots; max 256 chars) or a valid ARN (e.g., arn:aws:events:us-east-1:123456789012:event-bus/my-bus, arn:aws:events:us-gov-west-1:123456789012:event-bus/my-bus).', 'eventbridge-post-events'),
                $defaults['event_bus_name']
            );
        }

        // Sanitize event_source_name (preserve existing value if constant override is active and field is disabled)
        // EventBridge Source accepts alphanumeric, dots, hyphens, underscores, and forward slashes
        if (defined('EVENT_SOURCE_NAME') && !isset($input['event_source_name'])) {
            // Field was disabled due to constant override - preserve existing stored value
            $sanitized['event_source_name'] = isset($this->settings['event_source_name']) ? $this->settings['event_source_name'] : $defaults['event_source_name'];
        } else {
            $sanitized['event_source_name'] = $this->sanitize_and_validate_setting(
                $input,
                'event_source_name',
                '/^[a-zA-Z0-9._\-\/]{1,256}$/',
                'invalid_event_source_name',
                __('Event Source Name must contain only alphanumeric characters, hyphens, underscores, dots, and forward slashes (max 256 characters).', 'eventbridge-post-events'),
                $defaults['event_source_name']
            );
        }

        // Sanitize aws_region_override (preserve existing value if constant override is active and field is disabled)
        // Allow empty value to clear the override
        if (defined('EVENT_BRIDGE_REGION') && !isset($input['aws_region_override'])) {
            // Field was disabled due to constant override - preserve existing stored value
            $sanitized['aws_region_override'] = isset($this->settings['aws_region_override']) ? $this->settings['aws_region_override'] : $defaults['aws_region_override'];
        } else {
            $sanitized['aws_region_override'] = $this->sanitize_and_validate_setting(
                $input,
                'aws_region_override',
                EventBridgePutEvents::REGION_FORMAT_REGEX,
                'invalid_aws_region',
                __('AWS Region Override must be in valid format (e.g., us-east-1, ap-northeast-1, us-gov-west-1).', 'eventbridge-post-events'),
                $defaults['aws_region_override']
            );
        }

        // Sanitize enabled_post_types
        $sanitized['enabled_post_types'] = array();
        if (isset($input['enabled_post_types']) && is_array($input['enabled_post_types'])) {
            $valid_post_types = $this->get_available_post_types();
            foreach ($input['enabled_post_types'] as $post_type) {
                $post_type = sanitize_key($post_type);
                if (array_key_exists($post_type, $valid_post_types)) {
                    $sanitized['enabled_post_types'][] = $post_type;
                }
            }
        }

        // If no post types selected, default to 'post'
        if (empty($sanitized['enabled_post_types'])) {
            $sanitized['enabled_post_types'] = $defaults['enabled_post_types'];
        }

        // Sanitize enable_debug_logging
        $sanitized['enable_debug_logging'] = isset($input['enable_debug_logging']) && $input['enable_debug_logging'] === '1';

        // Sanitize debug_log_level
        $sanitized['debug_log_level'] = isset($input['debug_log_level']) && in_array($input['debug_log_level'], self::VALID_LOG_LEVELS, true)
            ? $input['debug_log_level']
            : $defaults['debug_log_level'];

        // Log settings save
        $this->log_info('Plugin settings saved', array(
            'event_format' => $sanitized['event_format'],
            'send_mode' => $sanitized['send_mode'],
            'debug_logging' => $sanitized['enable_debug_logging'] ? 'enabled' : 'disabled',
            'log_level' => $sanitized['debug_log_level']
        ));

        return $sanitized;
    }

    /**
     * Get available post types for EventBridge publishing
     *
     * @return array Associative array of post_type => label
     */
    private function get_available_post_types()
    {
        $post_types = get_post_types(array('public' => true), 'objects');
        $available = array();

        /**
         * Filter the list of post types to exclude from EventBridge settings
         *
         * @param array $excluded_post_types Array of post type slugs to exclude
         */
        $excluded_post_types = apply_filters('eventbridge_excluded_post_types', array('attachment'));

        foreach ($post_types as $post_type => $post_type_obj) {
            if (in_array($post_type, $excluded_post_types, true)) {
                continue;
            }
            $available[$post_type] = $post_type_obj->labels->name;
        }

        return $available;
    }

    /**
     * Render AWS configuration section description
     */
    public function render_aws_section_description()
    {
        ?>
        <p><?php esc_html_e('Configure AWS EventBridge connection settings.', 'eventbridge-post-events'); ?></p>
        <p class="description">
            <strong><?php esc_html_e('Note:', 'eventbridge-post-events'); ?></strong>
            <?php esc_html_e('These settings can be overridden by defining constants in wp-config.php (EVENT_BUS_NAME, EVENT_SOURCE_NAME, EVENT_BRIDGE_REGION). Constants take precedence over admin settings.', 'eventbridge-post-events'); ?>
        </p>
        <?php
    }

    /**
     * Render event bus name field
     */
    public function render_event_bus_name_field()
    {
        $value = $this->settings['event_bus_name'];
        $current_value = $this->get_setting('event_bus_name');
        $is_constant_override = defined('EVENT_BUS_NAME');
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_bus_name]"
               value="<?php echo esc_attr($value); ?>"
               class="regular-text"
               <?php echo $is_constant_override ? 'disabled' : ''; ?>>
        <?php if ($is_constant_override): ?>
            <p class="description" style="color: #d63638;">
                <strong><?php esc_html_e('Overridden by EVENT_BUS_NAME constant:', 'eventbridge-post-events'); ?></strong>
                <code><?php echo esc_html($current_value); ?></code>
            </p>
        <?php else: ?>
            <p class="description">
                <?php esc_html_e('The name of the EventBridge event bus (e.g., default, custom-bus) or ARN (e.g., arn:aws:events:us-east-1:123456789012:event-bus/my-bus). Max 256 characters.', 'eventbridge-post-events'); ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Render event source name field
     */
    public function render_event_source_name_field()
    {
        $value = $this->settings['event_source_name'];
        $current_value = $this->get_setting('event_source_name');
        $is_constant_override = defined('EVENT_SOURCE_NAME');
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_source_name]"
               value="<?php echo esc_attr($value); ?>"
               class="regular-text"
               <?php echo $is_constant_override ? 'disabled' : ''; ?>>
        <?php if ($is_constant_override): ?>
            <p class="description" style="color: #d63638;">
                <strong><?php esc_html_e('Overridden by EVENT_SOURCE_NAME constant:', 'eventbridge-post-events'); ?></strong>
                <code><?php echo esc_html($current_value); ?></code>
            </p>
        <?php else: ?>
            <p class="description">
                <?php esc_html_e('The source identifier for events (e.g., wordpress, com.example.app, aws.partner/source). Max 256 characters.', 'eventbridge-post-events'); ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Render AWS region override field
     */
    public function render_aws_region_field()
    {
        $value = $this->settings['aws_region_override'];
        $current_value = $this->get_setting('aws_region_override');
        $is_constant_override = defined('EVENT_BRIDGE_REGION');
        $detected_region = $this->region;
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[aws_region_override]"
               value="<?php echo esc_attr($value); ?>"
               class="regular-text"
               placeholder="<?php echo esc_attr($detected_region); ?>"
               <?php echo $is_constant_override ? 'disabled' : ''; ?>>
        <?php if ($is_constant_override): ?>
            <p class="description" style="color: #d63638;">
                <strong><?php esc_html_e('Overridden by EVENT_BRIDGE_REGION constant:', 'eventbridge-post-events'); ?></strong>
                <code><?php echo esc_html($current_value); ?></code>
            </p>
        <?php else: ?>
            <p class="description">
                <?php
                printf(
                    esc_html__('Override the detected AWS region (%s). Leave blank to use instance metadata. Format: us-east-1, ap-northeast-1, etc.', 'eventbridge-post-events'),
                    '<code>' . esc_html($detected_region) . '</code>'
                );
                ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Render section description
     */
    public function render_section_description()
    {
        echo '<p>' . esc_html__('EventBridgeへのイベント送信方法を設定します。', 'eventbridge-post-events') . '</p>';
    }

    /**
     * Render send mode field
     */
    public function render_send_mode_field()
    {
        $current = $this->get_setting('send_mode');
        ?>
        <fieldset>
            <label>
                <input type="radio" name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[send_mode]" value="sync" <?php checked($current, 'sync'); ?>>
                <?php esc_html_e('同期送信', 'eventbridge-post-events'); ?>
            </label>
            <p class="description"><?php esc_html_e('投稿の保存時に即座にEventBridgeへ送信します。送信完了まで画面がブロックされます。', 'eventbridge-post-events'); ?></p>
            <br>

            <label>
                <input type="radio" name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[send_mode]" value="async" <?php checked($current, 'async'); ?>>
                <?php esc_html_e('非同期送信（推奨）', 'eventbridge-post-events'); ?>
            </label>
            <p class="description"><?php esc_html_e('wp-cronを使用してバックグラウンドで送信します。UIをブロックしません。', 'eventbridge-post-events'); ?></p>
        </fieldset>
        <?php
    }

    /**
     * Render post types field
     */
    public function render_post_types_field()
    {
        $enabled_post_types = $this->get_setting('enabled_post_types');
        $available_post_types = $this->get_available_post_types();

        if (empty($available_post_types)) {
            echo '<p>' . esc_html__('利用可能な投稿タイプがありません。', 'eventbridge-post-events') . '</p>';
            return;
        }
        ?>
        <fieldset>
            <p class="description eventbridge-post-types-description">
                <?php esc_html_e('EventBridgeにイベントを送信する投稿タイプを選択してください。', 'eventbridge-post-events'); ?>
            </p>
            <?php foreach ($available_post_types as $post_type => $label) : ?>
                <label class="eventbridge-post-type-label">
                    <input type="checkbox"
                           name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[enabled_post_types][]"
                           value="<?php echo esc_attr($post_type); ?>"
                           <?php checked(in_array($post_type, $enabled_post_types, true)); ?>>
                    <?php echo esc_html($label); ?>
                    <code class="eventbridge-post-type-slug"><?php echo esc_html($post_type); ?></code>
                </label>
            <?php endforeach; ?>
            <p class="description eventbridge-post-types-note">
                <?php esc_html_e('※ 少なくとも1つの投稿タイプを選択してください。未選択の場合は「投稿」がデフォルトで選択されます。', 'eventbridge-post-events'); ?>
            </p>
        </fieldset>
        <?php
    }

    /**
     * Render debug logging field
     */
    public function render_debug_logging_field()
    {
        $enabled = $this->get_setting('enable_debug_logging');
        ?>
        <label>
            <input type="checkbox"
                   name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[enable_debug_logging]"
                   value="1"
                   <?php checked($enabled, true); ?>>
            <?php esc_html_e('Enable debug logging', 'eventbridge-post-events'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Logs plugin operations to a dedicated log file for debugging purposes. Logs are stored in wp-content/eventbridge-logs/eventbridge.log', 'eventbridge-post-events'); ?>
        </p>
        <?php
    }

    /**
     * Render log level field
     */
    public function render_log_level_field()
    {
        $current_level = $this->get_setting('debug_log_level');
        $enabled = $this->get_setting('enable_debug_logging');
        $disabled = !$enabled ? 'disabled' : '';
        ?>
        <select name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[debug_log_level]" <?php echo esc_attr($disabled); ?>>
            <option value="error" <?php selected($current_level, 'error'); ?>>
                <?php esc_html_e('Error - Only log errors', 'eventbridge-post-events'); ?>
            </option>
            <option value="info" <?php selected($current_level, 'info'); ?>>
                <?php esc_html_e('Info - Log errors and informational messages', 'eventbridge-post-events'); ?>
            </option>
            <option value="debug" <?php selected($current_level, 'debug'); ?>>
                <?php esc_html_e('Debug - Log everything including debug messages', 'eventbridge-post-events'); ?>
            </option>
        </select>
        <p class="description">
            <?php
            if (!$enabled) {
                esc_html_e('Enable debug logging to configure the log level.', 'eventbridge-post-events');
            } else {
                esc_html_e('Select the minimum level of messages to log. Debug includes all messages, Info excludes debug messages, Error only logs errors.', 'eventbridge-post-events');
            }
            ?>
        </p>
        <?php
    }

    /**
     * Get the path to the log file
     *
     * @return string Full path to the log file
     */
    private function get_log_file_path()
    {
        $upload_dir = wp_upload_dir();
        $log_dir = dirname($upload_dir['basedir']) . '/' . self::LOG_DIR_NAME;
        return $log_dir . '/eventbridge.log';
    }

    /**
     * Ensure the log directory exists and is protected
     *
     * @return bool True if directory exists or was created successfully
     */
    private function ensure_log_directory()
    {
        $upload_dir = wp_upload_dir();
        $log_dir = dirname($upload_dir['basedir']) . '/' . self::LOG_DIR_NAME;

        // Create directory if it doesn't exist
        if (!file_exists($log_dir)) {
            if (!wp_mkdir_p($log_dir)) {
                return false;
            }
        }

        // Create .htaccess file with modern Apache directives and legacy fallback
        $htaccess_file = $log_dir . '/.htaccess';
        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Deny all access to this directory\n";
            $htaccess_content .= "<IfModule mod_authz_core.c>\n";
            $htaccess_content .= "    Require all denied\n";
            $htaccess_content .= "</IfModule>\n";
            $htaccess_content .= "<IfModule !mod_authz_core.c>\n";
            $htaccess_content .= "    Deny from all\n";
            $htaccess_content .= "</IfModule>\n";

            // Write atomically using temp file + rename
            $temp_file = $htaccess_file . '.tmp';
            if (file_put_contents($temp_file, $htaccess_content) !== false) {
                rename($temp_file, $htaccess_file);
            }
        }

        // Create web.config for IIS with deny-all rule
        $webconfig_file = $log_dir . '/web.config';
        if (!file_exists($webconfig_file)) {
            $webconfig_content = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            $webconfig_content .= "<configuration>\n";
            $webconfig_content .= "  <system.webServer>\n";
            $webconfig_content .= "    <security>\n";
            $webconfig_content .= "      <authorization>\n";
            $webconfig_content .= "        <remove users=\"*\" roles=\"\" verbs=\"\" />\n";
            $webconfig_content .= "        <add accessType=\"Deny\" users=\"*\" />\n";
            $webconfig_content .= "      </authorization>\n";
            $webconfig_content .= "    </security>\n";
            $webconfig_content .= "  </system.webServer>\n";
            $webconfig_content .= "</configuration>\n";

            // Write atomically using temp file + rename
            $temp_file = $webconfig_file . '.tmp';
            if (file_put_contents($temp_file, $webconfig_content) !== false) {
                rename($temp_file, $webconfig_file);
            }
        }

        // Create index.php to prevent directory listing
        $index_file = $log_dir . '/index.php';
        if (!file_exists($index_file)) {
            $index_content = "<?php\n// Silence is golden.\n";

            // Write atomically using temp file + rename
            $temp_file = $index_file . '.tmp';
            if (file_put_contents($temp_file, $index_content) !== false) {
                rename($temp_file, $index_file);
            }
        }

        return true;
    }

    /**
     * Read the last N lines from a file efficiently without loading entire file into memory
     *
     * @param string $file_path Path to the file
     * @param int $num_lines Number of lines to read from the end
     * @return array|false Array of lines or false on failure
     */
    private function read_last_lines($file_path, $num_lines = 20)
    {
        if (!is_readable($file_path)) {
            return false;
        }

        // Try using tail command if available (most efficient)
        if (function_exists('shell_exec') && !ini_get('safe_mode')) {
            $tail_output = @shell_exec('tail -n ' . (int)$num_lines . ' ' . escapeshellarg($file_path) . ' 2>&1');
            if ($tail_output !== null && $tail_output !== '') {
                // Check if output looks like an error (contains "tail:" or similar)
                if (stripos($tail_output, 'tail:') === false && stripos($tail_output, 'command not found') === false) {
                    $lines = explode("\n", rtrim($tail_output, "\n"));
                    return $lines;
                }
            }
        }

        // Fallback: Use streaming approach with backwards reading
        $file = @fopen($file_path, 'r');
        if (!$file) {
            return false;
        }

        // Get file size
        fseek($file, 0, SEEK_END);
        $file_size = ftell($file);

        // If file is empty
        if ($file_size === 0) {
            fclose($file);
            return array();
        }

        // Read file in chunks from the end
        $lines = array();
        $chunk_size = 4096;
        $position = $file_size;
        $buffer = '';

        while (count($lines) < $num_lines && $position > 0) {
            // Calculate chunk to read
            $read_size = min($chunk_size, $position);
            $position -= $read_size;

            // Read chunk
            fseek($file, $position, SEEK_SET);
            $chunk = fread($file, $read_size);

            // Prepend to buffer
            $buffer = $chunk . $buffer;

            // Extract complete lines
            $buffer_lines = explode("\n", $buffer);

            // Keep the incomplete first line in buffer
            if ($position > 0) {
                $buffer = array_shift($buffer_lines);
            } else {
                $buffer = '';
            }

            // Add lines to result (in reverse since we're reading backwards)
            while (count($buffer_lines) > 0 && count($lines) < $num_lines) {
                $line = array_pop($buffer_lines);
                if ($line !== '') {
                    array_unshift($lines, $line);
                }
            }
        }

        fclose($file);
        return $lines;
    }

    /**
     * Check if a message at the given level should be logged
     *
     * @param string $message_level The level of the message (error, info, debug)
     * @return bool True if the message should be logged
     */
    private function should_log($message_level)
    {
        if (!$this->get_setting('enable_debug_logging')) {
            return false;
        }

        $configured_level = $this->get_setting('debug_log_level');

        // Define level hierarchy (lower number = higher priority)
        $level_priority = array(
            'error' => 1,
            'info' => 2,
            'debug' => 3,
        );

        $message_priority = isset($level_priority[$message_level]) ? $level_priority[$message_level] : 999;
        $configured_priority = isset($level_priority[$configured_level]) ? $level_priority[$configured_level] : 1;

        // Log if configured level priority >= message level priority
        return $configured_priority >= $message_priority;
    }

    /**
     * Write a log entry to the log file
     *
     * @param string $level Log level (error, info, debug)
     * @param string $message Log message
     * @param array $context Optional context data
     */
    private function write_log($level, $message, $context = array())
    {
        if (!$this->should_log($level)) {
            return;
        }

        if (!$this->ensure_log_directory()) {
            return;
        }

        $log_file = $this->get_log_file_path();
        $timestamp = current_time('Y-m-d H:i:s');
        $level_upper = strtoupper($level);

        // Format context data
        $context_str = '';
        if (!empty($context)) {
            $context_parts = array();
            foreach ($context as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $value = json_encode($value);
                }
                $context_parts[] = $key . '=' . $value;
            }
            $context_str = ' [' . implode(', ', $context_parts) . ']';
        }

        $log_entry = sprintf(
            "[%s] %s: %s%s\n",
            $timestamp,
            $level_upper,
            $message,
            $context_str
        );

        // Append to log file
        if (false === file_put_contents($log_file, $log_entry, FILE_APPEND)) {
            error_log('EventBridge: Failed to write to log file: ' . $log_file);
        }
    }

    /**
     * Log an error message
     *
     * @param string $message Log message
     * @param array $context Optional context data
     */
    public function log_error($message, $context = array())
    {
        $this->write_log('error', $message, $context);
    }

    /**
     * Log an info message
     *
     * @param string $message Log message
     * @param array $context Optional context data
     */
    public function log_info($message, $context = array())
    {
        $this->write_log('info', $message, $context);
    }

    /**
     * Log a debug message
     *
     * @param string $message Log message
     * @param array $context Optional context data
     */
    public function log_debug($message, $context = array())
    {
        $this->write_log('debug', $message, $context);
    }

    /**
     * Display and delete transient messages
     * Reduces duplication for displaying settings errors stored in transients
     *
     * @param string $transient_name The transient name to check and display
     */
    private function display_transient_messages($transient_name)
    {
        $messages = get_transient($transient_name);
        if ($messages) {
            foreach ($messages as $message) {
                printf(
                    '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
                    esc_attr($message['type']),
                    esc_html($message['message'])
                );
            }
            delete_transient($transient_name);
        }
    }

    /**
     * Render settings page
     */
    public function render_settings_page()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php
            // Display settings errors/success messages
            settings_errors('eventbridge_test');
            settings_errors('eventbridge_metrics');

            // Display transient messages
            $this->display_transient_messages('eventbridge_test_result');
            $this->display_transient_messages('eventbridge_metrics_result');

            // Display current metrics
            $metrics = get_option(self::OPTION_METRICS, array(
                'successful_events' => 0,
                'failed_events' => 0,
                'transient_failures' => 0,
                'permanent_failures' => 0
            ));
            $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array('last_failure_time' => null, 'messages' => array()));

            // Use effective region (respects aws_region_override setting)
            $effective_region = $this->get_effective_region();
            ?>

            <!-- Diagnostics & Status Section -->
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('Diagnostics & Status', 'eventbridge-post-events'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('Detected Region', 'eventbridge-post-events'); ?></th>
                        <td><code><?php echo esc_html($effective_region ?: __('Not detected', 'eventbridge-post-events')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Credential Source', 'eventbridge-post-events'); ?></th>
                        <td><code><?php echo esc_html($this->credential_source ?: __('Unknown', 'eventbridge-post-events')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Event Bus Name', 'eventbridge-post-events'); ?></th>
                        <td>
                            <code><?php echo esc_html($this->get_setting('event_bus_name')); ?></code>
                            <?php if (defined('EVENT_BUS_NAME')): ?>
                                <span style="color:#d63638;"> (<?php esc_html_e('constant override', 'eventbridge-post-events'); ?>)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Event Source Name', 'eventbridge-post-events'); ?></th>
                        <td>
                            <code><?php echo esc_html($this->get_setting('event_source_name')); ?></code>
                            <?php if (defined('EVENT_SOURCE_NAME')): ?>
                                <span style="color:#d63638;"> (<?php esc_html_e('constant override', 'eventbridge-post-events'); ?>)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Metrics', 'eventbridge-post-events'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('Successful Events', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:green;"><?php echo esc_html($metrics['successful_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Failed Events', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:<?php echo $metrics['failed_events'] > 0 ? 'red' : 'inherit'; ?>;"><?php echo esc_html($metrics['failed_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th style="padding-left:20px;"><?php esc_html_e('└ 一時的な失敗', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:orange;"><?php echo esc_html(isset($metrics['transient_failures']) ? $metrics['transient_failures'] : 0); ?></strong> <span class="description">(リトライ可能)</span></td>
                    </tr>
                    <tr>
                        <th style="padding-left:20px;"><?php esc_html_e('└ 恒久的な失敗', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:red;"><?php echo esc_html(isset($metrics['permanent_failures']) ? $metrics['permanent_failures'] : 0); ?></strong> <span class="description">(設定要確認)</span></td>
                    </tr>
                    <?php if (!empty($failure_details['last_failure_time'])): ?>
                    <tr>
                        <th><?php esc_html_e('Last Failure', 'eventbridge-post-events'); ?></th>
                        <td>
                            <?php echo esc_html($failure_details['last_failure_time']); ?>
                            <?php if (!empty($failure_details['messages'])):
                                $last_index = count($failure_details['messages']) - 1;
                                $last_message = isset($failure_details['messages'][$last_index]['message']) ? $failure_details['messages'][$last_index]['message'] : '';
                            ?>
                                <br><span class="description" style="color:#d63638;"><?php echo esc_html($last_message); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endif; ?>
                </table>

                <div>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                        <?php wp_nonce_field('eventbridge_test_connection', 'eventbridge_test_nonce'); ?>
                        <input type="hidden" name="action" value="eventbridge_test_connection">
                        <?php submit_button(__('Test Connection', 'eventbridge-post-events'), 'secondary', 'test_connection', false); ?>
                    </form>

                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;margin-left:10px;">
                        <?php wp_nonce_field('eventbridge_reset_metrics', 'eventbridge_reset_nonce'); ?>
                        <input type="hidden" name="action" value="eventbridge_reset_metrics">
                        <?php submit_button(__('Reset Metrics', 'eventbridge-post-events'), 'secondary', 'reset_metrics', false); ?>
                    </form>
                </div>
            </div>

            <?php if ($this->get_setting('enable_debug_logging')): ?>
            <!-- Debug Logging Section -->
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('Debug Logs', 'eventbridge-post-events'); ?></h2>
                <p>
                    <strong><?php esc_html_e('Log File Path:', 'eventbridge-post-events'); ?></strong>
                    <code><?php echo esc_html($this->get_log_file_path()); ?></code>
                </p>

                <h3><?php esc_html_e('Recent Log Entries (Last 20 lines)', 'eventbridge-post-events'); ?></h3>
                <?php
                $log_file = $this->get_log_file_path();
                if (file_exists($log_file) && is_readable($log_file)) {
                    $recent_lines = $this->read_last_lines($log_file, 20);
                    if ($recent_lines !== false && count($recent_lines) > 0) {
                        echo '<pre style="background:#f5f5f5;padding:10px;overflow-x:auto;max-height:400px;overflow-y:auto;font-size:12px;border:1px solid #ddd;">';
                        foreach ($recent_lines as $line) {
                            echo esc_html($line) . "\n";
                        }
                        echo '</pre>';
                    } else {
                        echo '<p>' . esc_html__('Log file is empty.', 'eventbridge-post-events') . '</p>';
                    }
                } else {
                    echo '<p>' . esc_html__('Log file does not exist or is not readable.', 'eventbridge-post-events') . '</p>';
                }
                ?>

                <div style="margin-top:15px;">
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                        <?php wp_nonce_field('eventbridge_clear_logs', 'eventbridge_clear_logs_nonce'); ?>
                        <input type="hidden" name="action" value="eventbridge_clear_logs">
                        <?php submit_button(__('Clear Logs', 'eventbridge-post-events'), 'secondary', 'clear_logs', false); ?>
                    </form>
                </div>
            </div>
            <?php endif; ?>

            <form action="options.php" method="post">
                <?php
                settings_fields('eventbridge_settings_group');
                do_settings_sections('eventbridge-settings');
                submit_button(__('Save Settings', 'eventbridge-post-events'));
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * Load metrics from WordPress options table
     */
    private function load_metrics()
    {
        $metrics = get_option(self::OPTION_METRICS, array(
            'successful_events' => 0,
            'failed_events' => 0,
            'transient_failures' => 0,
            'permanent_failures' => 0
        ));

        $this->successful_events = (int) $metrics['successful_events'];
        $this->failed_events = (int) $metrics['failed_events'];
        $this->transient_failures = (int) (isset($metrics['transient_failures']) ? $metrics['transient_failures'] : 0);
        $this->permanent_failures = (int) (isset($metrics['permanent_failures']) ? $metrics['permanent_failures'] : 0);
    }

    /**
     * Save metrics to WordPress options table
     * Uses single serialized option with autoload=false for performance
     */
    private function save_metrics()
    {
        $metrics = array(
            'successful_events' => $this->successful_events,
            'failed_events' => $this->failed_events,
            'transient_failures' => $this->transient_failures,
            'permanent_failures' => $this->permanent_failures
        );
        update_option(self::OPTION_METRICS, $metrics, false);
    }

    /**
     * Record a successful event
     */
    private function record_success()
    {
        $this->successful_events++;
        $this->save_metrics();
    }

    /**
     * Record a failed event
     * Consolidates DB writes to reduce I/O and race conditions
     *
     * @param string $error_message The error message
     * @param bool $is_transient Whether the failure is transient (retryable) or permanent
     */
    private function record_failure($error_message, $is_transient = false)
    {
        // Increment in-memory counters
        $this->failed_events++;
        if ($is_transient) {
            $this->transient_failures++;
        } else {
            $this->permanent_failures++;
        }

        // Read, mutate, and write failure details in one operation
        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array(
            'last_failure_time' => null,
            'messages' => array()
        ));

        $failure_details['last_failure_time'] = current_time('mysql');
        $failure_details['messages'][] = array(
            'time' => current_time('mysql'),
            'message' => $error_message,
            'type' => $is_transient ? 'transient' : 'permanent'
        );

        // Keep only the last 10 failure messages
        if (count($failure_details['messages']) > 10) {
            $failure_details['messages'] = array_slice($failure_details['messages'], -10);
        }

        // Two DB writes total: one for metrics, one for failure details
        update_option(self::OPTION_FAILURE_DETAILS, $failure_details, false);
        $this->save_metrics();
    }

    /**
     * Track event result and update metrics
     * Consolidates duplicated logic from send_post_event and send_delete_post_event
     *
     * @param array $result The result array from sendEvent()
     */
    private function track_event_result($result)
    {
        if ($result['success']) {
            $this->record_success();
        } else {
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $is_transient = isset($result['is_transient']) ? $result['is_transient'] : false;
            $this->record_failure($error_message, $is_transient);
        }
    }

    /**
     * Retrieve IMDSv2 token with persistent transient caching
     * Token has 6-hour TTL, cached for 5h50m to ensure fresh token
     *
     * @return string|null IMDSv2 token or null on failure
     */
    private function get_imdsv2_token()
    {
        // Check transient cache first (persists across requests)
        $cached_token = get_transient(self::TRANSIENT_IMDS_TOKEN);
        if ($cached_token !== false && !empty($cached_token)) {
            return $cached_token;
        }

        // Request new token with 6-hour TTL (21600 seconds)
        $response = wp_remote_request(self::IMDS_BASE_URL . '/latest/api/token', array(
            'method' => 'PUT',
            'headers' => array(
                'X-aws-ec2-metadata-token-ttl-seconds' => '21600'
            ),
            'timeout' => self::IMDS_TIMEOUT
        ));

        if (is_wp_error($response)) {
            error_log(sprintf(
                '[EventBridge] IMDSv2 token retrieval failed: %s',
                $response->get_error_message()
            ));
            return null;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log(sprintf(
                '[EventBridge] IMDSv2 token retrieval returned HTTP %d',
                $status_code
            ));
            return null;
        }

        $token = wp_remote_retrieve_body($response);
        if (empty($token)) {
            error_log('[EventBridge] IMDSv2 token is empty');
            return null;
        }

        // Cache token in transient for 5h50m (safe margin before 6h expiry)
        set_transient(self::TRANSIENT_IMDS_TOKEN, $token, self::IMDS_TOKEN_CACHE_DURATION);

        return $token;
    }

    /**
     * Get EC2 instance identity from metadata (IMDSv2 with transient caching)
     *
     * Uses persistent caching to avoid repeated timeouts on non-EC2 hosts.
     * Caches both successful results (1 hour) and failures (5 minutes).
     * Returns empty array on non-EC2 environments.
     *
     * @return array インスタンス識別情報
     */
    private function get_instance_identity()
    {
        // Check success cache first (persists across requests)
        $cached = get_transient(self::TRANSIENT_IMDS_IDENTITY);
        if ($cached !== false) {
            return $cached;
        }

        // Check failure cache to avoid repeated timeouts (short-circuit for non-EC2)
        if (get_transient(self::TRANSIENT_IMDS_FAILED) !== false) {
            return array();
        }

        // Try to get IMDSv2 token
        $token = $this->get_imdsv2_token();
        if ($token === null) {
            // Cache failure for 5 minutes to prevent repeated timeout attempts
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        // Request instance identity document with IMDSv2 token
        $response = wp_remote_get(self::IMDS_BASE_URL . '/latest/dynamic/instance-identity/document', array(
            'headers' => array(
                'X-aws-ec2-metadata-token' => $token
            ),
            'timeout' => self::IMDS_TIMEOUT
        ));

        if (is_wp_error($response)) {
            error_log(sprintf(
                '[EventBridge] Instance identity retrieval failed: %s',
                $response->get_error_message()
            ));
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log(sprintf(
                '[EventBridge] Instance identity returned HTTP %d',
                $status_code
            ));
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $identity = json_decode($body, true);

        // Validate that identity is a valid array and region is not null/empty
        if (!is_array($identity) || json_last_error() !== JSON_ERROR_NONE) {
            error_log('[EventBridge] Instance identity document has invalid JSON');
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        // Cache successful result for 1 hour
        set_transient(self::TRANSIENT_IMDS_IDENTITY, $identity, self::IMDS_IDENTITY_CACHE_DURATION);
        return $identity;
    }

    /**
     * EC2インスタンスロールから一時的な認証情報を取得する (IMDSv2 with smart caching)
     *
     * Retrieves temporary credentials with expiration-aware caching.
     * Only attempts IMDS in admin or wp-cron contexts to avoid frontend performance impact.
     *
     * @return array|null Array with AccessKeyId, SecretAccessKey, Token, Expiration or null on failure
     */
    private function get_instance_credentials()
    {
        // Only try instance credentials in admin or wp-cron contexts
        $should_try_imds = is_admin() || (defined('DOING_CRON') && DOING_CRON);
        if (!$should_try_imds) {
            return null;
        }

        // Check cached credentials
        $cached = get_transient(self::TRANSIENT_IMDS_CREDENTIALS);
        if ($cached !== false) {
            // Check if expiration is approaching (within 5 minutes)
            if (isset($cached['Expiration'])) {
                $expiration = strtotime($cached['Expiration']);
                $now = time();
                // Use cached credentials if more than 5 minutes until expiry
                if ($expiration - $now > 300) {
                    return $cached;
                }
                // Credentials expire soon, delete cache and refresh
                delete_transient(self::TRANSIENT_IMDS_CREDENTIALS);
            } else {
                return $cached;
            }
        }

        // Check failure cache
        if (get_transient(self::TRANSIENT_IMDS_FAILED) !== false) {
            return null;
        }

        // Get IMDSv2 token
        $token = $this->get_imdsv2_token();
        if ($token === null) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        // Get IAM role name
        $role_response = wp_remote_get(self::IMDS_BASE_URL . '/latest/meta-data/iam/security-credentials/', array(
            'headers' => array('X-aws-ec2-metadata-token' => $token),
            'timeout' => self::IMDS_TIMEOUT,
        ));

        if (is_wp_error($role_response) || wp_remote_retrieve_response_code($role_response) !== 200) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        $role_name = trim(wp_remote_retrieve_body($role_response));
        if (empty($role_name)) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        // Get credentials for the role
        $creds_response = wp_remote_get(self::IMDS_BASE_URL . '/latest/meta-data/iam/security-credentials/' . $role_name, array(
            'headers' => array('X-aws-ec2-metadata-token' => $token),
            'timeout' => self::IMDS_TIMEOUT,
        ));

        if (is_wp_error($creds_response) || wp_remote_retrieve_response_code($creds_response) !== 200) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        $creds = json_decode(wp_remote_retrieve_body($creds_response), true);

        // Validate credentials
        if (json_last_error() !== JSON_ERROR_NONE ||
            empty($creds['AccessKeyId']) ||
            empty($creds['SecretAccessKey']) ||
            !isset($creds['Token'])) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        $credentials = array(
            'AccessKeyId' => $creds['AccessKeyId'],
            'SecretAccessKey' => $creds['SecretAccessKey'],
            'Token' => $creds['Token'],
            'Expiration' => isset($creds['Expiration']) ? $creds['Expiration'] : null,
        );

        // Calculate cache duration based on expiration (5 min safety margin)
        $cache_duration = self::IMDS_IDENTITY_CACHE_DURATION;
        if (isset($creds['Expiration'])) {
            $expiration = strtotime($creds['Expiration']);
            $now = time();
            $time_until_expiry = $expiration - $now - 300; // 5 min margin
            if ($time_until_expiry > 0) {
                $cache_duration = min($cache_duration, $time_until_expiry);
            }
        }

        set_transient(self::TRANSIENT_IMDS_CREDENTIALS, $credentials, $cache_duration);
        return $credentials;
    }

    /**
     * イベントエンベロープを作成する
     *
     * @param array $data イベントデータ
     * @param string $correlation_id コリレーションID
     * @return array イベントエンベロープ
     */
    private function create_event_envelope($data, $correlation_id)
    {
        return array(
            'event_id' => wp_generate_uuid4(),
            'event_timestamp' => current_time('c'), // ISO 8601 format
            'event_version' => '1.0',
            'source_system' => get_bloginfo('url'),
            'correlation_id' => $correlation_id,
            'data' => $data
        );
    }

    /**
     * コリレーションIDを取得または生成する
     *
     * @param int $post_id 投稿ID
     * @return string コリレーションID
     */
    private function get_or_create_correlation_id($post_id)
    {
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        if (empty($correlation_id)) {
            // Try wp_generate_uuid4() first (WordPress 4.7+)
            if (function_exists('wp_generate_uuid4')) {
                $correlation_id = wp_generate_uuid4();
            } else {
                // Fallback: generate UUID v4 manually
                $correlation_id = $this->generate_uuid_v4();
            }

            $added = add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

            // If add_post_meta returned false, another request wrote the meta first
            // Re-read the actual value that was stored
            if ($added === false) {
                $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

                // Final fallback if correlation_id is still empty
                if (empty($correlation_id)) {
                    // This can happen in a race condition where another process adds an empty meta value.
                    // We'll generate a new UUID and attempt to save it.
                    $correlation_id = $this->generate_uuid_v4();
                    update_post_meta($post_id, '_event_correlation_id', $correlation_id);
                    error_log(sprintf(
                        '[EventBridge] Corrected empty correlation ID. Using fallback UUID for post ID %d: %s',
                        $post_id,
                        $correlation_id
                    ));
                }
            }
        }

        return $correlation_id;
    }

    /**
     * Generate UUID v4 as fallback when wp_generate_uuid4() is not available
     *
     * @return string UUID v4
     */
    private function generate_uuid_v4()
    {
        $data = random_bytes(16);

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Prepare event payload based on format setting
     *
     * @param array $event_data イベントデータ
     * @param int $post_id 投稿ID
     * @param bool $is_delete_event Whether this is a delete event (avoids unnecessary meta writes)
     * @return array イベントペイロード
     */
    private function prepare_event_payload($event_data, $post_id, $is_delete_event = false)
    {
        // Always use envelope format
        $correlation_id = $is_delete_event
            ? $this->get_existing_correlation_id($post_id)
            : $this->get_or_create_correlation_id($post_id);
        return $this->create_event_envelope($event_data, $correlation_id);
    }

    /**
     * Get existing correlation ID without creating a new one
     * Used for delete events to avoid unnecessary DB writes
     *
     * @param int $post_id 投稿ID
     * @return string コリレーションID (existing or newly generated without saving)
     */
    private function get_existing_correlation_id($post_id)
    {
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        // If no existing correlation ID, generate one but don't save it
        // (the post is being deleted anyway)
        if (empty($correlation_id)) {
            $correlation_id = wp_generate_uuid4();
        }

        return $correlation_id;
    }

    /**
     * 投稿のイベントをEventBridgeに送信する
     *
     * @param string $new_status 新しい投稿ステータス
     * @param string $old_status 前の投稿ステータス
     * @param WP_Post $post 投稿オブジェクト
     */
    public function send_post_event($new_status, $old_status, $post)
    {
        // Validate post object
        if (!($post instanceof WP_Post) || empty($post->ID)) {
            error_log('[EventBridge] Invalid post object provided to send_post_event');
            return;
        }

        // Check if this post type is enabled for EventBridge
        if (!$this->is_post_type_enabled($post->post_type)) {
            return;
        }

        // Only handle publish and future status transitions
        if ($new_status !== 'publish' && $new_status !== 'future') {
            return;
        }

        // Determine event type based on status transition
        if ($new_status === 'future') {
            // Scheduled post
            $event_name = 'post.scheduled';
        } elseif ($old_status === 'publish') {
            // Update to already published post (publish -> publish)
            $event_name = 'post.updated';
        } else {
            // New publish (from draft, future, etc.)
            $event_name = 'post.published';
        }

        // Safely get post properties with null checks
        $permalink = get_permalink($post->ID);
        $post_type = !empty($post->post_type) ? $post->post_type : 'post';
        $post_title = !empty($post->post_title) ? $post->post_title : '';
        $post_excerpt = !empty($post->post_excerpt) ? $post->post_excerpt : '';

        // Get REST API URL using rest_base from post type object
        $post_type_obj = get_post_type_object($post_type);
        $rest_base = (!empty($post_type_obj) && !empty($post_type_obj->rest_base)) ? $post_type_obj->rest_base : $post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $rest_base . '/' . $post->ID);

        $event_data = array(
            'id' => (string)$post->ID,
            'title' => $post_title,
            'excerpt' => $post_excerpt,
            'status' => $new_status,
            'previous_status' => $old_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type
        );

        $event_payload = $this->prepare_event_payload($event_data, $post->ID);

        // Early fast-fail: check if event payload can be JSON encoded
        // Note: The authoritative size check happens in sendEvent() after building the full envelope
        $payload_json = json_encode($event_payload);
        if ($payload_json === false) {
            error_log(sprintf(
                '[EventBridge] Failed to JSON encode event payload for post ID %d: %s',
                $post->ID,
                json_last_error_msg()
            ));
            return;
        }

        // Log event dispatch
        $this->log_info('Post event prepared for dispatch', array(
            'post_id' => $post->ID,
            'event_type' => $event_name,
            'post_type' => $post_type,
            'status_transition' => $old_status . ' -> ' . $new_status
        ));

        $this->dispatch_event($this->get_setting('event_source_name'), $event_name, $event_payload);
    }

    /**
     * 投稿削除のイベントをEventBridgeに送信する
     *
     * @param int $post_id 投稿ID
     */
    public function send_delete_post_event($post_id)
    {
        // Get post to check its type
        $post = get_post($post_id);
        if (!$post) {
            return;
        }

        // Check if this post type is enabled for EventBridge
        if (!$this->is_post_type_enabled($post->post_type)) {
            return;
        }

        $event_name = 'post.deleted';

        $event_data = array(
            'id' => (string)$post_id,
            'post_type' => $post->post_type
        );

        $event_payload = $this->prepare_event_payload($event_data, $post_id, true);

        // Log delete event
        $this->log_info('Delete event prepared for dispatch', array(
            'post_id' => $post_id,
            'event_type' => $event_name,
            'post_type' => $post->post_type
        ));

        $this->dispatch_event($this->get_setting('event_source_name'), $event_name, $event_payload);
    }

    /**
     * Check if a post type is enabled for EventBridge events
     *
     * @param string $post_type Post type to check
     * @return bool True if enabled, false otherwise
     */
    private function is_post_type_enabled($post_type)
    {
        $enabled_post_types = $this->get_setting('enabled_post_types');
        return in_array($post_type, $enabled_post_types, true);
    }

    /**
     * Dispatch event based on send mode setting
     *
     * @param string $source イベントソース
     * @param string $event_name イベント名
     * @param array $event_payload イベントペイロード
     */
    private function dispatch_event($source, $event_name, $event_payload)
    {
        $send_mode = $this->get_setting('send_mode');

        // Log dispatch mode
        $this->log_debug('Dispatching event', array(
            'event_name' => $event_name,
            'send_mode' => $send_mode
        ));

        if ($send_mode === 'sync') {
            // 同期送信 - 即座にEventBridgeへ送信
            $this->do_send_event($source, $event_name, $event_payload);
        } else {
            // 非同期送信 - wp-cronでバックグラウンド処理
            wp_schedule_single_event(time(), 'eventbridge_async_send_event', array($source, $event_name, $event_payload));
        }
    }

    /**
     * Execute the actual event sending and handle result tracking
     *
     * @param string $source イベントソース
     * @param string $detailType イベント詳細タイプ
     * @param array $detail イベント詳細データ
     * @return array 送信結果（success, error, response）
     */
    private function do_send_event($source, $detailType, $detail)
    {
        // Log before API call
        $this->log_debug('Sending event to EventBridge API', array(
            'source' => $source,
            'detail_type' => $detailType
        ));

        $result = $this->get_client()->sendEvent($source, $detailType, $detail);
        $this->track_event_result($result);

        if ($result['success']) {
            // Log successful send
            $this->log_info('Event sent successfully to EventBridge', array(
                'detail_type' => $detailType
            ));
        } else {
            // Log failure with details
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $is_transient = isset($result['is_transient']) ? $result['is_transient'] : false;
            $http_code = isset($result['response']['http_code']) ? $result['response']['http_code'] : 'N/A';

            $this->log_error('EventBridge API call failed', array(
                'detail_type' => $detailType,
                'error' => $error_message,
                'http_code' => $http_code,
                'is_transient' => $is_transient ? 'yes' : 'no'
            ));

            do_action('eventbridge_send_failed', $source, $detailType, $detail);
        }

        return $result;
    }

    /**
     * 非同期でEventBridgeにイベントを送信する（バックグラウンド処理）
     *
     * @param string $source イベントソース
     * @param string $detailType イベント詳細タイプ
     * @param array $detail イベント詳細データ
     * @return array 送信結果（success, error, response）
     */
    public function async_send_event($source, $detailType, $detail)
    {
        return $this->do_send_event($source, $detailType, $detail);
    }

    /**
     * EventBridge送信失敗時のハンドラー
     *
     * @param string $source イベントソース
     * @param string $detailType イベント詳細タイプ
     * @param array $detail イベント詳細データ
     */
    public function handle_send_failure($source, $detailType, $detail)
    {
        // Extract post ID from detail (handle both legacy and envelope formats)
        $postId = $detail['id'] ?? ($detail['data']['id'] ?? null);
        if ($postId) {
            // 失敗イベントをログに記録（監視・アラート用）
            error_log(sprintf(
                '[EventBridge] Failed to send event after all retries: DetailType=%s, PostID=%s, Source=%s',
                $detailType,
                $postId,
                $source
            ));
        }
    }

    /**
     * 失敗イベントをEventBridgeに送信する（非同期スケジュール）
     *
     * @param string $event_name 失敗したイベント名
     * @param int $post_id 投稿ID
     */
    private function send_failure_event($event_name, $post_id)
    {
        $event_name = 'failure.' . $event_name;
        $event_data = array(
            'id' => (string)$post_id,
            'failed_event' => $event_name
        );

        // 非同期でEventBridgeに送信（UIをブロックしない）
        wp_schedule_single_event(time(), 'eventbridge_async_send_event', array($this->get_setting('event_source_name'), $event_name, $event_data));
    }

    /**
     * Display admin notice for credential source and region fallback
     */
    public function display_config_notice()
    {
        // Only show to administrators
        if (!current_user_can('manage_options')) {
            return;
        }

        // Only show on admin pages
        if (!is_admin()) {
            return;
        }

        $messages = array();

        // Notice for environment variable credentials
        if ($this->credential_source === 'environment') {
            $messages[] = sprintf(
                '<strong>%s</strong> %s',
                esc_html__('認証情報ソース:', 'eventbridge-post-events'),
                esc_html__('環境変数 (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)', 'eventbridge-post-events')
            );
        }

        // Notice for region fallback
        if ($this->region_source === 'fallback') {
            $messages[] = sprintf(
                '<strong>%s</strong> %s',
                esc_html__('リージョン検出警告:', 'eventbridge-post-events'),
                sprintf(
                    esc_html__('EVENT_BRIDGE_REGION定数とEC2メタデータからリージョンを検出できませんでした。デフォルトの「%s」を使用します。', 'eventbridge-post-events'),
                    esc_html($this->region)
                )
            );
        }

        if (!empty($messages)) {
            ?>
            <div class="notice notice-info">
                <p><strong><?php esc_html_e('EventBridge Post Events 設定情報', 'eventbridge-post-events'); ?></strong></p>
                <ul style="list-style: disc; margin-left: 20px;">
                    <?php foreach ($messages as $message): ?>
                        <li><?php echo wp_kses_post($message); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php
        }
    }

    /**
     * Display admin notice when failure count exceeds threshold
     */
    public function display_failure_notice()
    {
        // Only show to administrators
        if (!current_user_can('manage_options')) {
            return;
        }

        // Check if notice was dismissed
        if (get_transient(self::TRANSIENT_NOTICE_DISMISSED)) {
            return;
        }

        // Check if failure count exceeds threshold
        $failure_count = $this->failed_events;
        if ($failure_count < self::FAILURE_THRESHOLD) {
            return;
        }

        // Get failure details from consolidated option
        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array(
            'last_failure_time' => 'Unknown',
            'messages' => array()
        ));

        $last_failure_time = $failure_details['last_failure_time'] ?: 'Unknown';
        $failure_messages = $failure_details['messages'];
        $success_count = $this->successful_events;

        // Get most recent error message using array indexing (safer than end())
        $recent_error = 'Unknown error';
        if (!empty($failure_messages)) {
            $last_index = count($failure_messages) - 1;
            $recent_error = isset($failure_messages[$last_index]['message'])
                ? $failure_messages[$last_index]['message']
                : 'Unknown error';
        }

        // Create dismiss URL
        $dismiss_url = add_query_arg(array(
            'eventbridge_dismiss_notice' => '1',
            'eventbridge_nonce' => wp_create_nonce('eventbridge_dismiss_notice')
        ));

        // Display the notice
        ?>
        <div class="notice notice-error is-dismissible">
            <h3><?php esc_html_e('EventBridge Publishing Failures Detected', 'eventbridge-post-events'); ?></h3>
            <p><strong><?php esc_html_e('Action Required:', 'eventbridge-post-events'); ?></strong> <?php esc_html_e('EventBridge event publishing is experiencing failures.', 'eventbridge-post-events'); ?></p>
            <ul>
                <li><strong><?php esc_html_e('Failed Events:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($failure_count); ?></li>
                <li><strong><?php esc_html_e('Successful Events:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($success_count); ?></li>
                <li><strong><?php esc_html_e('Last Failure:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($last_failure_time); ?></li>
                <li><strong><?php esc_html_e('Recent Error:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($recent_error); ?></li>
            </ul>
            <p>
                <strong><?php esc_html_e('Recommended Actions:', 'eventbridge-post-events'); ?></strong>
            </p>
            <ol>
                <li><?php esc_html_e('Check your AWS EventBridge credentials (AWS_EVENTBRIDGE_ACCESS_KEY_ID and AWS_EVENTBRIDGE_SECRET_ACCESS_KEY)', 'eventbridge-post-events'); ?></li>
                <li><?php printf(esc_html__('Verify EventBridge event bus "%s" exists in region "%s"', 'eventbridge-post-events'), esc_html($this->get_setting('event_bus_name')), esc_html($this->region)); ?></li>
                <li>
                    <?php
                    // Check for known error log plugins before displaying link
                    if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
                        $log_path = defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
                        printf(
                            esc_html__('Check error logs at %s or enable WP_DEBUG_LOG in wp-config.php', 'eventbridge-post-events'),
                            '<code>' . esc_html($log_path) . '</code>'
                        );
                    } else {
                        esc_html_e('Enable WP_DEBUG_LOG in wp-config.php and check wp-content/debug.log for error details', 'eventbridge-post-events');
                    }
                    ?>
                </li>
                <li><?php esc_html_e('Ensure IAM permissions include "events:PutEvents" for the event bus', 'eventbridge-post-events'); ?></li>
            </ol>
            <p>
                <a href="<?php echo esc_url($dismiss_url); ?>" class="button button-primary"><?php esc_html_e('Dismiss for 24 hours', 'eventbridge-post-events'); ?></a>
            </p>
        </div>
        <?php
    }

    /**
     * Handle admin notice dismissal
     */
    public function handle_notice_dismissal()
    {
        // Check if dismiss action was triggered
        if (!isset($_GET['eventbridge_dismiss_notice'])) {
            return;
        }

        // Sanitize and unslash nonce before verification
        if (!isset($_GET['eventbridge_nonce'])) {
            return;
        }

        $nonce = sanitize_text_field(wp_unslash($_GET['eventbridge_nonce']));
        if (!wp_verify_nonce($nonce, 'eventbridge_dismiss_notice')) {
            return;
        }

        // Only allow administrators
        if (!current_user_can('manage_options')) {
            return;
        }

        // Set transient to dismiss notice for 24 hours
        set_transient(self::TRANSIENT_NOTICE_DISMISSED, true, 24 * HOUR_IN_SECONDS);

        // Reset failure counter to prevent alert fatigue
        $this->failed_events = 0;
        $this->save_metrics();

        // Safely redirect to remove query parameters
        wp_safe_redirect(remove_query_arg(array('eventbridge_dismiss_notice', 'eventbridge_nonce')));
        exit;
    }

    /**
     * Handle test connection request
     */
    public function handle_test_connection()
    {
        // Security checks
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to perform this action.', 'eventbridge-post-events'));
        }

        if (!isset($_POST['eventbridge_test_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['eventbridge_test_nonce'])), 'eventbridge_test_connection')) {
            wp_die(esc_html__('Security check failed.', 'eventbridge-post-events'));
        }

        // Check if credentials and region are available (constructor may have bailed early)
        if (empty($this->access_key) || empty($this->secret_key) || empty($this->region)) {
            add_settings_error(
                'eventbridge_test',
                'test_error_no_credentials',
                __('Cannot test connection: AWS credentials or region not configured. Please check your wp-config.php or EC2 instance role settings.', 'eventbridge-post-events'),
                'error'
            );
            set_transient('eventbridge_test_result', get_settings_errors('eventbridge_test'), 30);
            wp_safe_redirect(admin_url('options-general.php?page=eventbridge-settings'));
            exit;
        }

        // Send test event
        $test_event_data = array(
            'test' => true,
            'timestamp' => current_time('c'),
            'message' => 'EventBridge connection test'
        );

        // Always use envelope format for test event
        $test_event_payload = $this->create_event_envelope($test_event_data, wp_generate_uuid4());

        $result = $this->get_client()->sendEvent(
            $this->get_setting('event_source_name'),
            'connection.test',
            $test_event_payload
        );

        // Redirect with result
        $redirect_args = array();
        if ($result['success']) {
            $redirect_args['eventbridge_test'] = 'success';
            add_settings_error(
                'eventbridge_test',
                'test_success',
                __('Test event sent successfully! Check your EventBridge console to verify receipt.', 'eventbridge-post-events'),
                'success'
            );
        } else {
            $redirect_args['eventbridge_test'] = 'error';
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            add_settings_error(
                'eventbridge_test',
                'test_error',
                sprintf(__('Test event failed: %s', 'eventbridge-post-events'), $error_message),
                'error'
            );
        }

        set_transient('eventbridge_test_result', get_settings_errors('eventbridge_test'), 30);
        wp_safe_redirect(add_query_arg($redirect_args, admin_url('options-general.php?page=eventbridge-settings')));
        exit;
    }

    /**
     * Handle metrics reset request
     */
    public function handle_reset_metrics()
    {
        // Security checks
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to perform this action.', 'eventbridge-post-events'));
        }

        if (!isset($_POST['eventbridge_reset_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['eventbridge_reset_nonce'])), 'eventbridge_reset_metrics')) {
            wp_die(esc_html__('Security check failed.', 'eventbridge-post-events'));
        }

        // Reset metrics
        $this->successful_events = 0;
        $this->failed_events = 0;
        $this->transient_failures = 0;
        $this->permanent_failures = 0;
        $this->save_metrics();

        // Clear failure details
        delete_option(self::OPTION_FAILURE_DETAILS);

        // Redirect with success message
        add_settings_error(
            'eventbridge_metrics',
            'metrics_reset',
            __('Metrics have been reset successfully.', 'eventbridge-post-events'),
            'success'
        );

        set_transient('eventbridge_metrics_result', get_settings_errors('eventbridge_metrics'), 30);
        wp_safe_redirect(add_query_arg('eventbridge_metrics_reset', '1', admin_url('options-general.php?page=eventbridge-settings')));
        exit;
    }

    /**
     * Handle clear logs request
     */
    public function handle_clear_logs()
    {
        // Security checks
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to perform this action.', 'eventbridge-post-events'));
        }

        if (!isset($_POST['eventbridge_clear_logs_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['eventbridge_clear_logs_nonce'])), 'eventbridge_clear_logs')) {
            wp_die(esc_html__('Security check failed.', 'eventbridge-post-events'));
        }

        // Clear log file by truncating it
        $log_file = $this->get_log_file_path();
        $clear_success = true;
        if (file_exists($log_file)) {
            if (false === file_put_contents($log_file, '')) {
                $clear_success = false;
            }
        }

        // Redirect with appropriate message
        if ($clear_success) {
            add_settings_error(
                'eventbridge_test',
                'logs_cleared',
                __('Debug logs have been cleared successfully.', 'eventbridge-post-events'),
                'success'
            );
        } else {
            add_settings_error(
                'eventbridge_test',
                'logs_clear_failed',
                __('Failed to clear debug logs. Please check file permissions and disk space.', 'eventbridge-post-events'),
                'error'
            );
        }

        set_transient('eventbridge_test_result', get_settings_errors('eventbridge_test'), 30);
        wp_safe_redirect(admin_url('options-general.php?page=eventbridge-settings'));
        exit;
    }
}

/**
 * Plugin activation callback
 * Initializes default options and validates AWS configuration
 */
function eventbridge_post_events_activate()
{
    // Initialize metrics with default values (matching EventBridgePostEvents class structure)
    $default_metrics = array(
        'successful_events' => 0,
        'failed_events' => 0,
        'transient_failures' => 0,
        'permanent_failures' => 0
    );
    add_option('eventbridge_metrics', $default_metrics, '', false);

    // Initialize settings with default values (matching EventBridgePostEvents class structure)
    $default_settings = array(
        'event_format' => 'envelope',
        'send_mode' => 'async',
        'enabled_post_types' => array('post')
    );
    add_option('eventbridge_settings', $default_settings, '', true);

    // Validate AWS credentials - check both sources
    $activation_errors = array();
    $activation_warnings = array();

    // Check for constant-based credentials
    $has_constant_credentials = (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && !empty(constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID')) &&
                                 defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') && !empty(constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')));

    // Check for instance role credentials (using IMDSv2)
    $has_instance_role = eventbridge_check_instance_role_credentials();

    // Fail activation only if NEITHER credential source is available
    if (!$has_constant_credentials && !$has_instance_role) {
        $activation_errors[] = 'No AWS credentials available. Please either:';
        $activation_errors[] = '1. Define AWS_EVENTBRIDGE_ACCESS_KEY_ID and AWS_EVENTBRIDGE_SECRET_ACCESS_KEY in wp-config.php, OR';
        $activation_errors[] = '2. Ensure the plugin is running on an EC2 instance with an IAM role that has EventBridge PutEvents permissions';
    }

    // Validate region detection (using IMDSv2)
    $identity = eventbridge_get_instance_identity_imdsv2(false); // Don't use cache during activation

    if (!empty($identity['region'])) {
        // Region detected successfully - log for confirmation
        error_log(sprintf('[EventBridge] Plugin activated. Region detected: %s', $identity['region']));
    } elseif (!defined('EVENT_BRIDGE_REGION') || empty(constant('EVENT_BRIDGE_REGION'))) {
        // No region from IMDS and no fallback constant
        $activation_warnings[] = 'AWS region could not be detected from EC2 instance metadata and EVENT_BRIDGE_REGION is not defined. Please ensure the plugin is running on an EC2 instance or define EVENT_BRIDGE_REGION in wp-config.php.';
    } else {
        // Using fallback region from constant
        error_log(sprintf('[EventBridge] Plugin activated. Using fallback region from constant: %s', constant('EVENT_BRIDGE_REGION')));
    }

    // Store activation errors/warnings for display
    if (!empty($activation_errors)) {
        update_option('eventbridge_activation_errors', $activation_errors, false);
        // Deactivate the plugin if there are critical errors
        deactivate_plugins(plugin_basename(EVENTBRIDGE_POST_EVENTS_FILE));
        wp_die(
            '<h1>EventBridge Post Events - Activation Failed</h1>' .
            '<p><strong>The following errors prevented plugin activation:</strong></p>' .
            '<ul><li>' . implode('</li><li>', array_map('esc_html', $activation_errors)) . '</li></ul>' .
            '<h3>Configuration Options:</h3>' .
            '<p><strong>Option 1: Static Credentials</strong><br>' .
            'Add to wp-config.php:</p>' .
            '<pre>define(\'AWS_EVENTBRIDGE_ACCESS_KEY_ID\', \'your-access-key-id\');<br>' .
            'define(\'AWS_EVENTBRIDGE_SECRET_ACCESS_KEY\', \'your-secret-access-key\');<br>' .
            'define(\'EVENT_BRIDGE_REGION\', \'us-east-1\'); // Optional if not on EC2</pre>' .
            '<p><strong>Option 2: EC2 Instance Role (Recommended)</strong><br>' .
            'Attach an IAM role to your EC2 instance with the following policy:</p>' .
            '<pre>{\n' .
            '  "Version": "2012-10-17",\n' .
            '  "Statement": [{\n' .
            '    "Effect": "Allow",\n' .
            '    "Action": "events:PutEvents",\n' .
            '    "Resource": "*"\n' .
            '  }]\n' .
            '}</pre>' .
            '<p><a href="' . esc_url(admin_url('plugins.php')) . '">Return to Plugins</a></p>'
        );
    }

    if (!empty($activation_warnings)) {
        update_option('eventbridge_activation_warnings', $activation_warnings, false);
    }

    // Log successful activation
    error_log('[EventBridge] Plugin activated successfully');
}

/**
 * Plugin deactivation callback
 * Clears scheduled events and transient notices, preserves metrics
 */
function eventbridge_post_events_deactivate()
{
    // Clear all scheduled single events for async EventBridge sending
    // WordPress doesn't provide a direct way to get all scheduled events by hook,
    // so we need to check the cron array
    $cron_array = get_option('cron');

    if (is_array($cron_array)) {
        foreach ($cron_array as $timestamp => $cron) {
            if (isset($cron['eventbridge_async_send_event'])) {
                foreach ($cron['eventbridge_async_send_event'] as $key => $event) {
                    wp_unschedule_event($timestamp, 'eventbridge_async_send_event', $event['args']);
                }
            }
        }
    }

    // Clear transient notices
    delete_transient('eventbridge_notice_dismissed');

    // Clear activation warnings if any
    delete_option('eventbridge_activation_warnings');
    delete_option('eventbridge_activation_errors');

    // Preserve metrics and failure details for potential reactivation
    // Do NOT delete: eventbridge_metrics, eventbridge_failure_details, eventbridge_settings

    // Log deactivation
    error_log('[EventBridge] Plugin deactivated - scheduled events and transients cleared');
}

// Register lifecycle hooks
register_activation_hook(EVENTBRIDGE_POST_EVENTS_FILE, 'eventbridge_post_events_activate');
register_deactivation_hook(EVENTBRIDGE_POST_EVENTS_FILE, 'eventbridge_post_events_deactivate');

// インスタンスの作成
new EventBridgePostEvents();