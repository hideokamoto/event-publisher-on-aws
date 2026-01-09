<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://example.com/eventbridge-post-events
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 1.1
Author: Your Name
Author URI: https://example.com
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Default configuration constants (can be overridden in wp-config.php)
if (!defined('EVENT_BUS_NAME')) {
    define('EVENT_BUS_NAME', 'wp-kyoto');
}
if (!defined('EVENT_SOURCE_NAME')) {
    define('EVENT_SOURCE_NAME', 'wordpress');
}

/**
 * EventBridge PutEvents API Client
 * Handles AWS Signature V4 signing and API communication
 */
class EventBridgePutEvents
{
    private $accessKeyId;
    private $secretAccessKey;
    private $region;
    private $endpoint;
    private $serviceName;

    // Timeout configuration (in seconds)
    const EVENTBRIDGE_API_TIMEOUT = 10;

    /**
     * Constructor with credential validation
     *
     * @param string|null $accessKeyId AWS Access Key ID
     * @param string|null $secretAccessKey AWS Secret Access Key
     * @param string $region AWS Region
     * @throws InvalidArgumentException If credentials are invalid
     */
    public function __construct($accessKeyId, $secretAccessKey, $region)
    {
        // Validate credentials are not empty
        if (empty($accessKeyId) || empty($secretAccessKey)) {
            throw new InvalidArgumentException('AWS credentials cannot be empty');
        }

        // Validate region format (e.g., us-east-1, ap-northeast-1)
        if (!preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region)) {
            throw new InvalidArgumentException('Invalid AWS region format: ' . $region);
        }

        $this->accessKeyId = $accessKeyId;
        $this->secretAccessKey = $secretAccessKey;
        $this->region = $region;
        $this->endpoint = 'events.' . $region . '.amazonaws.com';
        $this->serviceName = 'events';
    }

    /**
     * Get the event bus name with fallback to constants/options
     *
     * @return string Event bus name
     */
    private function get_event_bus_name()
    {
        // Check constant first
        if (defined('EVENT_BUS_NAME') && !empty(EVENT_BUS_NAME)) {
            return EVENT_BUS_NAME;
        }
        // Fallback to option
        $settings = get_option('eventbridge_settings', array());
        return isset($settings['event_bus_name']) && !empty($settings['event_bus_name'])
            ? $settings['event_bus_name']
            : 'default';
    }

    /**
     * Send event to EventBridge with retry logic
     *
     * @param string $source Event source
     * @param string $detailType Event detail type
     * @param array $detail Event detail payload
     * @return array Result with success, error, and response keys
     */
    public function sendEvent($source, $detailType, $detail)
    {
        $method = 'POST';
        $path = '/';
        $eventBusName = $this->get_event_bus_name();

        $payload = json_encode(array(
            'Entries' => array(
                array(
                    'EventBusName' => $eventBusName,
                    'Source' => $source,
                    'DetailType' => $detailType,
                    'Detail' => json_encode($detail),
                ),
            ),
        ));

        $now = new DateTime('now', new DateTimeZone('UTC'));
        $amzDate = $now->format('Ymd\THis\Z');
        $dateStamp = $now->format('Ymd');

        $canonicalHeaders = "content-type:application/x-amz-json-1.1\nhost:{$this->endpoint}\nx-amz-date:{$amzDate}\nx-amz-target:AWSEvents.PutEvents\n";
        $signedHeaders = 'content-type;host;x-amz-date;x-amz-target';
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
        if ($signingKey === false) {
            return array(
                'success' => false,
                'error' => 'Failed to generate signing key',
                'response' => null,
                'error_type' => 'permanent'
            );
        }

        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        $authorizationHeader = "AWS4-HMAC-SHA256 Credential={$this->accessKeyId}/{$dateStamp}/{$this->region}/{$this->serviceName}/aws4_request, SignedHeaders={$signedHeaders}, Signature={$signature}";

        $headers = array(
            'Content-Type' => 'application/x-amz-json-1.1',
            'X-Amz-Date' => $amzDate,
            'X-Amz-Target' => 'AWSEvents.PutEvents',
            'Authorization' => $authorizationHeader,
        );

        // Retry configuration
        $maxRetries = 3;
        $retryDelay = 1;
        $lastError = null;
        $lastResponseCode = null;
        $errorType = 'transient';
        $timestamp = date('Y-m-d H:i:s');

        $verboseLogging = defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;
        $postId = isset($detail['id']) ? $detail['id'] : (isset($detail['data']['id']) ? $detail['data']['id'] : 'N/A');

        for ($attempt = 0; $attempt <= $maxRetries; $attempt++) {
            if ($verboseLogging) {
                error_log(sprintf(
                    '[EventBridge] Attempt %d/%d - Sending event: DetailType=%s, PostID=%s, Region=%s, EventBus=%s, Timestamp=%s',
                    $attempt + 1,
                    $maxRetries + 1,
                    $detailType,
                    $postId,
                    $this->region,
                    $eventBusName,
                    $timestamp
                ));
            }

            $response = wp_remote_request("https://{$this->endpoint}{$path}", array(
                'method' => $method,
                'headers' => $headers,
                'body' => $payload,
                'timeout' => self::EVENTBRIDGE_API_TIMEOUT,
            ));

            if (is_wp_error($response)) {
                $lastError = $response->get_error_message();
                $lastResponseCode = 'WP_Error';
                $errorType = 'transient';

                if ($verboseLogging) {
                    error_log(sprintf('[EventBridge] WP_Error on attempt %d: %s', $attempt + 1, $lastError));
                }

                if ($attempt < $maxRetries) {
                    sleep($retryDelay);
                    $retryDelay *= 2;
                    continue;
                }
            } else {
                $statusCode = (int)wp_remote_retrieve_response_code($response);
                $lastResponseCode = $statusCode;
                $responseBody = wp_remote_retrieve_body($response);

                if ($statusCode >= 400) {
                    $lastError = sprintf('HTTP %d: %s', $statusCode, $responseBody);

                    // Parse error response for detailed information
                    $errorData = json_decode($responseBody, true);
                    if (isset($errorData['__type'])) {
                        $lastError = sprintf('HTTP %d: %s - %s',
                            $statusCode,
                            $errorData['__type'],
                            isset($errorData['message']) ? $errorData['message'] : $responseBody
                        );
                    }

                    if ($verboseLogging) {
                        error_log(sprintf('[EventBridge] HTTP error on attempt %d: Status=%d, Body=%s', $attempt + 1, $statusCode, $responseBody));
                    }

                    // Determine if error is retryable
                    $isRetryable = ($statusCode >= 500 && $statusCode < 600) || $statusCode === 429;
                    $errorType = $isRetryable ? 'transient' : 'permanent';

                    if ($isRetryable && $attempt < $maxRetries) {
                        if ($verboseLogging) {
                            error_log(sprintf('[EventBridge] Retryable error detected. Waiting %d seconds...', $retryDelay));
                        }
                        sleep($retryDelay);
                        $retryDelay *= 2;
                        continue;
                    } elseif (!$isRetryable) {
                        if ($verboseLogging) {
                            error_log(sprintf('[EventBridge] Permanent failure detected (HTTP %d). Not retrying.', $statusCode));
                        }
                        break;
                    }
                } else {
                    $data = json_decode($responseBody, true);
                    $failedCount = isset($data['FailedEntryCount']) ? (int)$data['FailedEntryCount'] : 0;

                    if ($failedCount > 0) {
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

                                    // Determine error type based on error code
                                    if (in_array($entry['ErrorCode'], array('ThrottlingException', 'InternalException'))) {
                                        $errorType = 'transient';
                                    } else {
                                        $errorType = 'permanent';
                                    }
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

                        if ($verboseLogging) {
                            error_log(sprintf('[EventBridge] Partial failure on attempt %d: FailedEntryCount=%d', $attempt + 1, $failedCount));
                        }

                        if ($attempt < $maxRetries && $errorType === 'transient') {
                            sleep($retryDelay);
                            $retryDelay *= 2;
                            continue;
                        }
                        break;
                    }

                    if ($verboseLogging) {
                        error_log(sprintf('[EventBridge] Success on attempt %d: Status=%d', $attempt + 1, $statusCode));
                    }

                    // Clear sensitive data
                    unset($signingKey);

                    return array('success' => true, 'error' => null, 'response' => $data, 'error_type' => null);
                }
            }
        }

        error_log(sprintf(
            '[EventBridge] FAILED after %d attempts - DetailType: %s, PostID: %s, LastError: %s, LastResponseCode: %s, Region: %s, EventBus: %s, Timestamp: %s',
            $maxRetries + 1,
            $detailType,
            $postId,
            $lastError,
            $lastResponseCode,
            $this->region,
            $eventBusName,
            $timestamp
        ));

        // Clear sensitive data
        unset($signingKey);

        return array('success' => false, 'error' => $lastError, 'response' => null, 'error_type' => $errorType);
    }

    /**
     * Generate AWS Signature V4 signing key with validation
     *
     * @param string $dateStamp Date stamp in YYYYMMDD format
     * @return string|false Signing key or false on failure
     */
    private function getSignatureKey($dateStamp)
    {
        $kSecret = 'AWS4' . $this->secretAccessKey;

        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        if ($kDate === false) {
            error_log('[EventBridge] Failed to generate kDate in signature key derivation');
            return false;
        }

        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        if ($kRegion === false) {
            error_log('[EventBridge] Failed to generate kRegion in signature key derivation');
            return false;
        }

        $kService = hash_hmac('sha256', $this->serviceName, $kRegion, true);
        if ($kService === false) {
            error_log('[EventBridge] Failed to generate kService in signature key derivation');
            return false;
        }

        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        if ($kSigning === false) {
            error_log('[EventBridge] Failed to generate kSigning in signature key derivation');
            return false;
        }

        // Clear intermediate values
        unset($kSecret, $kDate, $kRegion, $kService);

        return $kSigning;
    }
}

/**
 * Main Plugin Class
 * Handles WordPress integration, event dispatching, and admin UI
 */
class EventBridgePostEvents
{
    private $region;
    private $credentials;
    private $client;
    private $credential_source;

    // IMDSv2 token caching
    private $imdsv2_token = null;
    private $imdsv2_token_expiry = null;
    const IMDSV2_TOKEN_TTL = 21600; // 6 hours
    const IMDSV2_TOKEN_REFRESH_MARGIN = 300; // 5 minutes before expiry
    const METADATA_TIMEOUT = 5; // 5 seconds for metadata requests

    // In-memory counters
    private $successful_events = 0;
    private $failed_events = 0;
    private $transient_failures = 0;
    private $permanent_failures = 0;

    // WordPress options keys
    const OPTION_METRICS = 'eventbridge_metrics';
    const OPTION_FAILURE_DETAILS = 'eventbridge_failure_details';
    const OPTION_SETTINGS = 'eventbridge_settings';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5;

    // Valid setting values
    const VALID_EVENT_FORMATS = array('legacy', 'envelope');
    const VALID_SEND_MODES = array('sync', 'async');
    const DEFAULT_ALLOWED_POST_TYPES = array('post', 'page');
    const MAX_EVENT_SIZE = 262144; // 256KB EventBridge limit

    // Settings
    private $settings;

    public function __construct()
    {
        // Load settings first
        $this->load_settings();

        // Settings page - always register
        add_action('admin_menu', array($this, 'add_settings_menu'));
        add_action('admin_init', array($this, 'register_settings'));

        // Get AWS credentials with resolution order
        $credentials = $this->get_aws_credentials();

        if ($credentials === false) {
            add_action('admin_notices', array($this, 'display_credentials_missing_notice'));
            return;
        }

        $this->credentials = $credentials;
        $this->credential_source = $credentials['source'];

        // Display credential source notice
        add_action('admin_notices', array($this, 'display_credential_source_notice'));

        // Get region with fallback
        $this->region = $this->get_region_with_fallback();

        if (empty($this->region)) {
            add_action('admin_notices', array($this, 'display_region_error_notice'));
            return;
        }

        try {
            $this->client = new EventBridgePutEvents(
                $credentials['access_key'],
                $credentials['secret_key'],
                $this->region
            );
        } catch (InvalidArgumentException $e) {
            add_action('admin_notices', function() use ($e) {
                ?>
                <div class="notice notice-error">
                    <p><?php echo esc_html(sprintf(__('EventBridge Post Events: Configuration error - %s', 'eventbridge-post-events'), $e->getMessage())); ?></p>
                </div>
                <?php
            });
            return;
        }

        // Load metrics
        $this->load_metrics();

        // Register hooks
        add_action('transition_post_status', array($this, 'send_post_event'), 10, 3);
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);
        add_action('eventbridge_async_send_event', array($this, 'async_send_event'), 10, 3);
        add_action('eventbridge_send_failed', array($this, 'handle_send_failure'), 10, 3);
        add_action('admin_notices', array($this, 'display_failure_notice'));
        add_action('admin_init', array($this, 'handle_notice_dismissal'));
        add_action('admin_init', array($this, 'handle_test_connection'));
        add_action('admin_init', array($this, 'handle_reset_metrics'));

        // AJAX handler for test connection
        add_action('wp_ajax_eventbridge_test_connection', array($this, 'ajax_test_connection'));
    }

    /**
     * Get AWS credentials with resolution order:
     * 1. Environment variables
     * 2. WordPress constants
     * 3. Return false if neither available
     *
     * @return array|false Credentials array with 'access_key', 'secret_key', 'source' or false
     */
    private function get_aws_credentials()
    {
        // Check environment variables first
        $env_access_key = getenv('AWS_ACCESS_KEY_ID');
        $env_secret_key = getenv('AWS_SECRET_ACCESS_KEY');

        if (!empty($env_access_key) && !empty($env_secret_key)) {
            return array(
                'access_key' => $env_access_key,
                'secret_key' => $env_secret_key,
                'source' => 'environment'
            );
        }

        // Check WordPress constants
        if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            $const_access_key = constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID');
            $const_secret_key = constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY');

            if (!empty($const_access_key) && !empty($const_secret_key)) {
                return array(
                    'access_key' => $const_access_key,
                    'secret_key' => $const_secret_key,
                    'source' => 'constants'
                );
            }
        }

        return false;
    }

    /**
     * Get IMDSv2 token with caching and refresh logic
     *
     * @return string|false Token string or false on failure
     */
    private function get_imdsv2_token()
    {
        // Check if we have a valid cached token
        if ($this->imdsv2_token !== null && $this->imdsv2_token_expiry !== null) {
            // Check if token is within 5 minutes of expiry
            $time_remaining = $this->imdsv2_token_expiry - time();
            if ($time_remaining > self::IMDSV2_TOKEN_REFRESH_MARGIN) {
                return $this->imdsv2_token;
            }
        }

        // Request new token
        $response = wp_remote_request('http://169.254.169.254/latest/api/token', array(
            'method' => 'PUT',
            'headers' => array(
                'X-aws-ec2-metadata-token-ttl-seconds' => (string)self::IMDSV2_TOKEN_TTL,
            ),
            'timeout' => self::METADATA_TIMEOUT,
        ));

        if (is_wp_error($response)) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] IMDSv2 token request failed: ' . $response->get_error_message());
            }
            return false;
        }

        $statusCode = (int)wp_remote_retrieve_response_code($response);
        if ($statusCode !== 200) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] IMDSv2 token request returned HTTP ' . $statusCode);
            }
            return false;
        }

        $token = wp_remote_retrieve_body($response);
        if (empty($token)) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] IMDSv2 token response was empty');
            }
            return false;
        }

        // Cache the token
        $this->imdsv2_token = $token;
        $this->imdsv2_token_expiry = time() + self::IMDSV2_TOKEN_TTL;

        return $token;
    }

    /**
     * Get EC2 instance identity document
     * Uses IMDSv2 with fallback to IMDSv1
     *
     * @return array Instance identity data or empty array
     */
    private function get_instance_identity()
    {
        $headers = array();

        // Try to get IMDSv2 token first
        $token = $this->get_imdsv2_token();
        if ($token !== false) {
            $headers['X-aws-ec2-metadata-token'] = $token;
        } else {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Falling back to IMDSv1 for instance identity');
            }
        }

        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
            'headers' => $headers,
            'timeout' => self::METADATA_TIMEOUT,
        ));

        if (is_wp_error($response)) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Instance identity request failed: ' . $response->get_error_message());
            }
            return array();
        }

        $statusCode = (int)wp_remote_retrieve_response_code($response);
        if ($statusCode !== 200) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Instance identity request returned HTTP ' . $statusCode);
            }
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data)) {
            return array();
        }

        return $data;
    }

    /**
     * Get region with fallback logic:
     * 1. EVENT_BRIDGE_REGION constant
     * 2. Settings override
     * 3. EC2 metadata
     * 4. 'us-east-1' default
     *
     * @return string AWS region
     */
    private function get_region_with_fallback()
    {
        // Check constant first
        if (defined('EVENT_BRIDGE_REGION') && !empty(EVENT_BRIDGE_REGION)) {
            $region = EVENT_BRIDGE_REGION;
            if ($this->validate_region_format($region)) {
                return $region;
            }
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Invalid region format in EVENT_BRIDGE_REGION constant: ' . $region);
            }
        }

        // Check settings override
        $settings = get_option(self::OPTION_SETTINGS, array());
        if (isset($settings['aws_region_override']) && !empty($settings['aws_region_override'])) {
            $region = $settings['aws_region_override'];
            if ($this->validate_region_format($region)) {
                return $region;
            }
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Invalid region format in settings override: ' . $region);
            }
        }

        // Try EC2 metadata
        $identity = $this->get_instance_identity();
        if (isset($identity['region']) && !empty($identity['region'])) {
            $region = $identity['region'];
            if ($this->validate_region_format($region)) {
                return $region;
            }
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[EventBridge] Invalid region format from EC2 metadata: ' . $region);
            }
        }

        // Fallback to us-east-1
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[EventBridge] Using fallback region: us-east-1');
        }

        // Set flag for admin notice
        set_transient('eventbridge_region_fallback_used', true, HOUR_IN_SECONDS);

        return 'us-east-1';
    }

    /**
     * Validate AWS region format
     *
     * @param string $region Region to validate
     * @return bool True if valid
     */
    private function validate_region_format($region)
    {
        return preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region) === 1;
    }

    /**
     * Display notice when credentials are missing
     */
    public function display_credentials_missing_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="notice notice-error">
            <p><?php esc_html_e('EventBridge Post Events: AWS認証情報が設定されていません。環境変数（AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY）またはwp-config.phpで定数（AWS_EVENTBRIDGE_ACCESS_KEY_ID, AWS_EVENTBRIDGE_SECRET_ACCESS_KEY）を定義してください。', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }

    /**
     * Display notice indicating credential source
     */
    public function display_credential_source_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Only show once per session via transient
        $transient_key = 'eventbridge_credential_notice_shown';
        if (get_transient($transient_key)) {
            return;
        }

        // Only show on plugin settings page
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'settings_page_eventbridge-settings') {
            return;
        }

        set_transient($transient_key, true, HOUR_IN_SECONDS);

        $source_label = $this->credential_source === 'environment'
            ? __('環境変数', 'eventbridge-post-events')
            : __('wp-config.php定数', 'eventbridge-post-events');
        ?>
        <div class="notice notice-info is-dismissible">
            <p><?php echo esc_html(sprintf(__('EventBridge Post Events: AWS認証情報は%sから読み込まれています。', 'eventbridge-post-events'), $source_label)); ?></p>
        </div>
        <?php
    }

    /**
     * Display notice when region detection fails
     */
    public function display_region_error_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="notice notice-error">
            <p><?php esc_html_e('EventBridge Post Events: AWSリージョンの検出に失敗しました。EVENT_BRIDGE_REGION定数を設定するか、設定ページでリージョンを指定してください。', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }

    /**
     * Get default settings
     */
    private function get_default_settings()
    {
        return array(
            'event_format' => 'envelope',
            'send_mode' => 'async',
            'event_bus_name' => '',
            'event_source_name' => '',
            'aws_region_override' => '',
            'allowed_post_types' => self::DEFAULT_ALLOWED_POST_TYPES,
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
    }

    /**
     * Get a specific setting value with resolution order:
     * 1. Constants (for certain settings)
     * 2. WordPress options
     * 3. Default values
     *
     * @param string $key Setting key
     * @return mixed Setting value
     */
    public function get_setting($key)
    {
        // Check constants first for specific settings
        switch ($key) {
            case 'event_bus_name':
                if (defined('EVENT_BUS_NAME') && !empty(EVENT_BUS_NAME)) {
                    return EVENT_BUS_NAME;
                }
                break;
            case 'event_source_name':
                if (defined('EVENT_SOURCE_NAME') && !empty(EVENT_SOURCE_NAME)) {
                    return EVENT_SOURCE_NAME;
                }
                break;
            case 'aws_region_override':
                if (defined('EVENT_BRIDGE_REGION') && !empty(EVENT_BRIDGE_REGION)) {
                    return EVENT_BRIDGE_REGION;
                }
                break;
        }

        // Return from settings or default
        $defaults = $this->get_default_settings();
        $value = isset($this->settings[$key]) ? $this->settings[$key] : null;

        if ($value === null || $value === '') {
            return isset($defaults[$key]) ? $defaults[$key] : null;
        }

        return $value;
    }

    /**
     * Add settings menu
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
     * Register settings
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
            __('AWS設定', 'eventbridge-post-events'),
            array($this, 'render_aws_section_description'),
            'eventbridge-settings'
        );

        add_settings_field(
            'event_bus_name',
            __('イベントバス名', 'eventbridge-post-events'),
            array($this, 'render_event_bus_name_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        add_settings_field(
            'event_source_name',
            __('イベントソース名', 'eventbridge-post-events'),
            array($this, 'render_event_source_name_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        add_settings_field(
            'aws_region_override',
            __('AWSリージョン（オーバーライド）', 'eventbridge-post-events'),
            array($this, 'render_aws_region_field'),
            'eventbridge-settings',
            'eventbridge_aws_section'
        );

        // Event Configuration Section
        add_settings_section(
            'eventbridge_event_section',
            __('イベント送信設定', 'eventbridge-post-events'),
            array($this, 'render_section_description'),
            'eventbridge-settings'
        );

        add_settings_field(
            'event_format',
            __('イベント形式', 'eventbridge-post-events'),
            array($this, 'render_event_format_field'),
            'eventbridge-settings',
            'eventbridge_event_section'
        );

        add_settings_field(
            'send_mode',
            __('送信モード', 'eventbridge-post-events'),
            array($this, 'render_send_mode_field'),
            'eventbridge-settings',
            'eventbridge_event_section'
        );

        add_settings_field(
            'allowed_post_types',
            __('対象投稿タイプ', 'eventbridge-post-events'),
            array($this, 'render_allowed_post_types_field'),
            'eventbridge-settings',
            'eventbridge_event_section'
        );
    }

    /**
     * Sanitize settings
     */
    public function sanitize_settings($input)
    {
        $sanitized = array();
        $defaults = $this->get_default_settings();

        // Sanitize event_format
        $sanitized['event_format'] = isset($input['event_format']) && in_array($input['event_format'], self::VALID_EVENT_FORMATS, true)
            ? $input['event_format']
            : $defaults['event_format'];

        // Sanitize send_mode
        $sanitized['send_mode'] = isset($input['send_mode']) && in_array($input['send_mode'], self::VALID_SEND_MODES, true)
            ? $input['send_mode']
            : $defaults['send_mode'];

        // Sanitize event_bus_name (AWS naming: 1-256 chars, alphanumeric, hyphens, underscores, periods, slashes)
        if (isset($input['event_bus_name']) && !empty($input['event_bus_name'])) {
            $bus_name = sanitize_text_field($input['event_bus_name']);
            if (preg_match('/^[a-zA-Z0-9._\-\/]{1,256}$/', $bus_name)) {
                $sanitized['event_bus_name'] = $bus_name;
            } else {
                add_settings_error('eventbridge_settings', 'invalid_bus_name',
                    __('イベントバス名の形式が無効です。英数字、ハイフン、アンダースコア、ピリオド、スラッシュのみ使用できます。', 'eventbridge-post-events'));
                $sanitized['event_bus_name'] = '';
            }
        } else {
            $sanitized['event_bus_name'] = '';
        }

        // Sanitize event_source_name
        if (isset($input['event_source_name']) && !empty($input['event_source_name'])) {
            $source_name = sanitize_text_field($input['event_source_name']);
            if (preg_match('/^[a-zA-Z0-9._\-\/]{1,256}$/', $source_name)) {
                $sanitized['event_source_name'] = $source_name;
            } else {
                add_settings_error('eventbridge_settings', 'invalid_source_name',
                    __('イベントソース名の形式が無効です。', 'eventbridge-post-events'));
                $sanitized['event_source_name'] = '';
            }
        } else {
            $sanitized['event_source_name'] = '';
        }

        // Sanitize aws_region_override
        if (isset($input['aws_region_override']) && !empty($input['aws_region_override'])) {
            $region = sanitize_text_field($input['aws_region_override']);
            if ($this->validate_region_format($region)) {
                $sanitized['aws_region_override'] = $region;
            } else {
                add_settings_error('eventbridge_settings', 'invalid_region',
                    __('AWSリージョンの形式が無効です（例: ap-northeast-1）', 'eventbridge-post-events'));
                $sanitized['aws_region_override'] = '';
            }
        } else {
            $sanitized['aws_region_override'] = '';
        }

        // Sanitize allowed_post_types
        if (isset($input['allowed_post_types']) && is_array($input['allowed_post_types'])) {
            $sanitized['allowed_post_types'] = array_map('sanitize_text_field', $input['allowed_post_types']);
        } else {
            $sanitized['allowed_post_types'] = $defaults['allowed_post_types'];
        }

        return $sanitized;
    }

    /**
     * Render AWS section description
     */
    public function render_aws_section_description()
    {
        echo '<p>' . esc_html__('AWS EventBridgeの接続設定です。定数で定義されている場合、そちらが優先されます。', 'eventbridge-post-events') . '</p>';
    }

    /**
     * Render section description
     */
    public function render_section_description()
    {
        echo '<p>' . esc_html__('EventBridgeへのイベント送信方法を設定します。', 'eventbridge-post-events') . '</p>';
    }

    /**
     * Render event bus name field
     */
    public function render_event_bus_name_field()
    {
        $constant_defined = defined('EVENT_BUS_NAME') && !empty(EVENT_BUS_NAME);
        $current = $this->settings['event_bus_name'];
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_bus_name]"
               value="<?php echo esc_attr($current); ?>"
               class="regular-text"
               <?php echo $constant_defined ? 'disabled' : ''; ?>
               placeholder="<?php echo esc_attr($constant_defined ? EVENT_BUS_NAME : 'default'); ?>">
        <?php if ($constant_defined): ?>
            <p class="description"><?php echo esc_html(sprintf(__('定数 EVENT_BUS_NAME で「%s」が設定されています。', 'eventbridge-post-events'), EVENT_BUS_NAME)); ?></p>
        <?php else: ?>
            <p class="description"><?php esc_html_e('EventBridgeイベントバス名を指定します。空の場合は「default」が使用されます。', 'eventbridge-post-events'); ?></p>
        <?php endif;
    }

    /**
     * Render event source name field
     */
    public function render_event_source_name_field()
    {
        $constant_defined = defined('EVENT_SOURCE_NAME') && !empty(EVENT_SOURCE_NAME);
        $current = $this->settings['event_source_name'];
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_source_name]"
               value="<?php echo esc_attr($current); ?>"
               class="regular-text"
               <?php echo $constant_defined ? 'disabled' : ''; ?>
               placeholder="<?php echo esc_attr($constant_defined ? EVENT_SOURCE_NAME : 'wordpress'); ?>">
        <?php if ($constant_defined): ?>
            <p class="description"><?php echo esc_html(sprintf(__('定数 EVENT_SOURCE_NAME で「%s」が設定されています。', 'eventbridge-post-events'), EVENT_SOURCE_NAME)); ?></p>
        <?php else: ?>
            <p class="description"><?php esc_html_e('イベントのソース名を指定します。', 'eventbridge-post-events'); ?></p>
        <?php endif;
    }

    /**
     * Render AWS region field
     */
    public function render_aws_region_field()
    {
        $constant_defined = defined('EVENT_BRIDGE_REGION') && !empty(EVENT_BRIDGE_REGION);
        $current = $this->settings['aws_region_override'];
        ?>
        <input type="text"
               name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[aws_region_override]"
               value="<?php echo esc_attr($current); ?>"
               class="regular-text"
               <?php echo $constant_defined ? 'disabled' : ''; ?>
               placeholder="<?php echo esc_attr($constant_defined ? EVENT_BRIDGE_REGION : __('自動検出', 'eventbridge-post-events')); ?>">
        <?php if ($constant_defined): ?>
            <p class="description"><?php echo esc_html(sprintf(__('定数 EVENT_BRIDGE_REGION で「%s」が設定されています。', 'eventbridge-post-events'), EVENT_BRIDGE_REGION)); ?></p>
        <?php else: ?>
            <p class="description"><?php esc_html_e('AWSリージョンを指定します。空の場合はEC2メタデータから自動検出されます（例: ap-northeast-1）', 'eventbridge-post-events'); ?></p>
        <?php endif;
    }

    /**
     * Render event format field
     */
    public function render_event_format_field()
    {
        $current = $this->get_setting('event_format');
        ?>
        <fieldset>
            <label>
                <input type="radio" name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_format]" value="legacy" <?php checked($current, 'legacy'); ?>>
                <?php esc_html_e('レガシー形式（プロトタイプ互換）', 'eventbridge-post-events'); ?>
            </label>
            <p class="description"><?php esc_html_e('イベントデータをそのまま送信します。既存の受信側との互換性を維持します。', 'eventbridge-post-events'); ?></p>
            <pre style="background:#f5f5f5;padding:10px;margin:5px 0 15px;font-size:12px;">{"id": "123", "title": "記事タイトル", ...}</pre>

            <label>
                <input type="radio" name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[event_format]" value="envelope" <?php checked($current, 'envelope'); ?>>
                <?php esc_html_e('エンベロープ形式（推奨）', 'eventbridge-post-events'); ?>
            </label>
            <p class="description"><?php esc_html_e('イベントID、タイムスタンプ、コリレーションID等のメタデータを含めて送信します。', 'eventbridge-post-events'); ?></p>
            <pre style="background:#f5f5f5;padding:10px;margin:5px 0;font-size:12px;">{"event_id": "uuid", "correlation_id": "uuid", "data": {"id": "123", ...}}</pre>
        </fieldset>
        <?php
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
     * Render allowed post types field
     */
    public function render_allowed_post_types_field()
    {
        $current = $this->get_setting('allowed_post_types');
        $post_types = get_post_types(array('public' => true), 'objects');
        ?>
        <fieldset>
            <?php foreach ($post_types as $post_type): ?>
                <label style="display:block;margin-bottom:5px;">
                    <input type="checkbox"
                           name="<?php echo esc_attr(self::OPTION_SETTINGS); ?>[allowed_post_types][]"
                           value="<?php echo esc_attr($post_type->name); ?>"
                           <?php checked(in_array($post_type->name, $current, true)); ?>>
                    <?php echo esc_html($post_type->labels->name); ?> (<?php echo esc_html($post_type->name); ?>)
                </label>
            <?php endforeach; ?>
            <p class="description"><?php esc_html_e('イベントを送信する投稿タイプを選択します。', 'eventbridge-post-events'); ?></p>
        </fieldset>
        <?php
    }

    /**
     * Render settings page with diagnostics
     */
    public function render_settings_page()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php settings_errors('eventbridge_settings'); ?>

            <!-- Status Section -->
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('ステータス', 'eventbridge-post-events'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('リージョン', 'eventbridge-post-events'); ?></th>
                        <td>
                            <?php echo esc_html($this->region ?: __('未設定', 'eventbridge-post-events')); ?>
                            <?php if (get_transient('eventbridge_region_fallback_used')): ?>
                                <span style="color:orange;margin-left:10px;">⚠ <?php esc_html_e('フォールバックを使用', 'eventbridge-post-events'); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('認証情報ソース', 'eventbridge-post-events'); ?></th>
                        <td>
                            <?php
                            if (isset($this->credential_source)) {
                                echo $this->credential_source === 'environment'
                                    ? esc_html__('環境変数', 'eventbridge-post-events')
                                    : esc_html__('wp-config.php定数', 'eventbridge-post-events');
                            } else {
                                echo '<span style="color:red;">' . esc_html__('未設定', 'eventbridge-post-events') . '</span>';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('イベントバス', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html($this->get_setting('event_bus_name') ?: 'default'); ?></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('イベントソース', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html($this->get_setting('event_source_name') ?: 'wordpress'); ?></td>
                    </tr>
                </table>
            </div>

            <!-- Metrics Section -->
            <?php
            $metrics = get_option(self::OPTION_METRICS, array(
                'successful_events' => 0,
                'failed_events' => 0,
                'transient_failures' => 0,
                'permanent_failures' => 0
            ));
            $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array());
            ?>
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('送信統計', 'eventbridge-post-events'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('成功', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:green;"><?php echo esc_html($metrics['successful_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('失敗（合計）', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:<?php echo $metrics['failed_events'] > 0 ? 'red' : 'inherit'; ?>;"><?php echo esc_html($metrics['failed_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('一時的なエラー', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html(isset($metrics['transient_failures']) ? $metrics['transient_failures'] : 0); ?></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('永続的なエラー', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html(isset($metrics['permanent_failures']) ? $metrics['permanent_failures'] : 0); ?></td>
                    </tr>
                    <?php if (!empty($failure_details['last_failure_time'])): ?>
                    <tr>
                        <th><?php esc_html_e('最後のエラー', 'eventbridge-post-events'); ?></th>
                        <td>
                            <strong><?php echo esc_html($failure_details['last_failure_time']); ?></strong><br>
                            <?php
                            if (!empty($failure_details['messages'])) {
                                $last_msg = end($failure_details['messages']);
                                echo '<code>' . esc_html(isset($last_msg['message']) ? $last_msg['message'] : '') . '</code>';
                            }
                            ?>
                        </td>
                    </tr>
                    <?php endif; ?>
                </table>
                <p>
                    <?php
                    $reset_url = add_query_arg(array(
                        'eventbridge_reset_metrics' => '1',
                        'eventbridge_nonce' => wp_create_nonce('eventbridge_reset_metrics')
                    ));
                    ?>
                    <a href="<?php echo esc_url($reset_url); ?>" class="button" onclick="return confirm('<?php esc_attr_e('メトリクスをリセットしますか？', 'eventbridge-post-events'); ?>');">
                        <?php esc_html_e('メトリクスをリセット', 'eventbridge-post-events'); ?>
                    </a>
                </p>
            </div>

            <!-- Test Connection Section -->
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('接続テスト', 'eventbridge-post-events'); ?></h2>
                <p><?php esc_html_e('テストイベントをEventBridgeに送信して、接続を確認します。', 'eventbridge-post-events'); ?></p>
                <?php
                $test_url = add_query_arg(array(
                    'eventbridge_test_connection' => '1',
                    'eventbridge_nonce' => wp_create_nonce('eventbridge_test_connection')
                ));
                ?>
                <p>
                    <a href="<?php echo esc_url($test_url); ?>" class="button button-primary">
                        <?php esc_html_e('接続をテスト', 'eventbridge-post-events'); ?>
                    </a>
                </p>
                <?php if (isset($_GET['eventbridge_test_result'])): ?>
                    <?php if ($_GET['eventbridge_test_result'] === 'success'): ?>
                        <div class="notice notice-success inline"><p><?php esc_html_e('接続テスト成功！', 'eventbridge-post-events'); ?></p></div>
                    <?php else: ?>
                        <div class="notice notice-error inline">
                            <p><?php esc_html_e('接続テスト失敗', 'eventbridge-post-events'); ?>:
                            <?php echo esc_html(isset($_GET['eventbridge_test_error']) ? urldecode($_GET['eventbridge_test_error']) : ''); ?></p>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>

            <form action="options.php" method="post">
                <?php
                settings_fields('eventbridge_settings_group');
                do_settings_sections('eventbridge-settings');
                submit_button(__('設定を保存', 'eventbridge-post-events'));
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * Handle test connection request
     */
    public function handle_test_connection()
    {
        if (!isset($_GET['eventbridge_test_connection'])) {
            return;
        }

        if (!isset($_GET['eventbridge_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['eventbridge_nonce'])), 'eventbridge_test_connection')) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        if (!$this->client) {
            wp_safe_redirect(add_query_arg(array(
                'eventbridge_test_result' => 'error',
                'eventbridge_test_error' => urlencode(__('クライアントが初期化されていません', 'eventbridge-post-events'))
            ), remove_query_arg(array('eventbridge_test_connection', 'eventbridge_nonce'))));
            exit;
        }

        $test_event = array(
            'test' => true,
            'timestamp' => current_time('c'),
            'source' => get_bloginfo('url'),
        );

        $result = $this->client->sendEvent(
            $this->get_setting('event_source_name') ?: 'wordpress',
            'connection.test',
            $test_event
        );

        if ($result['success']) {
            wp_safe_redirect(add_query_arg(array(
                'eventbridge_test_result' => 'success'
            ), remove_query_arg(array('eventbridge_test_connection', 'eventbridge_nonce'))));
        } else {
            wp_safe_redirect(add_query_arg(array(
                'eventbridge_test_result' => 'error',
                'eventbridge_test_error' => urlencode($result['error'])
            ), remove_query_arg(array('eventbridge_test_connection', 'eventbridge_nonce'))));
        }
        exit;
    }

    /**
     * Handle metrics reset request
     */
    public function handle_reset_metrics()
    {
        if (!isset($_GET['eventbridge_reset_metrics'])) {
            return;
        }

        if (!isset($_GET['eventbridge_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['eventbridge_nonce'])), 'eventbridge_reset_metrics')) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $this->successful_events = 0;
        $this->failed_events = 0;
        $this->transient_failures = 0;
        $this->permanent_failures = 0;
        $this->save_metrics();

        delete_option(self::OPTION_FAILURE_DETAILS);

        wp_safe_redirect(remove_query_arg(array('eventbridge_reset_metrics', 'eventbridge_nonce')));
        exit;
    }

    /**
     * Load metrics from options
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
     * Save metrics to options
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
     * Record a failed event with error type distinction
     *
     * @param string $error_message Error message
     * @param string $error_type Error type (transient or permanent)
     */
    private function record_failure($error_message, $error_type = 'transient')
    {
        $this->failed_events++;

        if ($error_type === 'transient') {
            $this->transient_failures++;
        } else {
            $this->permanent_failures++;
        }

        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array(
            'last_failure_time' => null,
            'messages' => array()
        ));

        $failure_details['last_failure_time'] = current_time('mysql');
        $failure_details['messages'][] = array(
            'time' => current_time('mysql'),
            'message' => $error_message,
            'type' => $error_type
        );

        if (count($failure_details['messages']) > 10) {
            $failure_details['messages'] = array_slice($failure_details['messages'], -10);
        }

        update_option(self::OPTION_FAILURE_DETAILS, $failure_details, false);
        $this->save_metrics();
    }

    /**
     * Track event result
     */
    private function track_event_result($result)
    {
        if ($result['success']) {
            $this->record_success();
        } else {
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $error_type = isset($result['error_type']) ? $result['error_type'] : 'transient';
            $this->record_failure($error_message, $error_type);
        }
    }

    /**
     * Create event envelope
     */
    private function create_event_envelope($data, $correlation_id)
    {
        return array(
            'event_id' => wp_generate_uuid4(),
            'event_timestamp' => current_time('c'),
            'event_version' => '1.0',
            'source_system' => get_bloginfo('url'),
            'correlation_id' => $correlation_id,
            'data' => $data
        );
    }

    /**
     * Get or create correlation ID with fallback
     */
    private function get_or_create_correlation_id($post_id)
    {
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        if (empty($correlation_id)) {
            $correlation_id = wp_generate_uuid4();

            // Fallback UUID generation if wp_generate_uuid4 fails
            if (empty($correlation_id) || $correlation_id === false) {
                $correlation_id = sprintf(
                    '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                    mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0x0fff) | 0x4000,
                    mt_rand(0, 0x3fff) | 0x8000,
                    mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
                );
            }

            $added = add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

            if ($added === false) {
                $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
            }
        }

        return $correlation_id;
    }

    /**
     * Prepare event payload with size validation
     */
    private function prepare_event_payload($event_data, $post_id)
    {
        $event_format = $this->get_setting('event_format');

        if ($event_format === 'envelope') {
            $correlation_id = $this->get_or_create_correlation_id($post_id);
            $payload = $this->create_event_envelope($event_data, $correlation_id);
        } else {
            $payload = $event_data;
        }

        // Validate payload size (256KB limit)
        $json_payload = json_encode($payload);
        if (strlen($json_payload) > self::MAX_EVENT_SIZE) {
            error_log(sprintf(
                '[EventBridge] Event payload exceeds 256KB limit: %d bytes for post %d',
                strlen($json_payload),
                $post_id
            ));

            // Truncate excerpt if too long
            if (isset($payload['data']['excerpt'])) {
                $payload['data']['excerpt'] = mb_substr($payload['data']['excerpt'], 0, 500) . '...';
            } elseif (isset($payload['excerpt'])) {
                $payload['excerpt'] = mb_substr($payload['excerpt'], 0, 500) . '...';
            }
        }

        return $payload;
    }

    /**
     * Check if post type is allowed
     */
    private function is_post_type_allowed($post_type)
    {
        $allowed = $this->get_setting('allowed_post_types');
        if (!is_array($allowed) || empty($allowed)) {
            $allowed = self::DEFAULT_ALLOWED_POST_TYPES;
        }
        return in_array($post_type, $allowed, true);
    }

    /**
     * Determine event type based on status transition
     */
    private function get_event_type($new_status, $old_status)
    {
        if ($new_status === 'future') {
            return 'post.scheduled';
        }

        if ($new_status === 'publish' && $old_status !== 'publish') {
            return 'post.published';
        }

        if ($new_status === 'publish' && $old_status === 'publish') {
            return 'post.updated';
        }

        return 'post.' . $new_status;
    }

    /**
     * Send post event on status transition
     */
    public function send_post_event($new_status, $old_status, $post)
    {
        // Null checks for post object
        if (!$post || !is_object($post) || !isset($post->ID)) {
            return;
        }

        // Check allowed statuses
        $allowed_statuses = array('publish', 'future');
        if (!in_array($new_status, $allowed_statuses, true)) {
            return;
        }

        // Check post type
        $post_type = isset($post->post_type) ? $post->post_type : 'post';
        if (!$this->is_post_type_allowed($post_type)) {
            return;
        }

        $event_name = $this->get_event_type($new_status, $old_status);
        $permalink = get_permalink($post->ID);

        $post_type_obj = get_post_type_object($post_type);
        $rest_base = !empty($post_type_obj->rest_base) ? $post_type_obj->rest_base : $post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $rest_base . '/' . $post->ID);

        $event_data = array(
            'id' => (string)$post->ID,
            'title' => isset($post->post_title) ? $post->post_title : '',
            'excerpt' => isset($post->post_excerpt) ? $post->post_excerpt : '',
            'status' => $new_status,
            'previous_status' => $old_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type,
        );

        // Add scheduled time for future posts
        if ($new_status === 'future' && isset($post->post_date_gmt)) {
            $event_data['scheduled_time'] = $post->post_date_gmt;
        }

        $event_payload = $this->prepare_event_payload($event_data, $post->ID);
        $source = $this->get_setting('event_source_name') ?: 'wordpress';
        $this->dispatch_event($source, $event_name, $event_payload);
    }

    /**
     * Send delete post event
     */
    public function send_delete_post_event($post_id)
    {
        if (!$post_id) {
            return;
        }

        $post = get_post($post_id);
        if (!$post) {
            return;
        }

        $post_type = isset($post->post_type) ? $post->post_type : 'post';
        if (!$this->is_post_type_allowed($post_type)) {
            return;
        }

        $event_name = 'post.deleted';

        $event_data = array(
            'id' => (string)$post_id,
            'post_type' => $post_type,
        );

        $event_payload = $this->prepare_event_payload($event_data, $post_id);
        $source = $this->get_setting('event_source_name') ?: 'wordpress';
        $this->dispatch_event($source, $event_name, $event_payload);
    }

    /**
     * Dispatch event based on send mode
     */
    private function dispatch_event($source, $event_name, $event_payload)
    {
        $send_mode = $this->get_setting('send_mode');

        if ($send_mode === 'sync') {
            $this->do_send_event($source, $event_name, $event_payload);
        } else {
            wp_schedule_single_event(time(), 'eventbridge_async_send_event', array($source, $event_name, $event_payload));
        }
    }

    /**
     * Execute event sending
     */
    private function do_send_event($source, $detailType, $detail)
    {
        $result = $this->client->sendEvent($source, $detailType, $detail);
        $this->track_event_result($result);

        if (!$result['success']) {
            do_action('eventbridge_send_failed', $source, $detailType, $detail);
        }

        return $result;
    }

    /**
     * Async send event callback
     */
    public function async_send_event($source, $detailType, $detail)
    {
        return $this->do_send_event($source, $detailType, $detail);
    }

    /**
     * Handle send failure
     */
    public function handle_send_failure($source, $detailType, $detail)
    {
        $postId = isset($detail['id']) ? $detail['id'] : (isset($detail['data']['id']) ? $detail['data']['id'] : null);
        if ($postId) {
            error_log(sprintf(
                '[EventBridge] Failed to send event after all retries: DetailType=%s, PostID=%s, Source=%s',
                $detailType,
                $postId,
                $source
            ));
        }
    }

    /**
     * Display failure notice
     */
    public function display_failure_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (get_transient(self::TRANSIENT_NOTICE_DISMISSED)) {
            return;
        }

        $failure_count = $this->failed_events;
        if ($failure_count < self::FAILURE_THRESHOLD) {
            return;
        }

        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array(
            'last_failure_time' => 'Unknown',
            'messages' => array()
        ));

        $last_failure_time = $failure_details['last_failure_time'] ?: 'Unknown';
        $failure_messages = $failure_details['messages'];
        $success_count = $this->successful_events;

        $recent_error = 'Unknown error';
        if (!empty($failure_messages)) {
            $last_index = count($failure_messages) - 1;
            $recent_error = isset($failure_messages[$last_index]['message'])
                ? $failure_messages[$last_index]['message']
                : 'Unknown error';
        }

        $dismiss_url = add_query_arg(array(
            'eventbridge_dismiss_notice' => '1',
            'eventbridge_nonce' => wp_create_nonce('eventbridge_dismiss_notice')
        ));
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
                <li><?php esc_html_e('Check your AWS EventBridge credentials', 'eventbridge-post-events'); ?></li>
                <li><?php printf(esc_html__('Verify EventBridge event bus "%s" exists in region "%s"', 'eventbridge-post-events'), esc_html($this->get_setting('event_bus_name') ?: 'default'), esc_html($this->region)); ?></li>
                <li><?php esc_html_e('Ensure IAM permissions include "events:PutEvents"', 'eventbridge-post-events'); ?></li>
            </ol>
            <p>
                <a href="<?php echo esc_url($dismiss_url); ?>" class="button button-primary"><?php esc_html_e('Dismiss for 24 hours', 'eventbridge-post-events'); ?></a>
            </p>
        </div>
        <?php
    }

    /**
     * Handle notice dismissal
     */
    public function handle_notice_dismissal()
    {
        if (!isset($_GET['eventbridge_dismiss_notice'])) {
            return;
        }

        if (!isset($_GET['eventbridge_nonce'])) {
            return;
        }

        $nonce = sanitize_text_field(wp_unslash($_GET['eventbridge_nonce']));
        if (!wp_verify_nonce($nonce, 'eventbridge_dismiss_notice')) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        set_transient(self::TRANSIENT_NOTICE_DISMISSED, true, 24 * HOUR_IN_SECONDS);

        $this->failed_events = 0;
        $this->save_metrics();

        wp_safe_redirect(remove_query_arg(array('eventbridge_dismiss_notice', 'eventbridge_nonce')));
        exit;
    }

    /**
     * AJAX handler for test connection
     */
    public function ajax_test_connection()
    {
        check_ajax_referer('eventbridge_test_connection', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        if (!$this->client) {
            wp_send_json_error(array('message' => 'Client not initialized'));
        }

        $test_event = array(
            'test' => true,
            'timestamp' => current_time('c'),
            'source' => get_bloginfo('url'),
        );

        $result = $this->client->sendEvent(
            $this->get_setting('event_source_name') ?: 'wordpress',
            'connection.test',
            $test_event
        );

        if ($result['success']) {
            wp_send_json_success(array('message' => 'Connection successful'));
        } else {
            wp_send_json_error(array('message' => $result['error']));
        }
    }
}

/**
 * Plugin activation hook
 */
function eventbridge_activate()
{
    // Initialize metrics option
    if (!get_option(EventBridgePostEvents::OPTION_METRICS)) {
        add_option(EventBridgePostEvents::OPTION_METRICS, array(
            'successful_events' => 0,
            'failed_events' => 0,
            'transient_failures' => 0,
            'permanent_failures' => 0
        ), '', 'no');
    }

    // Validate AWS credentials availability
    $env_access = getenv('AWS_ACCESS_KEY_ID');
    $env_secret = getenv('AWS_SECRET_ACCESS_KEY');
    $const_access = defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') ? constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID') : null;
    $const_secret = defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') ? constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') : null;

    $has_credentials = (!empty($env_access) && !empty($env_secret)) ||
                       (!empty($const_access) && !empty($const_secret));

    if (!$has_credentials) {
        set_transient('eventbridge_activation_notice', 'credentials_missing', 60);
    }

    // Check region detection
    if (!defined('EVENT_BRIDGE_REGION') || empty(EVENT_BRIDGE_REGION)) {
        // Try to get from metadata (won't work if not on EC2)
        $response = @wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
            'timeout' => 2
        ));

        if (is_wp_error($response)) {
            set_transient('eventbridge_activation_notice', 'region_fallback', 60);
        }
    }
}
register_activation_hook(__FILE__, 'eventbridge_activate');

/**
 * Plugin deactivation hook
 */
function eventbridge_deactivate()
{
    // Clear scheduled events
    $timestamp = wp_next_scheduled('eventbridge_async_send_event');
    while ($timestamp) {
        wp_unschedule_event($timestamp, 'eventbridge_async_send_event');
        $timestamp = wp_next_scheduled('eventbridge_async_send_event');
    }

    // Clear transients
    delete_transient(EventBridgePostEvents::TRANSIENT_NOTICE_DISMISSED);
    delete_transient('eventbridge_credential_notice_shown');
    delete_transient('eventbridge_region_fallback_used');
    delete_transient('eventbridge_activation_notice');

    // Note: metrics and failure details are preserved for potential reactivation
}
register_deactivation_hook(__FILE__, 'eventbridge_deactivate');

// Display activation notices
add_action('admin_notices', function() {
    $notice = get_transient('eventbridge_activation_notice');
    if (!$notice) {
        return;
    }
    delete_transient('eventbridge_activation_notice');

    if ($notice === 'credentials_missing') {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><?php esc_html_e('EventBridge Post Events: AWS認証情報が見つかりませんでした。プラグインを使用するには、環境変数またはwp-config.phpで認証情報を設定してください。', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    } elseif ($notice === 'region_fallback') {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><?php esc_html_e('EventBridge Post Events: AWSリージョンの自動検出に失敗しました。EC2メタデータにアクセスできない環境では、EVENT_BRIDGE_REGION定数を設定してください。', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }
});

// Initialize plugin
new EventBridgePostEvents();
