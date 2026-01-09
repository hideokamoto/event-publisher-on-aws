<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://example.com/eventbridge-post-events
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 1.0
Author: Your Name
Author URI: https://example.com
*/

// EventBridge設定（wp-config.phpで上書き可能）
if (!defined('EVENT_BUS_NAME')) {
    define('EVENT_BUS_NAME', 'wp-kyoto');
}
if (!defined('EVENT_SOURCE_NAME')) {
    define('EVENT_SOURCE_NAME', 'wordpress');
}

class EventBridgePutEvents
{
    private $accessKeyId;
    private $secretAccessKey;
    private $sessionToken;
    private $region;
    private $endpoint;
    private $serviceName;
    private $eventBusName;

    public function __construct($accessKeyId, $secretAccessKey, $region, $sessionToken = null, $eventBusName = 'default')
    {
        $this->accessKeyId = $accessKeyId;
        $this->secretAccessKey = $secretAccessKey;
        $this->sessionToken = $sessionToken;
        $this->region = $region;
        $this->endpoint = 'events.' . $region . '.amazonaws.com';
        $this->serviceName = 'events';
        $this->eventBusName = $eventBusName;
    }

    public function sendEvent($source, $detailType, $detail)
    {
        $method = 'POST';
        $path = '/';

        // Build the EventBridge envelope
        $envelope = array(
            'Entries' => array(
                array(
                    'EventBusName' => $this->eventBusName,
                    'Source' => $source,
                    'DetailType' => $detailType,
                    'Detail' => json_encode($detail),
                ),
            ),
        );

        $payload = json_encode($envelope);

        // Validate final envelope size (256KB EventBridge limit per request)
        if ($payload === false) {
            $postId = isset($detail['id']) ? $detail['id'] : 'N/A';
            $errorMsg = sprintf(
                'Failed to JSON encode EventBridge envelope for DetailType=%s, PostID=%s: %s',
                $detailType,
                $postId,
                json_last_error_msg()
            );
            error_log('[EventBridge] ' . $errorMsg);
            return array('success' => false, 'error' => $errorMsg, 'response' => null, 'is_transient' => false);
        }

        $payload_size = strlen($payload);
        $max_payload_size = 256 * 1024; // 256KB in bytes

        if ($payload_size > $max_payload_size) {
            $postId = isset($detail['id']) ? $detail['id'] : 'N/A';
            $detail_size = strlen(json_encode($detail));
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

        // SessionTokenがある場合は署名対象のヘッダーに含める
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

        $authorizationHeader = "AWS4-HMAC-SHA256 Credential={$this->accessKeyId}/{$dateStamp}/{$this->region}/{$this->serviceName}/aws4_request, SignedHeaders={$signedHeaders}, Signature={$signature}";

        $headers = array(
            'Content-Type' => 'application/x-amz-json-1.1',
            'X-Amz-Date' => $amzDate,
            'X-Amz-Target' => 'AWSEvents.PutEvents',
            'Authorization' => $authorizationHeader,
        );

        // SessionTokenがある場合はヘッダーに追加
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

        // Extract post ID from detail if available
        $postId = isset($detail['id']) ? $detail['id'] : 'N/A';

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

    private function getSignatureKey($dateStamp)
    {
        $kSecret = 'AWS4' . $this->secretAccessKey;
        $kDate = hash_hmac('sha256', $dateStamp, $kSecret, true);
        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        $kService = hash_hmac('sha256', $this->serviceName, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

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

    // In-memory counters for tracking metrics
    private $successful_events = 0;
    private $failed_events = 0;
    private $transient_failures = 0;
    private $permanent_failures = 0;

    // WordPress options keys for persistent storage (non-autoload for performance)
    const OPTION_METRICS = 'eventbridge_metrics';
    const OPTION_FAILURE_DETAILS = 'eventbridge_failure_details';
    const OPTION_SETTINGS = 'eventbridge_settings';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5; // Number of failures before showing admin notice

    // IMDS cache transient keys
    const TRANSIENT_IMDS_IDENTITY = 'eventbridge_imds_identity';
    const TRANSIENT_IMDS_CREDENTIALS = 'eventbridge_imds_credentials';
    const TRANSIENT_IMDS_FAILED = 'eventbridge_imds_failed';

    // IMDS configuration
    const IMDS_BASE_URL = 'http://169.254.169.254';
    const IMDS_TIMEOUT = 2;
    const IMDS_IDENTITY_CACHE_DURATION = 3600; // 1 hour for successful lookups
    const IMDS_FAILED_CACHE_DURATION = 300;    // 5 minutes for failed lookups

    // Valid setting values
    const VALID_EVENT_FORMATS = array('legacy', 'envelope');
    const VALID_SEND_MODES = array('sync', 'async');

    // Settings defaults
    private $settings;

    public function __construct()
    {
        // Load settings first
        $this->load_settings();

        // Settings page - always register regardless of credentials
        add_action('admin_menu', array($this, 'add_settings_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));

        $access_key = null;
        $secret_key = null;
        $session_token = null;

        // 認証情報の取得: 1. 定数から、2. インスタンスロールから
        if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') &&
            defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') &&
            !empty(AWS_EVENTBRIDGE_ACCESS_KEY_ID) &&
            !empty(AWS_EVENTBRIDGE_SECRET_ACCESS_KEY)) {
            // 定数から静的認証情報を取得
            $access_key = AWS_EVENTBRIDGE_ACCESS_KEY_ID;
            $secret_key = AWS_EVENTBRIDGE_SECRET_ACCESS_KEY;
        } else {
            // 定数が未定義の場合、EC2インスタンスロールから取得
            $instance_creds = $this->get_instance_credentials();
            if ($instance_creds !== null) {
                $access_key = $instance_creds['AccessKeyId'];
                $secret_key = $instance_creds['SecretAccessKey'];
                $session_token = $instance_creds['Token'];
            }
        }

        // 認証情報が取得できない場合のみエラー
        if (empty($access_key) || empty($secret_key)) {
            add_action('admin_notices', function() {
                ?>
                <div class="notice notice-error">
                    <p><?php esc_html_e('EventBridge Post Events: AWS認証情報が設定されていません。wp-config.phpで定数を定義するか、EC2インスタンスロールを設定してください。', 'eventbridge-post-events'); ?></p>
                </div>
                <?php
            });
            return;
        }

        // リージョンの取得（EC2インスタンスメタデータ、または定数からのフォールバック）
        $identity = $this->get_instance_identity();
        if (!empty($identity['region'])) {
            $this->region = $identity['region'];
        } elseif (defined('AWS_EVENTBRIDGE_REGION') && !empty(AWS_EVENTBRIDGE_REGION)) {
            $this->region = AWS_EVENTBRIDGE_REGION;
        } else {
            add_action('admin_notices', function() {
                ?>
                <div class="notice notice-error">
                    <p><?php esc_html_e('EventBridge Post Events: AWSリージョンを特定できません。EC2以外の環境では、wp-config.phpでAWS_EVENTBRIDGE_REGION定数を定義してください。', 'eventbridge-post-events'); ?></p>
                </div>
                <?php
            });
            return;
        }

        // Store credentials for lazy client initialization
        $this->access_key = $access_key;
        $this->secret_key = $secret_key;
        $this->session_token = $session_token;
        // Note: Client will be initialized after settings are loaded to get event_bus_name
        $this->client = null;

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

        // Handle notice dismissal
        add_action('admin_init', array($this, 'handle_notice_dismissal'));
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
            $this->client = new EventBridgePutEvents(
                $this->access_key,
                $this->secret_key,
                $this->region,
                $this->session_token,
                $event_bus_name
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
     * Priority order: constants first → WordPress options → default values
     *
     * @param string $key Setting key
     * @return mixed Setting value
     */
    public function get_setting($key)
    {
        // Check for constant overrides first (highest priority)
        if ($key === 'event_bus_name' && defined('EVENT_BUS_NAME')) {
            return EVENT_BUS_NAME;
        }
        if ($key === 'event_source_name' && defined('EVENT_SOURCE_NAME')) {
            return EVENT_SOURCE_NAME;
        }
        if ($key === 'aws_region_override' && defined('AWS_REGION_OVERRIDE')) {
            return AWS_REGION_OVERRIDE;
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
            'event_format',
            __('イベント形式', 'eventbridge-post-events'),
            array($this, 'render_event_format_field'),
            'eventbridge-settings',
            'eventbridge_main_section'
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

        // Handle test connection
        add_action('admin_post_eventbridge_test_connection', array($this, 'handle_test_connection'));

        // Handle metrics reset
        add_action('admin_post_eventbridge_reset_metrics', array($this, 'handle_reset_metrics'));
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

        // Sanitize event_format
        $sanitized['event_format'] = isset($input['event_format']) && in_array($input['event_format'], self::VALID_EVENT_FORMATS, true)
            ? $input['event_format']
            : $defaults['event_format'];

        // Sanitize send_mode
        $sanitized['send_mode'] = isset($input['send_mode']) && in_array($input['send_mode'], self::VALID_SEND_MODES, true)
            ? $input['send_mode']
            : $defaults['send_mode'];

        // Sanitize event_bus_name (AWS naming conventions: alphanumeric, hyphens, underscores, dots, max 256 chars)
        if (isset($input['event_bus_name']) && !empty($input['event_bus_name'])) {
            $event_bus_name = sanitize_text_field($input['event_bus_name']);
            // Validate AWS EventBridge bus name pattern
            if (preg_match('/^[a-zA-Z0-9._\-]{1,256}$/', $event_bus_name)) {
                $sanitized['event_bus_name'] = $event_bus_name;
            } else {
                add_settings_error(
                    self::OPTION_SETTINGS,
                    'invalid_event_bus_name',
                    __('Event Bus Name must contain only alphanumeric characters, hyphens, underscores, and dots (max 256 characters).', 'eventbridge-post-events')
                );
                $sanitized['event_bus_name'] = $defaults['event_bus_name'];
            }
        } else {
            $sanitized['event_bus_name'] = $defaults['event_bus_name'];
        }

        // Sanitize event_source_name (AWS naming conventions: reverse domain notation)
        if (isset($input['event_source_name']) && !empty($input['event_source_name'])) {
            $event_source_name = sanitize_text_field($input['event_source_name']);
            // Validate AWS EventBridge source name pattern
            if (preg_match('/^[a-zA-Z0-9._\-]{1,256}$/', $event_source_name)) {
                $sanitized['event_source_name'] = $event_source_name;
            } else {
                add_settings_error(
                    self::OPTION_SETTINGS,
                    'invalid_event_source_name',
                    __('Event Source Name must contain only alphanumeric characters, hyphens, underscores, and dots (max 256 characters).', 'eventbridge-post-events')
                );
                $sanitized['event_source_name'] = $defaults['event_source_name'];
            }
        } else {
            $sanitized['event_source_name'] = $defaults['event_source_name'];
        }

        // Sanitize aws_region_override (AWS region format: us-east-1, etc.)
        if (isset($input['aws_region_override']) && !empty($input['aws_region_override'])) {
            $aws_region = sanitize_text_field($input['aws_region_override']);
            // Validate AWS region pattern
            if (preg_match('/^[a-z]{2}-[a-z]+-\d{1}$/', $aws_region)) {
                $sanitized['aws_region_override'] = $aws_region;
            } else {
                add_settings_error(
                    self::OPTION_SETTINGS,
                    'invalid_aws_region',
                    __('AWS Region Override must be in valid format (e.g., us-east-1, ap-northeast-1).', 'eventbridge-post-events')
                );
                $sanitized['aws_region_override'] = $defaults['aws_region_override'];
            }
        } else {
            $sanitized['aws_region_override'] = $defaults['aws_region_override'];
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
            <?php esc_html_e('These settings can be overridden by defining constants in wp-config.php (EVENT_BUS_NAME, EVENT_SOURCE_NAME, AWS_REGION_OVERRIDE). Constants take precedence over admin settings.', 'eventbridge-post-events'); ?>
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
                <?php esc_html_e('The name of the EventBridge event bus (e.g., default, custom-bus). Only alphanumeric characters, hyphens, underscores, and dots allowed (max 256 characters).', 'eventbridge-post-events'); ?>
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
                <?php esc_html_e('The source identifier for events (e.g., wordpress, com.example.app). Use reverse domain notation. Only alphanumeric characters, hyphens, underscores, and dots allowed (max 256 characters).', 'eventbridge-post-events'); ?>
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
        $is_constant_override = defined('AWS_REGION_OVERRIDE');
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
                <strong><?php esc_html_e('Overridden by AWS_REGION_OVERRIDE constant:', 'eventbridge-post-events'); ?></strong>
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
            $test_result = get_transient('eventbridge_test_result');
            if ($test_result) {
                foreach ($test_result as $error) {
                    printf(
                        '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
                        esc_attr($error['type']),
                        esc_html($error['message'])
                    );
                }
                delete_transient('eventbridge_test_result');
            }

            $metrics_result = get_transient('eventbridge_metrics_result');
            if ($metrics_result) {
                foreach ($metrics_result as $error) {
                    printf(
                        '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
                        esc_attr($error['type']),
                        esc_html($error['message'])
                    );
                }
                delete_transient('eventbridge_metrics_result');
            }

            // Display current metrics
            $metrics = get_option(self::OPTION_METRICS, array(
                'successful_events' => 0,
                'failed_events' => 0,
                'transient_failures' => 0,
                'permanent_failures' => 0
            ));
            $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array('last_failure_time' => null, 'messages' => array()));

            // Determine credential source
            $credential_source = 'Environment Variables';
            if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && !empty(AWS_EVENTBRIDGE_ACCESS_KEY_ID)) {
                $credential_source = 'Constants (wp-config.php)';
            }

            // Get current region (considering override)
            $current_region = $this->get_setting('aws_region_override');
            if (empty($current_region)) {
                $current_region = $this->region;
            }
            ?>

            <!-- Diagnostics & Status Section -->
            <div class="card" style="max-width:800px;margin-bottom:20px;">
                <h2><?php esc_html_e('Diagnostics & Status', 'eventbridge-post-events'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('Detected Region', 'eventbridge-post-events'); ?></th>
                        <td><code><?php echo esc_html($current_region ?: __('Not detected', 'eventbridge-post-events')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Credential Source', 'eventbridge-post-events'); ?></th>
                        <td><code><?php echo esc_html($credential_source); ?></code></td>
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

                <p>
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
                </p>
            </div>

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
     * IMDSv2トークンを取得する
     *
     * @return string|null トークン、または取得失敗時はnull
     */
    private function get_imds_token()
    {
        $token_response = wp_remote_request(self::IMDS_BASE_URL . '/latest/api/token', array(
            'method' => 'PUT',
            'headers' => array('X-aws-ec2-metadata-token-ttl-seconds' => '21600'),
            'timeout' => self::IMDS_TIMEOUT,
        ));

        if (is_wp_error($token_response) || wp_remote_retrieve_response_code($token_response) !== 200) {
            return null;
        }

        $token = wp_remote_retrieve_body($token_response);
        return !empty($token) ? $token : null;
    }

    /**
     * インスタンスメタデータから識別情報を取得する（IMDSv2対応、キャッシュ付き）
     *
     * IMDSv2はトークンベース認証を使用し、SSRF攻撃に対してより安全です。
     * 結果はWordPress transientにキャッシュされ、毎ページロードでのHTTPリクエストを回避します。
     * EC2以外の環境では空配列を返します。
     *
     * @return array インスタンス識別情報
     */
    private function get_instance_identity()
    {
        // キャッシュをチェック
        $cached = get_transient(self::TRANSIENT_IMDS_IDENTITY);
        if ($cached !== false) {
            return $cached;
        }

        // 失敗キャッシュをチェック（EC2以外の環境で無駄なリクエストを避ける）
        if (get_transient(self::TRANSIENT_IMDS_FAILED) !== false) {
            return array();
        }

        // IMDSv2トークンを取得
        $token = $this->get_imds_token();
        if ($token === null) {
            // 失敗をキャッシュ
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        // トークンを使ってメタデータを取得
        $response = wp_remote_get(self::IMDS_BASE_URL . '/latest/dynamic/instance-identity/document', array(
            'headers' => array('X-aws-ec2-metadata-token' => $token),
            'timeout' => self::IMDS_TIMEOUT,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return array();
        }

        // 成功をキャッシュ
        set_transient(self::TRANSIENT_IMDS_IDENTITY, $data, self::IMDS_IDENTITY_CACHE_DURATION);
        return $data;
    }

    /**
     * EC2インスタンスロールから一時的な認証情報を取得する（IMDSv2対応、キャッシュ付き）
     *
     * 認証情報の有効期限を考慮してキャッシュします。
     * 有効期限の5分前に新しい認証情報を取得します。
     *
     * @return array|null 認証情報配列（AccessKeyId, SecretAccessKey, Token, Expiration）、または取得失敗時はnull
     */
    private function get_instance_credentials()
    {
        // キャッシュをチェック
        $cached = get_transient(self::TRANSIENT_IMDS_CREDENTIALS);
        if ($cached !== false) {
            // 有効期限の5分前かどうかをチェック
            if (isset($cached['Expiration'])) {
                $expiration = strtotime($cached['Expiration']);
                $now = time();
                // 有効期限の5分前より早ければキャッシュを使用
                if ($expiration - $now > 300) {
                    return $cached;
                }
                // 有効期限が近いのでキャッシュを削除して再取得
                delete_transient(self::TRANSIENT_IMDS_CREDENTIALS);
            } else {
                return $cached;
            }
        }

        // 失敗キャッシュをチェック
        if (get_transient(self::TRANSIENT_IMDS_FAILED) !== false) {
            return null;
        }

        // IMDSv2トークンを取得
        $token = $this->get_imds_token();
        if ($token === null) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        // IAMロール名を取得
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

        // 認証情報を取得
        $creds_response = wp_remote_get(self::IMDS_BASE_URL . '/latest/meta-data/iam/security-credentials/' . $role_name, array(
            'headers' => array('X-aws-ec2-metadata-token' => $token),
            'timeout' => self::IMDS_TIMEOUT,
        ));

        if (is_wp_error($creds_response) || wp_remote_retrieve_response_code($creds_response) !== 200) {
            set_transient(self::TRANSIENT_IMDS_FAILED, true, self::IMDS_FAILED_CACHE_DURATION);
            return null;
        }

        $creds = json_decode(wp_remote_retrieve_body($creds_response), true);

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

        // 有効期限に基づいてキャッシュ期間を計算（有効期限の5分前まで）
        $cache_duration = self::IMDS_IDENTITY_CACHE_DURATION;
        if (isset($creds['Expiration'])) {
            $expiration = strtotime($creds['Expiration']);
            $now = time();
            $time_until_expiry = $expiration - $now - 300; // 5分のマージン
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
        $event_format = $this->get_setting('event_format');

        if ($event_format === 'envelope') {
            $correlation_id = $is_delete_event
                ? $this->get_existing_correlation_id($post_id)
                : $this->get_or_create_correlation_id($post_id);
            return $this->create_event_envelope($event_data, $correlation_id);
        }

        // Legacy format - send event_data directly
        return $event_data;
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
        $result = $this->get_client()->sendEvent($source, $detailType, $detail);
        $this->track_event_result($result);

        if (!$result['success']) {
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
        $postId = isset($detail['id']) ? $detail['id'] : null;
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

        // Send test event
        $test_event_data = array(
            'test' => true,
            'timestamp' => current_time('c'),
            'message' => 'EventBridge connection test'
        );

        $test_event_payload = array(
            'event_id' => wp_generate_uuid4(),
            'event_timestamp' => current_time('c'),
            'event_version' => '1.0',
            'source_system' => get_bloginfo('url'),
            'data' => $test_event_data
        );

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
}

// インスタンスの作成
new EventBridgePostEvents();