<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://example.com/eventbridge-post-events
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 1.0
Author: Your Name
Author URI: https://example.com
*/

// EventBridge設定
define('EVENT_BUS_NAME', 'wp-kyoto'); // デフォルトのイベントバスを使用する場合
define('EVENT_SOURCE_NAME', 'wordpress'); // デフォルトのイベントバスを使用する場合

class EventBridgePutEvents
{
    private $accessKeyId;
    private $secretAccessKey;
    private $region;
    private $endpoint;
    private $serviceName;

    public function __construct($accessKeyId, $secretAccessKey, $region)
    {
        $this->accessKeyId = $accessKeyId;
        $this->secretAccessKey = $secretAccessKey;
        $this->region = $region;
        $this->endpoint = 'events.' . $region . '.amazonaws.com';
        $this->serviceName = 'events';
    }

    public function sendEvent($source, $detailType, $detail)
    {
        $method = 'POST';
        $path = '/';
        $payload = json_encode(array(
            'Entries' => array(
                array(
                    'EventBusName' => EVENT_BUS_NAME,
                    'Source' => $source,
                    'DetailType' => $detailType,
                    'Detail' => json_encode($detail),
                ),
            ),
        ));

        $now = new DateTime();
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
                    EVENT_BUS_NAME,
                    $timestamp
                ));
            }

            $response = wp_remote_request("https://{$this->endpoint}{$path}", array(
                'method' => $method,
                'headers' => $headers,
                'body' => $payload,
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

        // All retries exhausted - log comprehensive error details (excluding sensitive event data)
        error_log(sprintf(
            '[EventBridge] FAILED after %d attempts - DetailType: %s, PostID: %s, LastError: %s, LastResponseCode: %s, Region: %s, EventBus: %s, Timestamp: %s',
            $maxRetries + 1,
            $detailType,
            $postId,
            $lastError,
            $lastResponseCode,
            $this->region,
            EVENT_BUS_NAME,
            $timestamp
        ));

        // Return array format for metrics tracking compatibility
        return array('success' => false, 'error' => $lastError, 'response' => null);
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

    // In-memory counters for tracking metrics
    private $successful_events = 0;
    private $failed_events = 0;

    // WordPress options keys for persistent storage (non-autoload for performance)
    const OPTION_METRICS = 'eventbridge_metrics';
    const OPTION_FAILURE_DETAILS = 'eventbridge_failure_details';
    const OPTION_SETTINGS = 'eventbridge_settings';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5; // Number of failures before showing admin notice

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

        // AWS認証情報の検証（定義されていて、空の値ではないか確認）
        if (empty(constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID')) || empty(constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY'))) {
            add_action('admin_notices', function() {
                ?>
                <div class="notice notice-error">
                    <p><?php esc_html_e('EventBridge Post Events: AWS認証情報が設定されていません。wp-config.phpでAWS_EVENTBRIDGE_ACCESS_KEY_IDとAWS_EVENTBRIDGE_SECRET_ACCESS_KEY定数を定義してください。', 'eventbridge-post-events'); ?></p>
                </div>
                <?php
            });
            return;
        }

        $identity = $this->get_instance_identity();
        $this->region = $identity['region'];
        $this->client = new EventBridgePutEvents(AWS_EVENTBRIDGE_ACCESS_KEY_ID, AWS_EVENTBRIDGE_SECRET_ACCESS_KEY, $this->region);

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
     * Get default settings
     *
     * @return array Default settings
     */
    private function get_default_settings()
    {
        return array(
            'event_format' => 'envelope', // 'legacy' or 'envelope'
            'send_mode' => 'async',       // 'sync' or 'async'
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
     * Get a specific setting value
     *
     * @param string $key Setting key
     * @return mixed Setting value
     */
    public function get_setting($key)
    {
        return isset($this->settings[$key]) ? $this->settings[$key] : null;
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
     * Register settings with WordPress Settings API
     */
    public function register_settings()
    {
        register_setting(
            'eventbridge_settings_group',
            self::OPTION_SETTINGS,
            array($this, 'sanitize_settings')
        );

        add_settings_section(
            'eventbridge_main_section',
            __('イベント送信設定', 'eventbridge-post-events'),
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

        return $sanitized;
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
            // Display current metrics
            $metrics = get_option(self::OPTION_METRICS, array('successful_events' => 0, 'failed_events' => 0));
            ?>
            <div class="card" style="max-width:600px;margin-bottom:20px;">
                <h2><?php esc_html_e('送信統計', 'eventbridge-post-events'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('成功', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:green;"><?php echo esc_html($metrics['successful_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('失敗', 'eventbridge-post-events'); ?></th>
                        <td><strong style="color:<?php echo $metrics['failed_events'] > 0 ? 'red' : 'inherit'; ?>;"><?php echo esc_html($metrics['failed_events']); ?></strong></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('リージョン', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html($this->region ?: __('未設定', 'eventbridge-post-events')); ?></td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('イベントバス', 'eventbridge-post-events'); ?></th>
                        <td><?php echo esc_html(EVENT_BUS_NAME); ?></td>
                    </tr>
                </table>
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
     * Load metrics from WordPress options table
     */
    private function load_metrics()
    {
        $metrics = get_option(self::OPTION_METRICS, array(
            'successful_events' => 0,
            'failed_events' => 0
        ));

        $this->successful_events = (int) $metrics['successful_events'];
        $this->failed_events = (int) $metrics['failed_events'];
    }

    /**
     * Save metrics to WordPress options table
     * Uses single serialized option with autoload=false for performance
     */
    private function save_metrics()
    {
        $metrics = array(
            'successful_events' => $this->successful_events,
            'failed_events' => $this->failed_events
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
     */
    private function record_failure($error_message)
    {
        // Increment in-memory counter
        $this->failed_events++;

        // Read, mutate, and write failure details in one operation
        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array(
            'last_failure_time' => null,
            'messages' => array()
        ));

        $failure_details['last_failure_time'] = current_time('mysql');
        $failure_details['messages'][] = array(
            'time' => current_time('mysql'),
            'message' => $error_message
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
            $this->record_failure($error_message);
        }
    }

    /**
     * インスタンスメタデータから識別情報を取得する
     *
     * @return array インスタンス識別情報
     */
    private function get_instance_identity()
    {
        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');
        if (is_wp_error($response)) {
            return array();
        }
        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
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
            $correlation_id = wp_generate_uuid4();
            $added = add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

            // If add_post_meta returned false, another request wrote the meta first
            // Re-read the actual value that was stored
            if ($added === false) {
                $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
            }
        }

        return $correlation_id;
    }

    /**
     * Prepare event payload based on format setting
     *
     * @param array $event_data イベントデータ
     * @param int $post_id 投稿ID
     * @return array イベントペイロード
     */
    private function prepare_event_payload($event_data, $post_id)
    {
        $event_format = $this->get_setting('event_format');

        if ($event_format === 'envelope') {
            $correlation_id = $this->get_or_create_correlation_id($post_id);
            return $this->create_event_envelope($event_data, $correlation_id);
        }

        // Legacy format - send event_data directly
        return $event_data;
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
        if ($new_status !== 'publish') {
            return;
        }

        $event_name = $new_status === $old_status ? 'post.updated' : 'post.' . $new_status . 'ed'; // post.published、post.drafted など
        $permalink = get_permalink($post->ID);
        $post_type = $post->post_type;

        // Get REST API URL using rest_base from post type object
        $post_type_obj = get_post_type_object($post_type);
        $rest_base = !empty($post_type_obj->rest_base) ? $post_type_obj->rest_base : $post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $rest_base . '/' . $post->ID);

        $event_data = array(
            'id' => (string)$post->ID,
            'title' => $post->post_title,
            'excerpt' => $post->post_excerpt,
            'status' => $new_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type,
            'previous_status' => $old_status
        );

        $event_payload = $this->prepare_event_payload($event_data, $post->ID);
        $this->dispatch_event(EVENT_SOURCE_NAME, $event_name, $event_payload);
    }

    /**
     * 投稿削除のイベントをEventBridgeに送信する
     *
     * @param int $post_id 投稿ID
     */
    public function send_delete_post_event($post_id)
    {
        $event_name = 'post.deleted';

        $event_data = array(
            'id' => (string)$post_id
        );

        $event_payload = $this->prepare_event_payload($event_data, $post_id);
        $this->dispatch_event(EVENT_SOURCE_NAME, $event_name, $event_payload);
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
        $result = $this->client->sendEvent($source, $detailType, $detail);
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
        wp_schedule_single_event(time(), 'eventbridge_async_send_event', array(EVENT_SOURCE_NAME, $event_name, $event_data));
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
                <li><?php printf(esc_html__('Verify EventBridge event bus "%s" exists in region "%s"', 'eventbridge-post-events'), esc_html(EVENT_BUS_NAME), esc_html($this->region)); ?></li>
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
}

/**
 * Plugin activation callback
 * Initializes default options and validates AWS configuration
 */
function eventbridge_post_events_activate()
{
    // Initialize metrics with default values
    $default_metrics = array(
        'successful_events' => 0,
        'failed_events' => 0
    );
    add_option('eventbridge_metrics', $default_metrics, '', false);

    // Initialize settings with default values
    $default_settings = array(
        'event_format' => 'envelope',
        'send_mode' => 'async'
    );
    add_option('eventbridge_settings', $default_settings, '', true);

    // Validate AWS credentials
    $activation_errors = array();
    $activation_warnings = array();

    if (!defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') || empty(constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID'))) {
        $activation_errors[] = 'AWS_EVENTBRIDGE_ACCESS_KEY_ID is not defined or empty in wp-config.php';
    }

    if (!defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') || empty(constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY'))) {
        $activation_errors[] = 'AWS_EVENTBRIDGE_SECRET_ACCESS_KEY is not defined or empty in wp-config.php';
    }

    // Validate region detection
    if (empty($activation_errors)) {
        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
            'timeout' => 5
        ));

        if (is_wp_error($response)) {
            $activation_warnings[] = sprintf(
                'Unable to detect AWS region from instance metadata: %s. Please ensure the plugin is running on an EC2 instance or configure region manually.',
                $response->get_error_message()
            );
        } else {
            $body = wp_remote_retrieve_body($response);
            $identity = json_decode($body, true);

            if (empty($identity['region'])) {
                $activation_warnings[] = 'AWS region could not be detected from instance metadata. Please ensure the plugin is running on an EC2 instance with proper IAM role.';
            } else {
                // Region detected successfully - log for confirmation
                error_log(sprintf('[EventBridge] Plugin activated. Region detected: %s', $identity['region']));
            }
        }
    }

    // Store activation errors/warnings for display
    if (!empty($activation_errors)) {
        update_option('eventbridge_activation_errors', $activation_errors, false);
        // Deactivate the plugin if there are critical errors
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            '<h1>EventBridge Post Events - Activation Failed</h1>' .
            '<p><strong>The following errors prevented plugin activation:</strong></p>' .
            '<ul><li>' . implode('</li><li>', array_map('esc_html', $activation_errors)) . '</li></ul>' .
            '<p>Please configure the required AWS credentials in wp-config.php:</p>' .
            '<pre>define(\'AWS_EVENTBRIDGE_ACCESS_KEY_ID\', \'your-access-key-id\');<br>' .
            'define(\'AWS_EVENTBRIDGE_SECRET_ACCESS_KEY\', \'your-secret-access-key\');</pre>' .
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
    $cron_array = _get_cron_array();

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
register_activation_hook(__FILE__, 'eventbridge_post_events_activate');
register_deactivation_hook(__FILE__, 'eventbridge_post_events_deactivate');

// インスタンスの作成
new EventBridgePostEvents();