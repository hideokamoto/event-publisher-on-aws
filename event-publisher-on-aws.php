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

        $response = wp_remote_request("https://{$this->endpoint}{$path}", array(
            'method' => $method,
            'headers' => $headers,
            'body' => $payload,
        ));

        if (!is_wp_error($response)) {
            $responseBody = wp_remote_retrieve_body($response);
            $data = json_decode($responseBody, true);
            $statusCode = wp_remote_retrieve_response_code($response);

            error_log('EventBridge Response: ' . print_r($data, true));

            // Check for failures in the response
            if ($statusCode === 200 && isset($data['FailedEntryCount']) && $data['FailedEntryCount'] === 0) {
                return array('success' => true, 'response' => $data);
            } else {
                $errorMessage = isset($data['Entries'][0]['ErrorMessage']) ? $data['Entries'][0]['ErrorMessage'] : 'Unknown error';
                error_log('EventBridge Failed: ' . $errorMessage);
                return array('success' => false, 'error' => $errorMessage, 'response' => $data);
            }
        } else {
            $errorMessage = $response->get_error_message();
            error_log('EventBridge Error: ' . $errorMessage);
            return array('success' => false, 'error' => $errorMessage);
        }
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

    // WordPress options keys for persistent storage
    const OPTION_SUCCESS_COUNT = 'eventbridge_success_count';
    const OPTION_FAILURE_COUNT = 'eventbridge_failure_count';
    const OPTION_LAST_FAILURE_TIME = 'eventbridge_last_failure_time';
    const OPTION_FAILURE_MESSAGES = 'eventbridge_failure_messages';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5; // Number of failures before showing admin notice

    public function __construct()
    {
        $identity = $this->get_instance_identity();
        $this->region = $identity['region'];
		$this->client = new EventBridgePutEvents(AWS_EVENTBRIDGE_ACCESS_KEY_ID, AWS_EVENTBRIDGE_SECRET_ACCESS_KEY, $this->region);

        // Load metrics from WordPress options
        $this->load_metrics();

        // 投稿を新規公開、更新した際のアクション
        add_action('transition_post_status', array($this, 'send_post_event'), 10, 3);

        // 投稿を削除した際のアクション
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);

        // Admin notice for failures
        add_action('admin_notices', array($this, 'display_failure_notice'));

        // Handle notice dismissal
        add_action('admin_init', array($this, 'handle_notice_dismissal'));
    }

    /**
     * Load metrics from WordPress options table
     */
    private function load_metrics()
    {
        $this->successful_events = (int) get_option(self::OPTION_SUCCESS_COUNT, 0);
        $this->failed_events = (int) get_option(self::OPTION_FAILURE_COUNT, 0);
    }

    /**
     * Save metrics to WordPress options table
     */
    private function save_metrics()
    {
        update_option(self::OPTION_SUCCESS_COUNT, $this->successful_events);
        update_option(self::OPTION_FAILURE_COUNT, $this->failed_events);
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
     *
     * @param string $error_message The error message
     */
    private function record_failure($error_message)
    {
        $this->failed_events++;
        update_option(self::OPTION_LAST_FAILURE_TIME, current_time('mysql'));

        // Store recent failure messages (keep last 10)
        $failure_messages = get_option(self::OPTION_FAILURE_MESSAGES, array());
        $failure_messages[] = array(
            'time' => current_time('mysql'),
            'message' => $error_message
        );

        // Keep only the last 10 failure messages
        if (count($failure_messages) > 10) {
            $failure_messages = array_slice($failure_messages, -10);
        }

        update_option(self::OPTION_FAILURE_MESSAGES, $failure_messages);
        $this->save_metrics();
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
        $event_name = $new_status === $old_status ? 'post.updated' :'post.' . $new_status . 'ed'; // post.published、post.drafted など
        $permalink = get_permalink($post->ID);
        $post_type = $post->post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $post_type . 's/' . $post->ID);

        $event_data = array(
            'id' => (string)$post->ID,
            'title' => $post->post_title,
            'status' => $new_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type,
            'previous_status' => $old_status
        );

		$result = $this->client->sendEvent(EVENT_SOURCE_NAME, $event_name, $event_data);

        // Track metrics based on result
        if ($result['success']) {
            $this->record_success();
        } else {
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $this->record_failure($error_message);
        }
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
		$result = $this->client->sendEvent(EVENT_SOURCE_NAME, $event_name, $event_data);

        // Track metrics based on result
        if ($result['success']) {
            $this->record_success();
        } else {
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $this->record_failure($error_message);
        }
    }

    /**
     * 失敗イベントをEventBridgeに送信する
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

		$this->client->sendEvent(EVENT_SOURCE_NAME, $event_name, $event_data);
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

        // Get failure details
        $last_failure_time = get_option(self::OPTION_LAST_FAILURE_TIME, 'Unknown');
        $failure_messages = get_option(self::OPTION_FAILURE_MESSAGES, array());
        $success_count = $this->successful_events;

        // Get most recent error message
        $recent_error = 'Unknown error';
        if (!empty($failure_messages)) {
            $last_message = end($failure_messages);
            $recent_error = $last_message['message'];
        }

        // Create dismiss URL
        $dismiss_url = add_query_arg(array(
            'eventbridge_dismiss_notice' => '1',
            'eventbridge_nonce' => wp_create_nonce('eventbridge_dismiss_notice')
        ));

        // Display the notice
        ?>
        <div class="notice notice-error is-dismissible">
            <h3>EventBridge Publishing Failures Detected</h3>
            <p><strong>Action Required:</strong> EventBridge event publishing is experiencing failures.</p>
            <ul>
                <li><strong>Failed Events:</strong> <?php echo esc_html($failure_count); ?></li>
                <li><strong>Successful Events:</strong> <?php echo esc_html($success_count); ?></li>
                <li><strong>Last Failure:</strong> <?php echo esc_html($last_failure_time); ?></li>
                <li><strong>Recent Error:</strong> <?php echo esc_html($recent_error); ?></li>
            </ul>
            <p>
                <strong>Recommended Actions:</strong>
            </p>
            <ol>
                <li>Check your AWS EventBridge credentials (AWS_EVENTBRIDGE_ACCESS_KEY_ID and AWS_EVENTBRIDGE_SECRET_ACCESS_KEY)</li>
                <li>Verify EventBridge event bus "<?php echo esc_html(EVENT_BUS_NAME); ?>" exists in region "<?php echo esc_html($this->region); ?>"</li>
                <li>Review error logs: <a href="<?php echo esc_url(admin_url('tools.php?page=error-log')); ?>">View Error Log</a></li>
                <li>Ensure IAM permissions include "events:PutEvents" for the event bus</li>
            </ol>
            <p>
                <a href="<?php echo esc_url($dismiss_url); ?>" class="button button-primary">Dismiss for 24 hours</a>
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

        // Verify nonce
        if (!isset($_GET['eventbridge_nonce']) || !wp_verify_nonce($_GET['eventbridge_nonce'], 'eventbridge_dismiss_notice')) {
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
        update_option(self::OPTION_FAILURE_COUNT, 0);

        // Redirect to remove query parameters
        wp_redirect(remove_query_arg(array('eventbridge_dismiss_notice', 'eventbridge_nonce')));
        exit;
    }
}

// インスタンスの作成
new EventBridgePostEvents();