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
// これらの定数はwp-config.phpで定義してください
// define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'your-access-key-id');
// define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'your-secret-access-key');
// define('AWS_EVENTBRIDGE_REGION', 'ap-northeast-1');
// define('EVENT_BUS_NAME', 'wp-kyoto');
// define('EVENT_SOURCE_NAME', 'wordpress');

if (!defined('EVENT_BUS_NAME')) {
    define('EVENT_BUS_NAME', 'default');
}
if (!defined('EVENT_SOURCE_NAME')) {
    define('EVENT_SOURCE_NAME', 'wordpress');
}
if (!defined('AWS_EVENTBRIDGE_REGION')) {
    define('AWS_EVENTBRIDGE_REGION', 'ap-northeast-1');
}

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
            'timeout' => 10,
        ));

        if (is_wp_error($response)) {
            error_log('EventBridge API Error: ' . $response->get_error_message());
            return false;
        }

        $responseBody = wp_remote_retrieve_body($response);
        $statusCode = wp_remote_retrieve_response_code($response);
        $data = json_decode($responseBody, true);

        if ($statusCode !== 200) {
            error_log('EventBridge API Error (HTTP ' . $statusCode . '): ' . $responseBody);
            return false;
        }

        if (!empty($data['FailedEntryCount']) && $data['FailedEntryCount'] > 0) {
            error_log('EventBridge Failed Entries: ' . print_r($data['Entries'], true));
            return false;
        }

        error_log('EventBridge Event Sent Successfully: ' . $payload);
        return true;
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

    public function __construct()
    {
        // 認証情報のチェック
        if (!defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') || !defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            add_action('admin_notices', array($this, 'show_config_notice'));
            return;
        }

        // リージョンの取得（優先順位: 定数 > インスタンスメタデータ > デフォルト）
        if (defined('AWS_EVENTBRIDGE_REGION')) {
            $this->region = AWS_EVENTBRIDGE_REGION;
        } else {
            $identity = $this->get_instance_identity();
            $this->region = !empty($identity['region']) ? $identity['region'] : 'ap-northeast-1';
        }

        $this->client = new EventBridgePutEvents(AWS_EVENTBRIDGE_ACCESS_KEY_ID, AWS_EVENTBRIDGE_SECRET_ACCESS_KEY, $this->region);

        // 投稿を新規公開、更新した際のアクション
        add_action('transition_post_status', array($this, 'send_post_event'), 10, 3);

        // 投稿を削除した際のアクション
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);
    }

    /**
     * 設定が不足している場合の管理画面通知
     */
    public function show_config_notice()
    {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>EventBridge Post Events:</strong> AWS認証情報が設定されていません。wp-config.phpに以下の定数を追加してください：<br>';
        echo '<code>define(\'AWS_EVENTBRIDGE_ACCESS_KEY_ID\', \'your-access-key-id\');</code><br>';
        echo '<code>define(\'AWS_EVENTBRIDGE_SECRET_ACCESS_KEY\', \'your-secret-access-key\');</code>';
        echo '</p></div>';
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
     * @param int $post_id 投稿ID
     * @param WP_Post $post 投稿オブジェクト (新規公開の場合)
     * @param WP_Post $post_before 更新前の投稿オブジェクト (更新の場合)
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

		$this->client->sendEvent(EVENT_SOURCE_NAME, $event_name, $event_data);
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
		$this->client->sendEvent(EVENT_SOURCE_NAME, $event_name, $event_data);
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
}

// インスタンスの作成
new EventBridgePostEvents();