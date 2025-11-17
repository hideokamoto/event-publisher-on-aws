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

/**
 * IMDSv2を使ってEC2インスタンスロールから認証情報を取得するクラス
 */
class AWS_IMDS_Credentials
{
    private $credentials = null;
    private $expiresAt = null;
    private $imdsEndpoint = 'http://169.254.169.254';

    /**
     * 認証情報を取得（キャッシュ機能付き）
     *
     * @return array|false 認証情報の配列、失敗時はfalse
     */
    public function getCredentials()
    {
        // キャッシュが有効かチェック（有効期限の5分前に更新）
        if ($this->credentials && $this->expiresAt && time() < ($this->expiresAt - 300)) {
            return $this->credentials;
        }

        // IMDSv2トークンを取得
        $token = $this->getImdsToken();
        if (!$token) {
            return false;
        }

        // ロール名を取得
        $roleName = $this->getIamRole($token);
        if (!$roleName) {
            return false;
        }

        // 認証情報を取得
        $credentials = $this->getIamCredentials($token, $roleName);
        if ($credentials) {
            $this->credentials = $credentials;
            $this->expiresAt = strtotime($credentials['Expiration']);
        }

        return $credentials;
    }

    /**
     * インスタンス識別情報を取得（IMDSv2使用）
     *
     * @return array|false インスタンス識別情報の配列、失敗時はfalse
     */
    public function getInstanceIdentity()
    {
        // IMDSv2トークンを取得
        $token = $this->getImdsToken();
        if (!$token) {
            return false;
        }

        $response = wp_remote_get("{$this->imdsEndpoint}/latest/dynamic/instance-identity/document", array(
            'headers' => array(
                'X-aws-ec2-metadata-token' => $token,
            ),
            'timeout' => 1,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (json_last_error() !== JSON_ERROR_NONE || !$data) {
            return false;
        }

        return $data;
    }

    /**
     * IMDSv2トークンを取得
     *
     * @return string|false トークン、失敗時はfalse
     */
    private function getImdsToken()
    {
        $response = wp_remote_request("{$this->imdsEndpoint}/latest/api/token", array(
            'method' => 'PUT',
            'headers' => array(
                'X-aws-ec2-metadata-token-ttl-seconds' => '21600',
            ),
            'timeout' => 1,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        return wp_remote_retrieve_body($response);
    }

    /**
     * IAMロール名を取得
     *
     * @param string $token IMDSv2トークン
     * @return string|false ロール名、失敗時はfalse
     */
    private function getIamRole($token)
    {
        $response = wp_remote_get("{$this->imdsEndpoint}/latest/meta-data/iam/security-credentials/", array(
            'headers' => array(
                'X-aws-ec2-metadata-token' => $token,
            ),
            'timeout' => 1,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        return trim(wp_remote_retrieve_body($response));
    }

    /**
     * IAM認証情報を取得
     *
     * @param string $token IMDSv2トークン
     * @param string $roleName IAMロール名
     * @return array|false 認証情報の配列、失敗時はfalse
     */
    private function getIamCredentials($token, $roleName)
    {
        $response = wp_remote_get("{$this->imdsEndpoint}/latest/meta-data/iam/security-credentials/{$roleName}", array(
            'headers' => array(
                'X-aws-ec2-metadata-token' => $token,
            ),
            'timeout' => 1,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!$data || !isset($data['AccessKeyId']) || !isset($data['SecretAccessKey'])) {
            return false;
        }

        return $data;
    }
}

class EventBridgePutEvents
{
    private $accessKeyId;
    private $secretAccessKey;
    private $sessionToken;
    private $region;
    private $endpoint;
    private $serviceName;

    public function __construct($accessKeyId, $secretAccessKey, $region, $sessionToken = null)
    {
        $this->accessKeyId = $accessKeyId;
        $this->secretAccessKey = $secretAccessKey;
        $this->sessionToken = $sessionToken;
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

        // セッショントークンがある場合はヘッダーに含める
        if ($this->sessionToken) {
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

        // セッショントークンがある場合はヘッダーに追加
        if ($this->sessionToken) {
            $headers['X-Amz-Security-Token'] = $this->sessionToken;
        }

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

        $statusCode = wp_remote_retrieve_response_code($response);
        $responseBody = wp_remote_retrieve_body($response);

        if ($statusCode !== 200) {
            error_log('EventBridge API Error (HTTP ' . $statusCode . '): ' . $responseBody);
            return false;
        }

        $data = json_decode($responseBody, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('EventBridge JSON Decode Error: ' . json_last_error_msg() . ' - Response: ' . $responseBody);
            return false;
        }

        if (!$data) {
            error_log('EventBridge Invalid Response: ' . $responseBody);
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
    private $imdsProvider;

    public function __construct()
    {
        // 認証情報の取得（優先順位: wp-config.php定数 > インスタンスロール）
        $accessKeyId = null;
        $secretAccessKey = null;
        $sessionToken = null;

        if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            // wp-config.phpで定義された認証情報を使用
            $accessKeyId = AWS_EVENTBRIDGE_ACCESS_KEY_ID;
            $secretAccessKey = AWS_EVENTBRIDGE_SECRET_ACCESS_KEY;
            error_log('EventBridge: Using credentials from wp-config.php');
        } else {
            // インスタンスロールから認証情報を取得
            $this->imdsProvider = new AWS_IMDS_Credentials();
            $credentials = $this->imdsProvider->getCredentials();

            if ($credentials) {
                $accessKeyId = $credentials['AccessKeyId'];
                $secretAccessKey = $credentials['SecretAccessKey'];
                $sessionToken = isset($credentials['Token']) ? $credentials['Token'] : null;
                error_log('EventBridge: Using credentials from EC2 instance role');
            } else {
                // 認証情報が取得できない場合は警告を表示
                add_action('admin_notices', array($this, 'show_config_notice'));
                return;
            }
        }

        // リージョンの取得（優先順位: 定数 > インスタンスメタデータ > デフォルト）
        if (defined('AWS_EVENTBRIDGE_REGION')) {
            $this->region = AWS_EVENTBRIDGE_REGION;
        } else {
            // IMDSv2を使ってリージョンを取得
            if (!$this->imdsProvider) {
                $this->imdsProvider = new AWS_IMDS_Credentials();
            }
            $identity = $this->imdsProvider->getInstanceIdentity();
            $this->region = !empty($identity['region']) ? $identity['region'] : 'ap-northeast-1';
        }

        $this->client = new EventBridgePutEvents($accessKeyId, $secretAccessKey, $this->region, $sessionToken);

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
        printf(
            '<div class="notice notice-error"><p>' .
            '<strong>EventBridge Post Events:</strong> AWS認証情報が設定されていません。<br>' .
            '以下のいずれかの方法で認証情報を設定してください：<br><br>' .
            '<strong>方法1:</strong> wp-config.phpに定数を追加<br>' .
            '<code>%s</code><br>' .
            '<code>%s</code><br><br>' .
            '<strong>方法2:</strong> EC2インスタンスロールを使用（EC2上で動作している場合）' .
            '</p></div>',
            esc_html("define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'your-access-key-id');"),
            esc_html("define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'your-secret-access-key');")
        );
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

        // REST APIのベースURLを取得（カスタム投稿タイプのrest_baseに対応）
        $post_type_obj = get_post_type_object($post_type);
        $rest_base = ($post_type_obj && !empty($post_type_obj->rest_base)) ? $post_type_obj->rest_base : $post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $rest_base . '/' . $post->ID);

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