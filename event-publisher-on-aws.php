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

class EventBridgePostEvents
{
    private $identity;
    private $region;
    private $credentials;

    public function __construct()
    {
        $identity = $this->_get_instance_identity();
        $this->region = $identity['region'];
        $this->credentials = $this->_get_instance_credentials($identity['instanceProfileArn']);

        // 投稿を新規公開、更新、削除した際のアクション
        add_action('publish_post', array($this, 'send_post_event'), 10, 2);
        add_action('publish_future_post', array($this, 'send_post_event'), 10, 2);
        add_action('post_updated', array($this, 'send_post_event'), 10, 3);
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);
    }

    /**
     * インスタンスメタデータから識別情報を取得する
     *
     * @return array インスタンス識別情報
     */
    private function _get_instance_identity()
    {
        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document');
        if (is_wp_error($response)) {
            return array();
        }
        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
    }
    
    /**
     * インスタンスメタデータから一時的な認証情報を取得する
     *
     * @param string $instance_profile_arn インスタンスプロファイルARN
     * @return array 一時的な認証情報
     */
    private function _get_instance_credentials($instance_profile_arn)
    {
        $response = wp_remote_get('http://169.254.169.254/latest/meta-data/iam/security-credentials/' . $instance_profile_arn);
        if (is_wp_error($response)) {
            return array();
        }
        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
    }
    
    /**
     * 署名日付を取得する
     *
     * @return string 署名日付
     */
    private function _get_signature_date()
    {
        return gmdate('Ymd');
    }

    /**
     * 投稿のイベントをEventBridgeに送信する
     *
     * @param int $post_id 投稿ID
     * @param WP_Post $post 投稿オブジェクト (新規公開の場合)
     * @param WP_Post $post_before 更新前の投稿オブジェクト (更新の場合)
     */
    public function send_post_event($post_id, $post, $post_before = null)
    {
        $event_name = 'post.' . $post->post_status . 'ed'; // post.published、post.drafted など
        $permalink = get_permalink($post_id);
        $post_type = get_post_type($post_id);
        $api_url = get_rest_url(null, 'wp/v2/' . $post_type . 's/' . $post_id);

        $event_data = array(
            'id' => (string)$post_id,
            'title' => $post->post_title,
            'content' => $post->post_content,
            'status' => $post->post_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type
        );

        if ($post_before) {
            $event_data['previous_title'] = $post_before->post_title;
            $event_data['previous_content'] = $post_before->post_content;
            $event_data['previous_status'] = $post_before->post_status;
        }

        if (!$this->put_event_to_eventbridge($event_name, $event_data)) {
            $this->send_failure_event($event_name, $post_id);
            error_log('Failed to send event: ' . $event_name . ' for post ID: ' . $post_id);
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

        if (!$this->put_event_to_eventbridge($event_name, $event_data)) {
            $this->send_failure_event($event_name, $post_id);
            error_log('Failed to send event: ' . $event_name . ' for post ID: ' . $post_id);
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
        $failure_event_name = 'failure.' . $event_name;
        $failure_event_data = array(
            'id' => (string)$post_id,
            'failed_event' => $event_name
        );

        $this->put_event_to_eventbridge($failure_event_name, $failure_event_data);
    }

    /**
     * EventBridgeにイベントを送信する
     *
     * @param string $event_name イベント名
     * @param array $event_data イベントデータ
     * @return bool 成功したらtrue、失敗したらfalse
     */
    private function put_event_to_eventbridge($event_name, $event_data)
    {
        $endpoint = 'https://events.' .$this->region . '.amazonaws.com';
        $headers = array(
            'Content-Type' => 'application/x-amz-json-1.0',
            'Authorization' => sprintf('AWS4-HMAC-SHA256 Credential=%s/%s/events/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s',
                '',
                $this->_get_signature_date(),
                $this->get_signature('/default', array('Entries' => array(array('EventBusName' => EVENT_BUS_NAME, 'Source' => Source, 'DetailType' => $event_name, 'Detail' => json_encode($event_data)))), $this->credentials['SecretAccessKey'], 'PutEvents')
            ),
            'X-Amz-Date' => gmdate('Ymd\THis\Z'),
            'X-Amz-Target' => 'AWSEvents.PutEvents'
        );

        $payload = json_encode(array(
            'Entries' => array(
                array(
                    'EventBusName' => EVENT_BUS_NAME,
                    'Source' => EVENT_SOURCE_NAME,
                    'DetailType' => $event_name,
                    'Detail' => json_encode($event_data)
                )
            )
        ));

        $response = wp_remote_request($endpoint, array(
            'headers' => $headers,
            'body' => $payload,
            'method' => 'POST',
            'sslverify' => true // 必要に応じてSSL検証を無効化
        ));

        if (is_wp_error($response)) {
            // リクエストエラー
            return false;
        }

        $http_code = wp_remote_retrieve_response_code($response);

        return ($http_code == 200);
    }

    /**
     * リクエスト署名を生成する
     *
     * @param string $path リクエストパス
     * @param array $params リクエストのパラメータ
     * @param string $secret_access_key 秘密アクセスキー
     * @param string $target_operation 実行するAPIオペレーション
     * @return string 署名
     */
    private function get_signature($path, $params, $secret_access_key, $target_operation)
    {
        $payload = json_encode($params);

        $date = $this->_get_signature_date();
        $canonicalRequest = implode("\n", array(
            'POST',
            $path,
            '',
            'host:events.' .$this->region . '.amazonaws.com',
            'x-amz-date:' . gmdate('Ymd\THis\Z'),
            '',
            'host;x-amz-date',
            hash('sha256', $payload)
        ));

        $canonicalRequestHash = hash('sha256', $canonicalRequest);
        $stringToSign = implode("\n", array(
            'AWS4-HMAC-SHA256',
            gmdate('Ymd\THis\Z'),
            $date . '/' .$this->region . '/events/aws4_request',
            $canonicalRequestHash
        ));

        $signingKey = $this->getSignatureKey($date, $secret_access_key);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        return $signature;
    }

    /**
     * 署名キーを取得する
     *
     * @param string $date 署名日付
     * @param string $secret_access_key 秘密アクセスキー
     * @return string 署名キー
     */
    private function getSignatureKey($date, $secret_access_key)
    {
        $kSecret = 'AWS4' . $secret_access_key;
        $kDate = hash_hmac('sha256', $date, $kSecret, true);
        $kRegion = hash_hmac('sha256',$this->region, $kDate, true);
        $kService = hash_hmac('sha256', 'events', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return $kSigning;
    }
}

// インスタンスの作成
new EventBridgePostEvents();