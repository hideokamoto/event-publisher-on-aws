<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://example.com/eventbridge-post-events
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 2.0
Author: Your Name
Author URI: https://example.com
*/

// Load Composer autoloader
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use Aws\EventBridge\EventBridgeClient;
use Aws\Credentials\CredentialProvider;
use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;

// Default configuration constants (can be overridden in wp-config.php)
if (!defined('EVENT_BUS_NAME')) {
    define('EVENT_BUS_NAME', 'wp-kyoto');
}
if (!defined('EVENT_SOURCE_NAME')) {
    define('EVENT_SOURCE_NAME', 'wordpress');
}

class EventBridgePostEvents
{
    private $region;
    private $client;
    private $credentialProvider;
    private $credentialSource = 'unknown';
    private $regionSource = 'unknown';
    private $regionFallbackUsed = false;

    // In-memory counters for tracking metrics
    private $successful_events = 0;
    private $failed_events = 0;

    // WordPress options keys for persistent storage (non-autoload for performance)
    const OPTION_METRICS = 'eventbridge_metrics';
    const OPTION_FAILURE_DETAILS = 'eventbridge_failure_details';
    const TRANSIENT_NOTICE_DISMISSED = 'eventbridge_notice_dismissed';
    const FAILURE_THRESHOLD = 5; // Number of failures before showing admin notice
    const EVENT_SIZE_LIMIT = 256 * 1024; // 256KB EventBridge limit

    public function __construct()
    {
        // Check if AWS SDK is loaded
        if (!class_exists('Aws\EventBridge\EventBridgeClient')) {
            add_action('admin_notices', array($this, 'display_sdk_missing_notice'));
            return;
        }

        // Initialize credential provider chain
        try {
            $this->credentialProvider = $this->create_credential_provider();
        } catch (Exception $e) {
            add_action('admin_notices', array($this, 'display_credential_error_notice'));
            error_log('[EventBridge] Credential provider initialization failed: ' . $e->getMessage());
            return;
        }

        // Detect and validate region
        $this->region = $this->detect_region();
        if (!$this->validate_region($this->region)) {
            add_action('admin_notices', array($this, 'display_region_error_notice'));
            error_log('[EventBridge] Invalid region detected: ' . $this->region);
            return;
        }

        // Display notice if region fallback was used
        if ($this->regionFallbackUsed) {
            add_action('admin_notices', array($this, 'display_region_fallback_notice'));
        }

        // Initialize AWS EventBridge client
        try {
            $this->client = $this->create_eventbridge_client();
        } catch (Exception $e) {
            add_action('admin_notices', array($this, 'display_client_error_notice'));
            error_log('[EventBridge] Client initialization failed: ' . $e->getMessage());
            return;
        }

        // Load metrics from WordPress options
        $this->load_metrics();

        // Post status transition hooks
        add_action('transition_post_status', array($this, 'send_post_event'), 10, 3);
        add_action('before_delete_post', array($this, 'send_delete_post_event'), 10, 1);

        // Async EventBridge sending action
        add_action('eventbridge_async_send_event', array($this, 'async_send_event'), 10, 3);
        add_action('eventbridge_send_failed', array($this, 'handle_send_failure'), 10, 3);

        // Admin notices
        add_action('admin_notices', array($this, 'display_failure_notice'));
        add_action('admin_init', array($this, 'handle_notice_dismissal'));

        // Admin menu and settings
        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_post_eventbridge_test_connection', array($this, 'handle_test_connection'));
        add_action('admin_post_eventbridge_reset_metrics', array($this, 'handle_reset_metrics'));
    }

    /**
     * Create credential provider chain
     * Priority: IAM instance profile → environment variables → WordPress constants
     */
    private function create_credential_provider()
    {
        $providers = array();

        // 1. WordPress constants (highest priority for explicit configuration)
        if (defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID') && defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            $key = constant('AWS_EVENTBRIDGE_ACCESS_KEY_ID');
            $secret = constant('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY');

            if (!empty($key) && !empty($secret)) {
                $providers[] = function() use ($key, $secret) {
                    $this->credentialSource = 'WordPress constants';
                    return Promise\promise_for(new Credentials($key, $secret));
                };
            }
        }

        // 2. Environment variables
        $envProvider = CredentialProvider::env();
        $providers[] = function() use ($envProvider) {
            try {
                $credentials = $envProvider()->wait();
                $this->credentialSource = 'Environment variables';
                return Promise\promise_for($credentials);
            } catch (Exception $e) {
                return Promise\rejection_for($e);
            }
        };

        // 3. IAM instance profile (EC2/ECS)
        $instanceProvider = CredentialProvider::instanceProfile();
        $providers[] = function() use ($instanceProvider) {
            try {
                $credentials = $instanceProvider()->wait();
                $this->credentialSource = 'IAM instance profile';
                return Promise\promise_for($credentials);
            } catch (Exception $e) {
                return Promise\rejection_for($e);
            }
        };

        // Chain providers with memoization
        return CredentialProvider::memoize(
            CredentialProvider::chain(...$providers)
        );
    }

    /**
     * Detect AWS region with fallback logic
     * Priority: EVENT_BRIDGE_REGION constant → EC2 metadata → 'us-east-1' default
     */
    private function detect_region()
    {
        // 1. Check for constant override
        if (defined('EVENT_BRIDGE_REGION') && !empty(constant('EVENT_BRIDGE_REGION'))) {
            $this->regionSource = 'EVENT_BRIDGE_REGION constant';
            return constant('EVENT_BRIDGE_REGION');
        }

        // 2. Check for admin setting override
        $regionOverride = $this->get_setting('aws_region_override');
        if (!empty($regionOverride)) {
            $this->regionSource = 'Settings page override';
            return $regionOverride;
        }

        // 3. Try EC2 instance metadata
        $identity = $this->get_instance_identity();
        if (!empty($identity['region'])) {
            $this->regionSource = 'EC2 instance metadata';
            return $identity['region'];
        }

        // 4. Fallback to us-east-1
        $this->regionSource = 'Default fallback';
        $this->regionFallbackUsed = true;
        return 'us-east-1';
    }

    /**
     * Validate AWS region format
     */
    private function validate_region($region)
    {
        // AWS region format: lowercase letters, numbers, and hyphens
        // Examples: us-east-1, eu-west-2, ap-southeast-1
        return preg_match('/^[a-z]{2}-[a-z]+-\d+$/', $region);
    }

    /**
     * Get instance identity from EC2 metadata
     */
    private function get_instance_identity()
    {
        $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
            'timeout' => 1,
        ));

        if (is_wp_error($response)) {
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        return is_array($data) ? $data : array();
    }

    /**
     * Create EventBridge client with retry configuration
     */
    private function create_eventbridge_client()
    {
        return new EventBridgeClient(array(
            'version' => 'latest',
            'region' => $this->region,
            'credentials' => $this->credentialProvider,
            'retries' => array(
                'mode' => 'standard',
                'max_attempts' => 5,
            ),
        ));
    }

    /**
     * Get setting with constant override support
     * Priority: Constants → WordPress options → default values
     */
    public function get_setting($key, $default = '')
    {
        // Map setting keys to constant names
        $constantMap = array(
            'event_bus_name' => 'EVENT_BUS_NAME',
            'event_source_name' => 'EVENT_SOURCE_NAME',
            'aws_region_override' => 'EVENT_BRIDGE_REGION',
        );

        // Check if constant is defined and use it
        if (isset($constantMap[$key]) && defined($constantMap[$key])) {
            $value = constant($constantMap[$key]);
            if (!empty($value)) {
                return $value;
            }
        }

        // Fall back to WordPress option
        $option = get_option('eventbridge_' . $key, $default);
        return !empty($option) ? $option : $default;
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
     */
    private function record_failure($error_message)
    {
        $this->failed_events++;

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

        update_option(self::OPTION_FAILURE_DETAILS, $failure_details, false);
        $this->save_metrics();
    }

    /**
     * Validate event payload size
     */
    private function validate_payload_size($detail)
    {
        $detailJson = json_encode($detail);
        $size = strlen($detailJson);

        if ($size > self::EVENT_SIZE_LIMIT) {
            return array(
                'valid' => false,
                'error' => sprintf('Event payload size (%d bytes) exceeds EventBridge limit (%d bytes)', $size, self::EVENT_SIZE_LIMIT)
            );
        }

        return array('valid' => true);
    }

    /**
     * Get allowed post types for event publishing
     */
    private function get_allowed_post_types()
    {
        $default = array('post', 'page');

        // Allow filtering via constant
        if (defined('EVENTBRIDGE_ALLOWED_POST_TYPES')) {
            $types = constant('EVENTBRIDGE_ALLOWED_POST_TYPES');
            if (is_array($types)) {
                return $types;
            }
        }

        // Allow filtering via WordPress filter
        return apply_filters('eventbridge_allowed_post_types', $default);
    }

    /**
     * Send event to EventBridge using AWS SDK
     */
    private function sendEvent($source, $detailType, $detail)
    {
        try {
            // Validate payload size
            $sizeValidation = $this->validate_payload_size($detail);
            if (!$sizeValidation['valid']) {
                throw new Exception($sizeValidation['error']);
            }

            $eventBusName = $this->get_setting('event_bus_name', EVENT_BUS_NAME);

            $result = $this->client->putEvents(array(
                'Entries' => array(
                    array(
                        'EventBusName' => $eventBusName,
                        'Source' => $source,
                        'DetailType' => $detailType,
                        'Detail' => json_encode($detail),
                    ),
                ),
            ));

            // Check for partial failures
            $failedCount = isset($result['FailedEntryCount']) ? (int) $result['FailedEntryCount'] : 0;

            if ($failedCount > 0) {
                $entries = isset($result['Entries']) ? $result['Entries'] : array();
                $errorMessages = array();

                foreach ($entries as $index => $entry) {
                    if (isset($entry['ErrorCode'])) {
                        $errorMessages[] = sprintf(
                            'Entry[%d]: %s - %s',
                            $index,
                            $entry['ErrorCode'],
                            isset($entry['ErrorMessage']) ? $entry['ErrorMessage'] : 'Unknown error'
                        );
                    }
                }

                throw new Exception(sprintf(
                    'Partial failure: %d/%d entries failed. %s',
                    $failedCount,
                    count($entries),
                    implode('; ', $errorMessages)
                ));
            }

            return array('success' => true, 'error' => null, 'response' => $result);

        } catch (AwsException $e) {
            // Determine if error is retryable
            $statusCode = $e->getStatusCode();
            $errorCode = $e->getAwsErrorCode();
            $isRetryable = ($statusCode >= 500 && $statusCode < 600) ||
                          $errorCode === 'ThrottlingException' ||
                          $errorCode === 'RequestLimitExceeded';

            $errorMessage = sprintf(
                'AWS Error [%s]: %s (HTTP %d, RequestId: %s, Retryable: %s)',
                $errorCode,
                $e->getAwsErrorMessage(),
                $statusCode,
                $e->getAwsRequestId() ?: 'N/A',
                $isRetryable ? 'Yes' : 'No'
            );

            error_log('[EventBridge] ' . $errorMessage);

            return array(
                'success' => false,
                'error' => $errorMessage,
                'response' => null,
                'retryable' => $isRetryable
            );

        } catch (Exception $e) {
            $errorMessage = 'Unexpected error: ' . $e->getMessage();
            error_log('[EventBridge] ' . $errorMessage);

            return array(
                'success' => false,
                'error' => $errorMessage,
                'response' => null,
                'retryable' => false
            );
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
     * Get or create correlation ID for post
     */
    private function get_or_create_correlation_id($post_id)
    {
        $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);

        if (empty($correlation_id)) {
            // Try to generate UUID, fallback to uniqid if function doesn't exist
            $correlation_id = function_exists('wp_generate_uuid4')
                ? wp_generate_uuid4()
                : uniqid('event-', true);

            $added = add_post_meta($post_id, '_event_correlation_id', $correlation_id, true);

            if ($added === false) {
                $correlation_id = get_post_meta($post_id, '_event_correlation_id', true);
            }
        }

        return $correlation_id;
    }

    /**
     * Send post event to EventBridge
     * Handles: publish, future (scheduled), and update transitions
     */
    public function send_post_event($new_status, $old_status, $post)
    {
        // Validate post object
        if (!$post || !isset($post->ID) || !isset($post->post_type)) {
            return;
        }

        // Check if post type is allowed
        $allowedTypes = $this->get_allowed_post_types();
        if (!in_array($post->post_type, $allowedTypes)) {
            return;
        }

        // Determine event type based on status transitions
        $event_name = '';

        if ($new_status === 'future') {
            // Scheduled post
            $event_name = 'post.scheduled';
        } elseif ($new_status === 'publish' && $old_status !== 'publish') {
            // New publish
            $event_name = 'post.published';
        } elseif ($new_status === 'publish' && $old_status === 'publish') {
            // Update to already published post
            $event_name = 'post.updated';
        } else {
            // Other transitions (draft, pending, etc.) - skip for now
            return;
        }

        $permalink = get_permalink($post->ID);
        $post_type = $post->post_type;

        // Get REST API URL
        $post_type_obj = get_post_type_object($post_type);
        $rest_base = !empty($post_type_obj->rest_base) ? $post_type_obj->rest_base : $post_type;
        $api_url = get_rest_url(null, 'wp/v2/' . $rest_base . '/' . $post->ID);

        // Get or create correlation_id
        $correlation_id = $this->get_or_create_correlation_id($post->ID);

        $event_data = array(
            'id' => (string) $post->ID,
            'title' => isset($post->post_title) ? $post->post_title : '',
            'status' => $new_status,
            'previous_status' => $old_status,
            'updated_at' => time(),
            'permalink' => $permalink,
            'api_url' => $api_url,
            'post_type' => $post_type,
        );

        // Create event envelope
        $event_envelope = $this->create_event_envelope($event_data, $correlation_id);

        $eventSource = $this->get_setting('event_source_name', EVENT_SOURCE_NAME);

        // Schedule async event
        wp_schedule_single_event(time(), 'eventbridge_async_send_event', array($eventSource, $event_name, $event_envelope));
    }

    /**
     * Send delete post event to EventBridge
     */
    public function send_delete_post_event($post_id)
    {
        $post = get_post($post_id);

        // Validate post
        if (!$post || !isset($post->post_type)) {
            return;
        }

        // Check if post type is allowed
        $allowedTypes = $this->get_allowed_post_types();
        if (!in_array($post->post_type, $allowedTypes)) {
            return;
        }

        $event_name = 'post.deleted';
        $correlation_id = $this->get_or_create_correlation_id($post_id);

        $event_data = array(
            'id' => (string) $post_id
        );

        $event_envelope = $this->create_event_envelope($event_data, $correlation_id);

        $eventSource = $this->get_setting('event_source_name', EVENT_SOURCE_NAME);

        wp_schedule_single_event(time(), 'eventbridge_async_send_event', array($eventSource, $event_name, $event_envelope));
    }

    /**
     * Async event sending (background processing)
     */
    public function async_send_event($source, $detailType, $detail)
    {
        $result = $this->sendEvent($source, $detailType, $detail);

        if ($result['success']) {
            $this->record_success();
        } else {
            $error_message = isset($result['error']) ? $result['error'] : 'Unknown error';
            $this->record_failure($error_message);
            do_action('eventbridge_send_failed', $source, $detailType, $detail);
        }

        return $result;
    }

    /**
     * Handle EventBridge send failure
     */
    public function handle_send_failure($source, $detailType, $detail)
    {
        $postId = isset($detail['data']['id']) ? $detail['data']['id'] : null;
        if ($postId) {
            error_log(sprintf(
                '[EventBridge] Failed to send event: DetailType=%s, PostID=%s, Source=%s',
                $detailType,
                $postId,
                $source
            ));
        }
    }

    /**
     * Display failure notice in admin
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
     * Display SDK missing notice
     */
    public function display_sdk_missing_notice()
    {
        ?>
        <div class="notice notice-error">
            <p><strong><?php esc_html_e('EventBridge Post Events:', 'eventbridge-post-events'); ?></strong> <?php esc_html_e('AWS SDK for PHP is not installed. Please run "composer install" in the plugin directory.', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }

    /**
     * Display credential error notice
     */
    public function display_credential_error_notice()
    {
        ?>
        <div class="notice notice-error">
            <p><strong><?php esc_html_e('EventBridge Post Events:', 'eventbridge-post-events'); ?></strong> <?php esc_html_e('Unable to resolve AWS credentials. Please configure credentials via IAM instance profile, environment variables, or WordPress constants.', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }

    /**
     * Display region error notice
     */
    public function display_region_error_notice()
    {
        ?>
        <div class="notice notice-error">
            <p><strong><?php esc_html_e('EventBridge Post Events:', 'eventbridge-post-events'); ?></strong> <?php printf(esc_html__('Invalid AWS region detected: %s', 'eventbridge-post-events'), esc_html($this->region)); ?></p>
        </div>
        <?php
    }

    /**
     * Display region fallback notice
     */
    public function display_region_fallback_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong><?php esc_html_e('EventBridge Post Events:', 'eventbridge-post-events'); ?></strong> <?php printf(esc_html__('AWS region not detected, using default: %s. Consider setting EVENT_BRIDGE_REGION constant in wp-config.php.', 'eventbridge-post-events'), esc_html($this->region)); ?></p>
        </div>
        <?php
    }

    /**
     * Display client error notice
     */
    public function display_client_error_notice()
    {
        ?>
        <div class="notice notice-error">
            <p><strong><?php esc_html_e('EventBridge Post Events:', 'eventbridge-post-events'); ?></strong> <?php esc_html_e('Failed to initialize EventBridge client. Check error logs for details.', 'eventbridge-post-events'); ?></p>
        </div>
        <?php
    }

    /**
     * Add settings page to WordPress admin
     */
    public function add_settings_page()
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
        // Register settings
        register_setting('eventbridge_settings', 'eventbridge_event_bus_name', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_event_bus_name'),
            'default' => EVENT_BUS_NAME,
        ));

        register_setting('eventbridge_settings', 'eventbridge_event_source_name', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_event_source_name'),
            'default' => EVENT_SOURCE_NAME,
        ));

        register_setting('eventbridge_settings', 'eventbridge_aws_region_override', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_region'),
            'default' => '',
        ));

        // AWS Configuration section
        add_settings_section(
            'eventbridge_aws_config',
            __('AWS Configuration', 'eventbridge-post-events'),
            array($this, 'render_aws_config_section'),
            'eventbridge-settings'
        );

        add_settings_field(
            'aws_region_override',
            __('AWS Region Override', 'eventbridge-post-events'),
            array($this, 'render_region_field'),
            'eventbridge-settings',
            'eventbridge_aws_config'
        );

        // Event Configuration section
        add_settings_section(
            'eventbridge_event_config',
            __('Event Configuration', 'eventbridge-post-events'),
            array($this, 'render_event_config_section'),
            'eventbridge-settings'
        );

        add_settings_field(
            'event_bus_name',
            __('Event Bus Name', 'eventbridge-post-events'),
            array($this, 'render_event_bus_field'),
            'eventbridge-settings',
            'eventbridge_event_config'
        );

        add_settings_field(
            'event_source_name',
            __('Event Source Name', 'eventbridge-post-events'),
            array($this, 'render_event_source_field'),
            'eventbridge-settings',
            'eventbridge_event_config'
        );

        // Diagnostics section
        add_settings_section(
            'eventbridge_diagnostics',
            __('Diagnostics', 'eventbridge-post-events'),
            array($this, 'render_diagnostics_section'),
            'eventbridge-settings'
        );
    }

    /**
     * Sanitize event bus name
     */
    public function sanitize_event_bus_name($value)
    {
        $value = sanitize_text_field($value);

        // AWS EventBridge event bus name constraints: 1-256 characters, alphanumeric, hyphens, underscores, periods, forward slashes
        if (!preg_match('/^[a-zA-Z0-9\-_.\/]{1,256}$/', $value)) {
            add_settings_error(
                'eventbridge_event_bus_name',
                'invalid_event_bus_name',
                __('Event Bus Name must be 1-256 characters and contain only alphanumeric characters, hyphens, underscores, periods, and forward slashes.', 'eventbridge-post-events')
            );
            return EVENT_BUS_NAME;
        }

        return $value;
    }

    /**
     * Sanitize event source name
     */
    public function sanitize_event_source_name($value)
    {
        $value = sanitize_text_field($value);

        // AWS EventBridge source name constraints: typically reverse domain notation
        if (empty($value)) {
            add_settings_error(
                'eventbridge_event_source_name',
                'empty_event_source_name',
                __('Event Source Name cannot be empty.', 'eventbridge-post-events')
            );
            return EVENT_SOURCE_NAME;
        }

        return $value;
    }

    /**
     * Sanitize region
     */
    public function sanitize_region($value)
    {
        $value = sanitize_text_field($value);

        if (empty($value)) {
            return '';
        }

        if (!$this->validate_region($value)) {
            add_settings_error(
                'eventbridge_aws_region_override',
                'invalid_region',
                __('Invalid AWS region format. Must match pattern: xx-xxxx-#', 'eventbridge-post-events')
            );
            return '';
        }

        return $value;
    }

    /**
     * Render AWS config section
     */
    public function render_aws_config_section()
    {
        echo '<p>' . esc_html__('Configure AWS-specific settings. Constants in wp-config.php take precedence over these settings.', 'eventbridge-post-events') . '</p>';
    }

    /**
     * Render event config section
     */
    public function render_event_config_section()
    {
        echo '<p>' . esc_html__('Configure EventBridge event settings.', 'eventbridge-post-events') . '</p>';
    }

    /**
     * Render region field
     */
    public function render_region_field()
    {
        $value = get_option('eventbridge_aws_region_override', '');
        $isConstantDefined = defined('EVENT_BRIDGE_REGION');

        printf(
            '<input type="text" name="eventbridge_aws_region_override" value="%s" class="regular-text" %s />',
            esc_attr($value),
            $isConstantDefined ? 'disabled' : ''
        );

        echo '<p class="description">';
        if ($isConstantDefined) {
            printf(
                esc_html__('Region is set via EVENT_BRIDGE_REGION constant: %s', 'eventbridge-post-events'),
                '<code>' . esc_html(constant('EVENT_BRIDGE_REGION')) . '</code>'
            );
        } else {
            esc_html_e('Override the detected AWS region. Leave empty to auto-detect.', 'eventbridge-post-events');
        }
        echo '</p>';
    }

    /**
     * Render event bus field
     */
    public function render_event_bus_field()
    {
        $value = get_option('eventbridge_event_bus_name', EVENT_BUS_NAME);
        $isConstantDefined = defined('EVENT_BUS_NAME');

        printf(
            '<input type="text" name="eventbridge_event_bus_name" value="%s" class="regular-text" %s />',
            esc_attr($value),
            $isConstantDefined ? 'disabled' : ''
        );

        echo '<p class="description">';
        if ($isConstantDefined) {
            printf(
                esc_html__('Event bus name is set via EVENT_BUS_NAME constant: %s', 'eventbridge-post-events'),
                '<code>' . esc_html(EVENT_BUS_NAME) . '</code>'
            );
        } else {
            esc_html_e('The name of your EventBridge event bus.', 'eventbridge-post-events');
        }
        echo '</p>';
    }

    /**
     * Render event source field
     */
    public function render_event_source_field()
    {
        $value = get_option('eventbridge_event_source_name', EVENT_SOURCE_NAME);
        $isConstantDefined = defined('EVENT_SOURCE_NAME');

        printf(
            '<input type="text" name="eventbridge_event_source_name" value="%s" class="regular-text" %s />',
            esc_attr($value),
            $isConstantDefined ? 'disabled' : ''
        );

        echo '<p class="description">';
        if ($isConstantDefined) {
            printf(
                esc_html__('Event source name is set via EVENT_SOURCE_NAME constant: %s', 'eventbridge-post-events'),
                '<code>' . esc_html(EVENT_SOURCE_NAME) . '</code>'
            );
        } else {
            esc_html_e('The source identifier for your events (e.g., wordpress).', 'eventbridge-post-events');
        }
        echo '</p>';
    }

    /**
     * Render diagnostics section
     */
    public function render_diagnostics_section()
    {
        $eventBusName = $this->get_setting('event_bus_name', EVENT_BUS_NAME);
        $eventSource = $this->get_setting('event_source_name', EVENT_SOURCE_NAME);

        ?>
        <table class="widefat">
            <thead>
                <tr>
                    <th><?php esc_html_e('Setting', 'eventbridge-post-events'); ?></th>
                    <th><?php esc_html_e('Value', 'eventbridge-post-events'); ?></th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong><?php esc_html_e('Detected Region', 'eventbridge-post-events'); ?></strong></td>
                    <td><code><?php echo esc_html($this->region); ?></code> <em>(<?php echo esc_html($this->regionSource); ?>)</em></td>
                </tr>
                <tr>
                    <td><strong><?php esc_html_e('Credential Source', 'eventbridge-post-events'); ?></strong></td>
                    <td><code><?php echo esc_html($this->credentialSource); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php esc_html_e('Event Bus Name', 'eventbridge-post-events'); ?></strong></td>
                    <td><code><?php echo esc_html($eventBusName); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php esc_html_e('Event Source', 'eventbridge-post-events'); ?></strong></td>
                    <td><code><?php echo esc_html($eventSource); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php esc_html_e('Successful Events', 'eventbridge-post-events'); ?></strong></td>
                    <td><?php echo esc_html($this->successful_events); ?></td>
                </tr>
                <tr>
                    <td><strong><?php esc_html_e('Failed Events', 'eventbridge-post-events'); ?></strong></td>
                    <td><?php echo esc_html($this->failed_events); ?></td>
                </tr>
            </tbody>
        </table>

        <p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline-block; margin-right: 10px;">
                <?php wp_nonce_field('eventbridge_test_connection', 'eventbridge_test_nonce'); ?>
                <input type="hidden" name="action" value="eventbridge_test_connection" />
                <input type="submit" class="button button-secondary" value="<?php esc_attr_e('Test Connection', 'eventbridge-post-events'); ?>" />
            </form>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline-block;">
                <?php wp_nonce_field('eventbridge_reset_metrics', 'eventbridge_reset_nonce'); ?>
                <input type="hidden" name="action" value="eventbridge_reset_metrics" />
                <input type="submit" class="button button-secondary" value="<?php esc_attr_e('Reset Metrics', 'eventbridge-post-events'); ?>" onclick="return confirm('<?php esc_attr_e('Are you sure you want to reset metrics?', 'eventbridge-post-events'); ?>');" />
            </form>
        </p>

        <?php
        // Display last failure details
        $failure_details = get_option(self::OPTION_FAILURE_DETAILS, array());
        if (!empty($failure_details['last_failure_time'])) {
            ?>
            <h3><?php esc_html_e('Last Failure Details', 'eventbridge-post-events'); ?></h3>
            <p><strong><?php esc_html_e('Time:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($failure_details['last_failure_time']); ?></p>

            <?php if (!empty($failure_details['messages'])) : ?>
                <h4><?php esc_html_e('Recent Error Messages:', 'eventbridge-post-events'); ?></h4>
                <ul style="list-style: disc; margin-left: 20px;">
                    <?php foreach (array_slice(array_reverse($failure_details['messages']), 0, 5) as $msg) : ?>
                        <li>
                            <strong><?php echo esc_html($msg['time']); ?>:</strong>
                            <?php echo esc_html($msg['message']); ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <?php
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

        // Check if test was just run
        if (isset($_GET['test_result'])) {
            $result = sanitize_text_field(wp_unslash($_GET['test_result']));
            if ($result === 'success') {
                ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php esc_html_e('Connection test successful! Event sent to EventBridge.', 'eventbridge-post-events'); ?></p>
                </div>
                <?php
            } else {
                $error = isset($_GET['error']) ? sanitize_text_field(wp_unslash($_GET['error'])) : __('Unknown error', 'eventbridge-post-events');
                ?>
                <div class="notice notice-error is-dismissible">
                    <p><strong><?php esc_html_e('Connection test failed:', 'eventbridge-post-events'); ?></strong> <?php echo esc_html($error); ?></p>
                </div>
                <?php
            }
        }

        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('eventbridge_settings');
                do_settings_sections('eventbridge-settings');
                submit_button();
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
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized', 'eventbridge-post-events'));
        }

        check_admin_referer('eventbridge_test_connection', 'eventbridge_test_nonce');

        $test_event = array(
            'test' => true,
            'timestamp' => current_time('c'),
            'message' => 'Connection test from WordPress'
        );

        $eventSource = $this->get_setting('event_source_name', EVENT_SOURCE_NAME);
        $result = $this->sendEvent($eventSource, 'connection.test', $test_event);

        $redirect_url = add_query_arg(
            array('page' => 'eventbridge-settings'),
            admin_url('options-general.php')
        );

        if ($result['success']) {
            $redirect_url = add_query_arg('test_result', 'success', $redirect_url);
        } else {
            $redirect_url = add_query_arg(array(
                'test_result' => 'failure',
                'error' => urlencode($result['error'])
            ), $redirect_url);
        }

        wp_safe_redirect($redirect_url);
        exit;
    }

    /**
     * Handle reset metrics request
     */
    public function handle_reset_metrics()
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized', 'eventbridge-post-events'));
        }

        check_admin_referer('eventbridge_reset_metrics', 'eventbridge_reset_nonce');

        $this->successful_events = 0;
        $this->failed_events = 0;
        $this->save_metrics();

        delete_option(self::OPTION_FAILURE_DETAILS);

        wp_safe_redirect(add_query_arg(
            array('page' => 'eventbridge-settings'),
            admin_url('options-general.php')
        ));
        exit;
    }
}

// Activation hook
register_activation_hook(__FILE__, 'eventbridge_activation_callback');

function eventbridge_activation_callback()
{
    // Initialize metrics option
    add_option('eventbridge_metrics', array(
        'successful_events' => 0,
        'failed_events' => 0
    ), '', false);

    // Try to validate credentials by creating a temporary instance
    try {
        if (!class_exists('Aws\EventBridge\EventBridgeClient')) {
            wp_die(__('AWS SDK for PHP is not installed. Please run "composer install" in the plugin directory.', 'eventbridge-post-events'));
        }

        // Create temporary instance to validate setup
        $tempInstance = new EventBridgePostEvents();

        // Log activation success
        error_log('[EventBridge] Plugin activated successfully');

    } catch (Exception $e) {
        error_log('[EventBridge] Activation error: ' . $e->getMessage());
        // Don't prevent activation, just log the error
    }
}

// Deactivation hook
register_deactivation_hook(__FILE__, 'eventbridge_deactivation_callback');

function eventbridge_deactivation_callback()
{
    // Clear scheduled events
    $timestamp = wp_next_scheduled('eventbridge_async_send_event');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'eventbridge_async_send_event');
    }

    // Clear all scheduled single events (requires iterating cron array)
    $crons = _get_cron_array();
    if (is_array($crons)) {
        foreach ($crons as $timestamp => $cron) {
            if (isset($cron['eventbridge_async_send_event'])) {
                foreach ($cron['eventbridge_async_send_event'] as $key => $event) {
                    wp_unschedule_event($timestamp, 'eventbridge_async_send_event', $event['args']);
                }
            }
        }
    }

    // Clear transient notices
    delete_transient(EventBridgePostEvents::TRANSIENT_NOTICE_DISMISSED);

    error_log('[EventBridge] Plugin deactivated');
}

// Initialize plugin
new EventBridgePostEvents();
