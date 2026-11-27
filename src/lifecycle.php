<?php
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
