<?php
/**
 * EventBridge Post Events Uninstall
 *
 * Removes all plugin data when the plugin is uninstalled via the WordPress admin.
 *
 * @package EventBridge_Post_Events
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove WordPress options
delete_option('eventbridge_metrics');
delete_option('eventbridge_failure_details');
delete_option('eventbridge_settings');

// Remove transients
delete_transient('eventbridge_notice_dismissed');
delete_transient('eventbridge_credential_notice_shown');
delete_transient('eventbridge_region_fallback_used');
delete_transient('eventbridge_activation_notice');

// Delete all post metadata with key _event_correlation_id
global $wpdb;
$wpdb->delete(
    $wpdb->postmeta,
    array('meta_key' => '_event_correlation_id'),
    array('%s')
);

// Clear any remaining scheduled events
$timestamp = wp_next_scheduled('eventbridge_async_send_event');
while ($timestamp) {
    wp_unschedule_event($timestamp, 'eventbridge_async_send_event');
    $timestamp = wp_next_scheduled('eventbridge_async_send_event');
}

// Clear all scheduled events with any arguments (handles edge cases)
wp_unschedule_hook('eventbridge_async_send_event');
