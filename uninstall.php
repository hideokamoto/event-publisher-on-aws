<?php
/**
 * Uninstall script for EventBridge Post Events
 *
 * This file is called when the plugin is uninstalled via the WordPress admin.
 * It removes all plugin data from the database.
 *
 * @package EventBridgePostEvents
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove WordPress options
delete_option('eventbridge_metrics');
delete_option('eventbridge_failure_details');
delete_option('eventbridge_event_bus_name');
delete_option('eventbridge_event_source_name');
delete_option('eventbridge_aws_region_override');

// Remove transients
delete_transient('eventbridge_notice_dismissed');

// Remove all post metadata with key '_event_correlation_id'
global $wpdb;

$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->postmeta} WHERE meta_key = %s",
        '_event_correlation_id'
    )
);

// Clear all scheduled events
$timestamp = wp_next_scheduled('eventbridge_async_send_event');
if ($timestamp) {
    wp_unschedule_event($timestamp, 'eventbridge_async_send_event');
}

// Clear all scheduled single events
$crons = _get_cron_array();
if (is_array($crons)) {
    foreach ($crons as $timestamp => $cron) {
        if (isset($cron['eventbridge_async_send_event'])) {
            foreach ($cron['eventbridge_async_send_event'] as $key => $event) {
                wp_unschedule_event($timestamp, 'eventbridge_async_send_event', $event['args']);
            }
        }

        if (isset($cron['eventbridge_send_failed'])) {
            foreach ($cron['eventbridge_send_failed'] as $key => $event) {
                wp_unschedule_event($timestamp, 'eventbridge_send_failed', $event['args']);
            }
        }
    }
}

// Log uninstall completion
error_log('[EventBridge] Plugin uninstalled and all data removed');
