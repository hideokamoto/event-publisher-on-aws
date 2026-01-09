<?php
/**
 * Plugin uninstall handler
 * Removes all plugin data from WordPress database
 *
 * @package EventBridge_Post_Events
 */

// Exit if uninstall not called from WordPress
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Remove all plugin options
 */
function eventbridge_post_events_uninstall_remove_options()
{
    delete_option('eventbridge_metrics');
    delete_option('eventbridge_failure_details');
    delete_option('eventbridge_settings');
    delete_option('eventbridge_activation_warnings');
    delete_option('eventbridge_activation_errors');
}

/**
 * Remove all transients
 */
function eventbridge_post_events_uninstall_remove_transients()
{
    delete_transient('eventbridge_notice_dismissed');
}

/**
 * Remove all post metadata with key _event_correlation_id
 */
function eventbridge_post_events_uninstall_remove_post_meta()
{
    global $wpdb;

    // Delete all postmeta entries with meta_key = '_event_correlation_id'
    // Using direct SQL for efficiency when dealing with potentially large datasets
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->postmeta} WHERE meta_key = %s",
            '_event_correlation_id'
        )
    );
}

/**
 * Clear all remaining scheduled events
 */
function eventbridge_post_events_uninstall_clear_scheduled_events()
{
    // Get all scheduled cron events
    $cron_array = get_option('cron');

    if (is_array($cron_array)) {
        foreach ($cron_array as $timestamp => $cron) {
            // Clear eventbridge_async_send_event hooks
            if (isset($cron['eventbridge_async_send_event'])) {
                foreach ($cron['eventbridge_async_send_event'] as $key => $event) {
                    wp_unschedule_event($timestamp, 'eventbridge_async_send_event', $event['args']);
                }
            }
        }
    }
}

/**
 * Execute uninstall cleanup
 */
function eventbridge_post_events_uninstall()
{
    // Remove all options
    eventbridge_post_events_uninstall_remove_options();

    // Remove all transients
    eventbridge_post_events_uninstall_remove_transients();

    // Remove all post metadata
    eventbridge_post_events_uninstall_remove_post_meta();

    // Clear all scheduled events
    eventbridge_post_events_uninstall_clear_scheduled_events();

    // Log uninstall completion
    if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        error_log('[EventBridge] Plugin uninstalled - all data removed from database');
    }
}

// Execute uninstall
eventbridge_post_events_uninstall();
