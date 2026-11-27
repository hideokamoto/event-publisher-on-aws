<?php
/*
Plugin Name: EventBridge Post Events
Plugin URI: https://github.com/hideokamoto/event-publisher-on-aws
Description: Sends events to Amazon EventBridge when WordPress posts are published, updated, or deleted
Version: 2.0.0
Requires at least: 6.5
Requires PHP: 8.1
Author: Hidetaka Okamoto
Author URI: https://hidetaka.dev
*/

if (!defined('EVENTBRIDGE_POST_EVENTS_FILE')) {
    define('EVENTBRIDGE_POST_EVENTS_FILE', __FILE__);
}

require_once __DIR__ . '/src/bootstrap.php';

register_activation_hook(EVENTBRIDGE_POST_EVENTS_FILE, 'eventbridge_post_events_activate');
register_deactivation_hook(EVENTBRIDGE_POST_EVENTS_FILE, 'eventbridge_post_events_deactivate');

new EventBridgePostEvents();