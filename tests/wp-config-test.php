<?php
/**
 * WordPress test configuration for wp-env
 *
 * This file is used by the WordPress test library when running in wp-env.
 * It's referenced by WP_PHPUNIT__TESTS_CONFIG environment variable.
 */

// Test database configuration for wp-env
define('DB_NAME', getenv('WP_TESTS_DB_NAME') ?: 'wordpress_test');
define('DB_USER', getenv('WP_TESTS_DB_USER') ?: 'root');
define('DB_PASSWORD', getenv('WP_TESTS_DB_PASSWORD') ?: 'password');
define('DB_HOST', getenv('WP_TESTS_DB_HOST') ?: 'mysql');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

// Test site configuration
define('WP_TESTS_DOMAIN', 'example.org');
define('WP_TESTS_EMAIL', 'admin@example.org');
define('WP_TESTS_TITLE', 'Test Blog');

// Debug configuration
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);

// Table prefix
$table_prefix = 'wptests_';

// AWS test credentials
define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', getenv('AWS_EVENTBRIDGE_ACCESS_KEY_ID') ?: 'test-access-key-id');
define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', getenv('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') ?: 'test-secret-access-key');

// Absolute path to WordPress directory
if (!defined('ABSPATH')) {
    define('ABSPATH', '/var/www/html/');
}
