<?php
/**
 * PHPUnit bootstrap file for integration tests with wp-env
 *
 * This bootstrap file is used when running tests in the wp-env tests-cli container.
 * It loads the WordPress test library and the plugin under test.
 */

// Determine if we're running in wp-env or local environment
$is_wp_env = getenv('WP_ENV_HOME') !== false || file_exists('/var/www/html/wp-load.php');

if ($is_wp_env) {
    // Running in wp-env tests-cli container
    $wp_tests_dir = '/wordpress-phpunit';

    // Load WordPress test library
    require_once $wp_tests_dir . '/includes/functions.php';

    /**
     * Manually load the plugin being tested.
     */
    function _manually_load_plugin() {
        // Define test AWS credentials as constants
        if (!defined('AWS_EVENTBRIDGE_ACCESS_KEY_ID')) {
            define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', getenv('AWS_EVENTBRIDGE_ACCESS_KEY_ID') ?: 'test-access-key-id');
        }
        if (!defined('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY')) {
            define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', getenv('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY') ?: 'test-secret-access-key');
        }

        require dirname(dirname(__FILE__)) . '/event-publisher-on-aws.php';
    }
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');

    // Start up the WordPress testing environment
    require $wp_tests_dir . '/includes/bootstrap.php';
} else {
    // Running unit tests locally without WordPress
    // Load Composer autoloader for Brain Monkey and other dependencies
    if (file_exists(dirname(dirname(__FILE__)) . '/vendor/autoload.php')) {
        require_once dirname(dirname(__FILE__)) . '/vendor/autoload.php';
    } else {
        die("Composer dependencies not installed. Run 'composer install --dev' first.\n");
    }

    // Brain Monkey will be initialized in unit test bootstrap
}
