<?php
/**
 * PHPUnit bootstrap file for integration tests
 *
 * @package EventBridgePostEvents
 */

// Composer autoloader
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Check if WordPress test library is available
$_tests_dir = getenv('WP_TESTS_DIR');

if (!$_tests_dir) {
    $_tests_dir = rtrim(sys_get_temp_dir(), '/\\') . '/wordpress-tests-lib';
}

// Give access to tests_add_filter() function
if (file_exists($_tests_dir . '/includes/functions.php')) {
    require_once $_tests_dir . '/includes/functions.php';

    /**
     * Manually load the plugin being tested
     */
    function _manually_load_plugin() {
        require dirname(__DIR__) . '/event-publisher-on-aws.php';
    }
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');

    // Start up the WP testing environment
    require $_tests_dir . '/includes/bootstrap.php';
} else {
    // If WordPress test library is not available, skip integration tests
    echo "WordPress test library not found. Integration tests will be skipped.\n";
    echo "Set WP_TESTS_DIR environment variable to point to WordPress tests directory.\n";
}
