<?php
/**
 * PHPUnit bootstrap file
 *
 * Determines which bootstrap to load based on test suite being run.
 *
 * @package EventBridge_Post_Events
 */

// Determine which test suite is being run
$is_unit_test = true;

// Check if running via wp-env (integration tests)
if (getenv('WP_TESTS_DIR') || getenv('WP_PHPUNIT__TESTS_CONFIG')) {
    $is_unit_test = false;
}

// Check command line arguments for test suite
global $argv;
if (is_array($argv)) {
    foreach ($argv as $arg) {
        if (strpos($arg, 'integration') !== false) {
            $is_unit_test = false;
            break;
        }
        if (strpos($arg, 'unit') !== false) {
            $is_unit_test = true;
            break;
        }
    }
}

if ($is_unit_test) {
    require_once __DIR__ . '/unit/bootstrap.php';
} else {
    require_once __DIR__ . '/integration/bootstrap.php';
}
