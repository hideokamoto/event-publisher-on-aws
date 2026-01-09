<?php
/**
 * Unit tests bootstrap file
 *
 * Sets up Brain Monkey for WordPress function mocking in unit tests.
 *
 * @package EventBridge_Post_Events
 */

// Composer autoloader
$autoloader = dirname(dirname(__DIR__)) . '/vendor/autoload.php';

if (!file_exists($autoloader)) {
    echo "Composer autoloader not found. Run 'composer install' first.\n";
    exit(1);
}

require_once $autoloader;

// Initialize Brain Monkey
require_once dirname(dirname(__DIR__)) . '/vendor/brain/monkey/inc/patchwork-loader.php';

use Brain\Monkey;

// Set up Brain Monkey before tests
Monkey\setUp();

// Define WordPress constants that may be needed
if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/wordpress/');
}

if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

// Define plugin constants
if (!defined('EVENT_BUS_NAME')) {
    define('EVENT_BUS_NAME', 'test-event-bus');
}

if (!defined('EVENT_SOURCE_NAME')) {
    define('EVENT_SOURCE_NAME', 'wordpress-test');
}

/**
 * Base test case for unit tests
 */
abstract class EventBridge_Unit_Test_Case extends \PHPUnit\Framework\TestCase
{
    use \Yoast\PHPUnitPolyfills\Polyfills\AssertIsType;

    protected function set_up()
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tear_down()
    {
        Monkey\tearDown();
        parent::tearDown();
    }
}
