<?php
/**
 * Unit tests bootstrap file
 *
 * This file initializes Brain Monkey for WordPress function mocking
 * and loads the plugin code for unit testing without WordPress.
 */

use Brain\Monkey;

// Load Composer autoloader
if (file_exists(dirname(dirname(dirname(__FILE__))) . '/vendor/autoload.php')) {
    require_once dirname(dirname(dirname(__FILE__))) . '/vendor/autoload.php';
} else {
    die("Composer dependencies not installed. Run 'composer install --dev' first.\n");
}

// Initialize Brain Monkey before each test
class BrainMonkeyPHPUnitIntegration extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }
}
