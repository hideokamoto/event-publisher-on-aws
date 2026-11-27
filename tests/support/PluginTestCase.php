<?php

declare(strict_types=1);

namespace EventPublisherOnAWS\Tests\Support;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

/**
 * Loads plugin classes without running the production bootstrap hook registration twice.
 */
abstract class PluginTestCase extends TestCase
{
    protected static bool $plugin_loaded = false;

    protected function setUpMonkeyDefaults(): void
    {
        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('esc_html')->returnArg();
        Functions\when('esc_attr')->returnArg();
        Functions\when('esc_url')->returnArg();
        Functions\when('wp_unslash')->alias(static fn ($value) => $value);
        Functions\when('sanitize_text_field')->alias(static function ($str) {
            $str = strip_tags((string) $str);
            $str = str_replace("\0", '', $str);
            return trim($str);
        });
        Functions\when('sanitize_key')->alias(static function ($key) {
            return strtolower(preg_replace('/[^a-z0-9_\-]/', '', (string) $key));
        });
        Functions\when('add_settings_error')->justReturn(null);
        Functions\when('apply_filters')->alias(static fn ($filter, $value) => $value);
        Functions\when('wp_parse_args')->alias(static function ($args, $defaults) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            }
            if (is_array($args)) {
                return array_merge($defaults, $args);
            }
            return $defaults;
        });
        Functions\when('get_option')->alias(static fn ($option, $default = false) => $default);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('delete_transient')->justReturn(true);
        Functions\when('register_activation_hook')->justReturn(null);
        Functions\when('register_deactivation_hook')->justReturn(null);
        Functions\when('add_action')->justReturn(null);
        Functions\when('add_filter')->justReturn(null);
        Functions\when('is_admin')->justReturn(false);
        Functions\when('wp_remote_request')->justReturn(
            new \WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('wp_remote_get')->justReturn(
            new \WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('is_wp_error')->alias(static fn ($thing) => $thing instanceof \WP_Error);
    }

    protected function loadPluginClasses(): void
    {
        if (self::$plugin_loaded) {
            return;
        }

        $root = dirname(__DIR__, 2);
        require_once $root . '/src/imds.php';
        require_once $root . '/src/EventBridgePutEvents.php';
        require_once $root . '/src/EventBridgePostEvents.php';
        self::$plugin_loaded = true;
    }

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
        $this->setUpMonkeyDefaults();
        $this->loadPluginClasses();
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }
}