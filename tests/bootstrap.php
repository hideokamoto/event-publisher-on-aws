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
        die("Composer dependencies not installed. Run 'composer install' first.\n");
    }

    // Define WP_Error stub class for unit tests that don't have WordPress loaded
    if (!class_exists('WP_Error')) {
        /**
         * Minimal WP_Error stub for unit testing without WordPress
         */
        class WP_Error {
            private array $errors = [];
            private array $error_data = [];

            public function __construct(string $code = '', string $message = '', mixed $data = '') {
                if (empty($code)) {
                    return;
                }
                $this->errors[$code][] = $message;
                if (!empty($data)) {
                    $this->error_data[$code] = $data;
                }
            }

            public function get_error_codes(): array {
                return array_keys($this->errors);
            }

            public function get_error_code(): string {
                $codes = $this->get_error_codes();
                return empty($codes) ? '' : $codes[0];
            }

            public function get_error_messages(string $code = ''): array {
                if (empty($code)) {
                    return array_merge(...array_values($this->errors));
                }
                return $this->errors[$code] ?? [];
            }

            public function get_error_message(string $code = ''): string {
                if (empty($code)) {
                    $code = $this->get_error_code();
                }
                $messages = $this->get_error_messages($code);
                return empty($messages) ? '' : $messages[0];
            }

            public function get_error_data(string $code = ''): mixed {
                if (empty($code)) {
                    $code = $this->get_error_code();
                }
                return $this->error_data[$code] ?? null;
            }

            public function has_errors(): bool {
                return !empty($this->errors);
            }
        }
    }

    // Note: is_wp_error() is NOT defined here because Brain Monkey (via Patchwork)
    // needs to be able to mock it. Tests that need is_wp_error() should mock it
    // using Functions\when('is_wp_error')->justReturn() or similar.
    // Brain Monkey will be initialized in unit test bootstrap
}
