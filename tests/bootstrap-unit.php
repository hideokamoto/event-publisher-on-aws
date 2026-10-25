<?php
/**
 * PHPUnit bootstrap file for unit tests (no WordPress)
 *
 * Unit tests mock WordPress functions with Brain Monkey (Patchwork), which cannot redefine
 * a function that is already defined. Loading WordPress first makes every such mock fail
 * with Patchwork\Exceptions\DefinedTooEarly, so unit tests must never load WordPress, even
 * inside the wp-env tests-cli container. Run them with:
 *
 *     vendor/bin/phpunit --bootstrap tests/bootstrap-unit.php --testsuite unit
 */

// Load Composer autoloader for Brain Monkey and other dependencies
if (file_exists(dirname(__DIR__) . '/vendor/autoload.php')) {
    require_once dirname(__DIR__) . '/vendor/autoload.php';
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
