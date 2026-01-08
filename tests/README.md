# EventBridge Post Events - Test Suite

This directory contains the test suite for the EventBridge Post Events WordPress plugin.

## Overview

The test infrastructure uses:
- **PHPUnit** for running tests
- **wp-env** for local WordPress testing environment
- **Brain Monkey** for WordPress function mocking in unit tests
- **Yoast PHPUnit Polyfills** for cross-version PHP compatibility

## Test Structure

```
tests/
├── bootstrap.php              # Main test bootstrap for wp-env
├── wp-config-test.php         # WordPress test configuration
├── unit/                      # Unit tests (no WordPress)
│   ├── bootstrap.php          # Brain Monkey initialization
│   ├── CredentialResolutionTest.php
│   ├── RegionDetectionTest.php
│   ├── SignatureV4Test.php
│   └── EventBridgeErrorHandlingTest.php
├── integration/               # Integration tests (with WordPress)
│   ├── PostStatusTransitionTest.php
│   ├── AdminSettingsTest.php
│   └── ActivationDeactivationTest.php
└── fixtures/                  # Test fixtures and mock data
    └── aws-responses.php
```

## Prerequisites

1. **Node.js and npm** - For running wp-env
2. **Docker** - wp-env uses Docker containers
3. **Composer** - For installing PHP test dependencies (installed in container)

## Setup

### 1. Install Node.js dependencies

```bash
npm install
```

### 2. Start wp-env

```bash
npm run wp-env start
```

This will:
- Download and set up WordPress in Docker containers
- Mount the plugin in the WordPress installation
- Create a test database

### 3. Install PHP test dependencies (inside wp-env)

```bash
npm run test:setup
```

This installs Composer dependencies inside the wp-env container. **Important:** The `vendor/` directory is never created in your local plugin directory.

## Running Tests

### Run all tests

```bash
npm test
```

### Run unit tests only

```bash
npm run test:unit
```

Unit tests run quickly because they don't require WordPress. They use Brain Monkey to mock WordPress functions.

### Run integration tests only

```bash
npm run test:integration
```

Integration tests run with a full WordPress installation and test real plugin behavior.

## Test Suites

### Unit Tests

Unit tests verify individual components without WordPress:

- **CredentialResolutionTest**: Tests AWS credential resolution from environment variables and constants
- **RegionDetectionTest**: Tests region detection from EC2 metadata service with fallback logic
- **SignatureV4Test**: Tests AWS Signature Version 4 signing with known test vectors
- **EventBridgeErrorHandlingTest**: Tests error handling for various AWS API responses

### Integration Tests

Integration tests run with WordPress and test plugin integration:

- **PostStatusTransitionTest**: Tests that events are created when posts change status
- **AdminSettingsTest**: Tests settings persistence using WordPress options API
- **ActivationDeactivationTest**: Tests plugin lifecycle and state management

## Test Configuration

### phpunit.xml.dist

Main PHPUnit configuration file defining:
- Test suites (unit and integration)
- Bootstrap file location
- Environment variables
- Code coverage settings

### .wp-env.json

wp-env configuration defining:
- WordPress version
- PHP version
- Plugin mounting
- Test environment mappings

## Important Notes

### No Production Dependencies

This plugin uses **ONLY dev dependencies** (`require-dev` in composer.json):

- `phpunit/phpunit` - Testing framework
- `yoast/phpunit-polyfills` - PHP version compatibility
- `brain/monkey` - WordPress function mocking

**The `vendor/` directory must NEVER be distributed with the plugin.** The plugin code is entirely self-contained and has no production dependencies.

### Vendor Directory

- `vendor/` is in `.gitignore`
- `vendor/` only exists inside the wp-env Docker container
- GitHub Actions CI verifies `vendor/` is not present in the repository
- The workflow will fail if production dependencies are found

## Continuous Integration

Tests run automatically on GitHub Actions for:
- All pull requests
- Pushes to `main` and `develop` branches
- Multiple PHP versions: 7.4, 8.0, 8.1, 8.2
- Multiple WordPress versions: 6.4, 6.5, 6.6, 6.7, latest

See `.github/workflows/tests.yml` for the complete CI configuration.

## Writing Tests

### Unit Test Example

```php
namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class MyUnitTest extends TestCase
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

    public function test_something()
    {
        Functions\when('get_option')->justReturn('test-value');
        $this->assertEquals('test-value', get_option('test'));
    }
}
```

### Integration Test Example

```php
namespace EventPublisherOnAWS\Tests\Integration;

use WP_UnitTestCase;

class MyIntegrationTest extends WP_UnitTestCase
{
    public function test_something_with_wordpress()
    {
        $post_id = $this->factory()->post->create([
            'post_title' => 'Test Post',
        ]);

        $this->assertGreaterThan(0, $post_id);
    }
}
```

## Troubleshooting

### Tests not running

```bash
# Stop and restart wp-env
npm run wp-env stop
npm run wp-env start

# Reinstall dependencies
npm run test:setup
```

### Docker issues

```bash
# Check Docker is running
docker ps

# View wp-env logs
npm run wp-env logs
```

### Composer dependency issues

```bash
# Install dependencies manually
npm run wp-env run tests-cli --env-cwd=wp-content/plugins/event-publisher-on-aws "composer install --dev"
```

## Additional Commands

```bash
# Stop wp-env
npm run wp-env stop

# Destroy wp-env (clean slate)
npm run wp-env destroy

# Run wp-cli commands
npm run wp-env run cli wp --info

# Access tests-cli container shell
npm run wp-env run tests-cli bash
```

## Test Coverage

To generate code coverage reports (requires Xdebug):

```bash
npm run wp-env run tests-cli --env-cwd=wp-content/plugins/event-publisher-on-aws "vendor/bin/phpunit --coverage-html tests/coverage"
```

Coverage reports will be available in `tests/coverage/` directory.
