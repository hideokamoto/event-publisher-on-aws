<?php

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use EventBridgePostEvents;
use EventPublisherOnAWS\Tests\Support\ReflectionTestHelper;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class CredentialResolutionTest extends TestCase
{
    use ReflectionTestHelper;

    private EventBridgePostEvents $plugin;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        Functions\when('wp_unslash')->returnArg();
        Functions\when('sanitize_text_field')->returnArg();

        require_once dirname(__DIR__) . '/support/load-src.php';

        $reflection = new ReflectionClass(EventBridgePostEvents::class);
        $this->plugin = $reflection->newInstanceWithoutConstructor();
    }

    protected function tearDown(): void
    {
        putenv('AWS_ACCESS_KEY_ID');
        putenv('AWS_SECRET_ACCESS_KEY');
        unset($_ENV['AWS_ACCESS_KEY_ID'], $_SERVER['AWS_ACCESS_KEY_ID']);
        Monkey\tearDown();
        parent::tearDown();
    }

    public function test_get_env_var_reads_from_getenv(): void
    {
        putenv('AWS_ACCESS_KEY_ID=test-from-getenv');

        $value = $this->invokePrivate($this->plugin, 'get_env_var', ['AWS_ACCESS_KEY_ID']);

        $this->assertSame('test-from-getenv', $value);
    }

    public function test_get_env_var_falls_back_to_server(): void
    {
        putenv('AWS_ACCESS_KEY_ID');
        $_SERVER['AWS_ACCESS_KEY_ID'] = 'test-from-server';

        $value = $this->invokePrivate($this->plugin, 'get_env_var', ['AWS_ACCESS_KEY_ID']);

        $this->assertSame('test-from-server', $value);
    }

    public function test_phpunit_env_credentials_are_available(): void
    {
        $this->assertNotEmpty(getenv('AWS_EVENTBRIDGE_ACCESS_KEY_ID'));
        $this->assertNotEmpty(getenv('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY'));
    }
}