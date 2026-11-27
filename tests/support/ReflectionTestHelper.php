<?php

declare(strict_types=1);

namespace EventPublisherOnAWS\Tests\Support;

use ReflectionMethod;

trait ReflectionTestHelper
{
    /**
     * @param array<int, mixed> $args
     */
    protected function invokePrivate(object $object, string $method, array $args = []): mixed
    {
        $reflection = new ReflectionMethod($object, $method);
        $reflection->setAccessible(true);

        return $reflection->invoke($object, ...$args);
    }
}