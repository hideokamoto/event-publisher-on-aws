<?php
/**
 * Unit tests for the retry loop in EventBridgePutEvents::sendEvent()
 *
 * Every test here calls the production class. wp_remote_request() is replaced with
 * Brain Monkey, so a test can count how many PutEvents requests the plugin sent and
 * feed it a sequence of responses. error_log() output goes to a temporary file, so a
 * test can read the line the plugin logged when it gave up.
 *
 * sleep() is replaced as well (patchwork.json lists it in "redefinable-internals").
 * Without that, every test that exercises the full retry schedule would block for
 * 1 + 2 + 4 = 7 seconds. The replacement records the delays the plugin asked for, so
 * the tests also check that the backoff schedule stays 1, 2, 4 seconds.
 */

namespace EventPublisherOnAWS\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

class SendEventRetryTest extends TestCase
{
    /**
     * Number of times wp_remote_request() was called
     *
     * @var int
     */
    private $requestCount = 0;

    /**
     * Arguments passed to sleep(), in call order
     *
     * @var int[]
     */
    private $sleeps = [];

    /**
     * tmpfile() handle for the error_log() output. PHP deletes the file when the
     * handle is closed, so the test never has to delete a file itself.
     *
     * @var resource|null
     */
    private $logHandle = null;

    /**
     * Path of the tmpfile() above, used as the error_log ini value
     *
     * @var string
     */
    private $logFile = '';

    /**
     * error_log ini value restored in tearDown()
     *
     * @var string|false
     */
    private $savedErrorLog = false;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        $this->logHandle = tmpfile();
        $this->logFile = stream_get_meta_data($this->logHandle)['uri'];
        $this->savedErrorLog = ini_get('error_log');
        ini_set('error_log', $this->logFile);

        // Mock WordPress functions BEFORE loading the plugin file: loading it
        // instantiates EventBridgePostEvents, which calls these.
        Functions\when('__')->returnArg();
        Functions\when('esc_html__')->returnArg();
        Functions\when('wp_parse_args')->alias(function ($args, $defaults) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            }
            if (is_array($args)) {
                return array_merge($defaults, $args);
            }
            return $defaults;
        });
        // Like WordPress, return the default when the option does not exist
        Functions\when('get_option')->alias(function ($option, $default = false) {
            return $default;
        });
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('delete_transient')->justReturn(true);
        Functions\when('register_activation_hook')->justReturn(null);
        Functions\when('register_deactivation_hook')->justReturn(null);
        Functions\when('add_action')->justReturn(null);
        Functions\when('add_filter')->justReturn(null);
        Functions\when('sanitize_text_field')->alias(function ($str) {
            return strip_tags($str);
        });
        Functions\when('get_post_types')->justReturn([
            'post' => (object)['name' => 'post', 'label' => 'Posts', 'labels' => (object)['name' => 'Posts']],
        ]);
        Functions\when('apply_filters')->alias(function ($filter, $value) {
            return $value;
        });
        // Prevent HTTP calls (IMDS lookups) during plugin initialization
        Functions\when('wp_remote_request')->justReturn(
            new \WP_Error('http_request_failed', 'Mocked error')
        );
        Functions\when('is_wp_error')->alias(function ($thing) {
            return $thing instanceof \WP_Error;
        });
        Functions\when('is_admin')->justReturn(false);

        if (!class_exists('EventBridgePutEvents')) {
            require_once dirname(dirname(__DIR__)) . '/event-publisher-on-aws.php';
        }

        // Functions sendEvent() calls
        Functions\when('wp_json_encode')->alias(function ($data) {
            return json_encode($data);
        });
        Functions\when('wp_remote_retrieve_response_code')->alias(function ($response) {
            return $response['response']['code'];
        });
        Functions\when('wp_remote_retrieve_body')->alias(function ($response) {
            return $response['body'];
        });
        Functions\when('sleep')->alias(function ($seconds) {
            $this->sleeps[] = $seconds;
            return 0;
        });
    }

    protected function tearDown(): void
    {
        ini_set('error_log', $this->savedErrorLog === false ? '' : $this->savedErrorLog);
        if (is_resource($this->logHandle)) {
            fclose($this->logHandle); // Also deletes the temporary file
        }
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Make wp_remote_request() return the given responses in order.
     * After the list runs out, the last response is returned again.
     *
     * @param array $responses wp_remote_request() return values
     */
    private function stubResponses(array $responses): void
    {
        $this->requestCount = 0;
        Functions\when('wp_remote_request')->alias(function () use ($responses) {
            $index = min($this->requestCount, count($responses) - 1);
            $this->requestCount++;
            return $responses[$index];
        });
    }

    private static function httpResponse(int $code, string $body): array
    {
        return ['response' => ['code' => $code], 'body' => $body];
    }

    /**
     * A PutEvents 200 response in which the only entry failed with $errorCode
     */
    private static function partialFailure(string $errorCode): array
    {
        return self::httpResponse(200, json_encode([
            'FailedEntryCount' => 1,
            'Entries' => [
                ['ErrorCode' => $errorCode, 'ErrorMessage' => 'message for ' . $errorCode],
            ],
        ]));
    }

    private static function success(): array
    {
        return self::httpResponse(200, json_encode([
            'FailedEntryCount' => 0,
            'Entries' => [['EventId' => 'test-event-id']],
        ]));
    }

    private function sendEvent(): array
    {
        $client = new \EventBridgePutEvents('test-access-key', 'test-secret-key', 'us-east-1');
        return $client->sendEvent('wordpress', 'post.published', ['id' => '123']);
    }

    private function loggedText(): string
    {
        return (string)file_get_contents($this->logFile);
    }

    /**
     * ErrorCode values listed under "Non-retryable errors include:" in the EventBridge
     * API model (PutEventsResultEntry, member ErrorCode)
     */
    public function nonRetryableErrorCodes(): array
    {
        return [
            'AccessDeniedException' => ['AccessDeniedException'],
            'InvalidAccountIdException' => ['InvalidAccountIdException'],
            'InvalidArgument' => ['InvalidArgument'],
            'MalformedDetail' => ['MalformedDetail'],
            'RedactionFailure' => ['RedactionFailure'],
            'NotAuthorizedForSourceException' => ['NotAuthorizedForSourceException'],
            'NotAuthorizedForDetailTypeException' => ['NotAuthorizedForDetailTypeException'],
        ];
    }

    /**
     * ErrorCode values listed under "Retryable errors include:" in the same model
     */
    public function retryableErrorCodes(): array
    {
        return [
            'InternalFailure' => ['InternalFailure'],
            'ThrottlingException' => ['ThrottlingException'],
        ];
    }

    /**
     * A partial failure whose ErrorCode is non-retryable must not be resent.
     *
     * @dataProvider nonRetryableErrorCodes
     */
    public function test_partial_failure_with_non_retryable_error_code_is_sent_once(string $errorCode)
    {
        $this->stubResponses([self::partialFailure($errorCode)]);

        $result = $this->sendEvent();

        $this->assertSame(1, $this->requestCount, 'A non-retryable partial failure must be sent only once');
        $this->assertSame([], $this->sleeps, 'No backoff delay is needed when nothing is retried');
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('ErrorCode=' . $errorCode, $result['error']);
        $this->assertFalse($result['is_transient'], 'A failure that is not retried is reported as permanent');
    }

    /**
     * Retryable partial failures keep the existing retry schedule: 4 requests, 1/2/4 s backoff.
     *
     * @dataProvider retryableErrorCodes
     */
    public function test_partial_failure_with_retryable_error_code_is_retried(string $errorCode)
    {
        $this->stubResponses([self::partialFailure($errorCode)]);

        $result = $this->sendEvent();

        $this->assertSame(4, $this->requestCount);
        $this->assertSame([1, 2, 4], $this->sleeps);
        $this->assertFalse($result['success']);
        $this->assertTrue($result['is_transient']);
        $this->assertStringContainsString('[EventBridge] FAILED after 4 attempts - DetailType: post.published', $this->loggedText());
    }

    /**
     * The model's lists say "include", so they are not exhaustive. An ErrorCode in neither
     * list keeps the behaviour it had before: it is retried.
     */
    public function test_partial_failure_with_unlisted_error_code_is_still_retried()
    {
        $this->stubResponses([self::partialFailure('SomeUnlistedErrorCode')]);

        $result = $this->sendEvent();

        $this->assertSame(4, $this->requestCount);
        $this->assertSame([1, 2, 4], $this->sleeps);
        $this->assertFalse($result['success']);
        $this->assertTrue($result['is_transient']);
    }

    public function test_retryable_partial_failure_followed_by_success_returns_success()
    {
        $this->stubResponses([self::partialFailure('ThrottlingException'), self::success()]);

        $result = $this->sendEvent();

        $this->assertSame(2, $this->requestCount);
        $this->assertSame([1], $this->sleeps);
        $this->assertTrue($result['success']);
        $this->assertStringNotContainsString('FAILED after', $this->loggedText());
    }

    /**
     * Responses the plugin does not retry. Each must be sent once, and the final log line
     * must say so.
     */
    public function notRetriedResponses(): array
    {
        return [
            'HTTP 400' => [self::httpResponse(400, json_encode(['__type' => 'ValidationException', 'message' => 'Invalid parameter']))],
            'HTTP 403' => [self::httpResponse(403, json_encode(['__type' => 'AccessDeniedException', 'message' => 'Denied']))],
            'HTTP 200 with a body that is not JSON' => [self::httpResponse(200, 'not json')],
            'partial failure with NotAuthorizedForSourceException' => [self::partialFailure('NotAuthorizedForSourceException')],
        ];
    }

    /**
     * @dataProvider notRetriedResponses
     */
    public function test_failure_log_reports_one_attempt_when_the_request_is_not_retried(array $response)
    {
        $this->stubResponses([$response]);

        $result = $this->sendEvent();

        $this->assertFalse($result['success']);
        $this->assertSame(1, $this->requestCount);
        $log = $this->loggedText();
        $this->assertStringContainsString('[EventBridge] FAILED after 1 attempts - DetailType: post.published', $log);
        $this->assertStringNotContainsString('FAILED after 4 attempts', $log);
    }

    /**
     * Retryable failures keep the existing retry schedule and the existing log line.
     */
    public function retriedResponses(): array
    {
        return [
            'HTTP 500' => [self::httpResponse(500, json_encode(['__type' => 'InternalException', 'message' => 'Internal error']))],
            'HTTP 503' => [self::httpResponse(503, 'Service Unavailable')],
            'HTTP 429' => [self::httpResponse(429, json_encode(['__type' => 'ThrottlingException', 'message' => 'Rate exceeded']))],
            'WP_Error (network error)' => [new \WP_Error('http_request_failed', 'Connection timed out')],
        ];
    }

    /**
     * @dataProvider retriedResponses
     */
    public function test_retryable_failure_is_sent_four_times_and_logged_as_four_attempts($response)
    {
        $this->stubResponses([$response]);

        $result = $this->sendEvent();

        $this->assertFalse($result['success']);
        $this->assertTrue($result['is_transient']);
        $this->assertSame(4, $this->requestCount);
        $this->assertSame([1, 2, 4], $this->sleeps);
        $this->assertStringContainsString('[EventBridge] FAILED after 4 attempts - DetailType: post.published', $this->loggedText());
    }

    public function test_retryable_http_error_followed_by_success_returns_success()
    {
        $this->stubResponses([self::httpResponse(500, 'Internal error'), self::success()]);

        $result = $this->sendEvent();

        $this->assertSame(2, $this->requestCount);
        $this->assertSame([1], $this->sleeps);
        $this->assertTrue($result['success']);
    }
}
