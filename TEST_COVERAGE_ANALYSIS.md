# Test Coverage Analysis - EventBridge Post Events Plugin

## Executive Summary

This document analyzes the current test coverage of the EventBridge Post Events WordPress plugin and proposes areas for improvement. The plugin currently has good foundational testing with **8 test files** covering unit and integration scenarios, but several critical areas lack comprehensive coverage.

---

## Current Test Coverage Overview

### Existing Tests

#### Unit Tests (4 files)
1. **RegionDetectionTest.php** - AWS region detection from EC2 metadata
2. **CredentialResolutionTest.php** - AWS credential resolution
3. **SignatureV4Test.php** - AWS Signature V4 authentication
4. **EventBridgeErrorHandlingTest.php** - EventBridge API error handling

#### Integration Tests (3 files)
5. **PostStatusTransitionTest.php** - Post status transition events
6. **AdminSettingsTest.php** - Admin settings persistence
7. **ActivationDeactivationTest.php** - Plugin activation/deactivation

### Coverage Statistics

**Source Code:**
- Main plugin file: `event-publisher-on-aws.php` (2,269 lines)
- Uninstall handler: `uninstall.php` (96 lines)
- **Total:** ~2,365 lines of production code

**Classes:**
- `EventBridgePutEvents` - EventBridge API client
- `EventBridgePostEvents` - Main plugin orchestration class

**Public Functions:** 2 standalone functions + ~40+ class methods

---

## Critical Coverage Gaps

### 1. **EventBridgePutEvents Class - Critical Gaps**

#### Missing Tests:
- ✗ **`sendEvent()` method (line 155)** - Core functionality
  - No integration test actually calling this method
  - No test for successful event sending with real payload
  - No test for event size validation
  - No test for retry logic execution

- ✗ **`encode_and_validate()` method (line 476)** - Payload validation
  - No test for JSON encoding edge cases
  - No test for payload size limits (256KB EventBridge limit)
  - No test for malformed detail payloads
  - No test for Unicode/special character handling

- ✗ **Constructor validation**
  - No test for invalid credentials format
  - No test for empty/null parameters
  - No test for invalid region names

#### Partially Tested:
- ⚠ **`getSignatureKey()` (line 499)** - Only test vectors, missing edge cases
  - Missing test for empty secret key
  - Missing test for malformed date stamps

---

### 2. **EventBridgePostEvents Class - Major Gaps**

#### Settings & Configuration (Low Coverage)
- ✗ **`sanitize_and_validate_setting()` (line 759)** - Critical security function
  - No test for SQL injection attempts
  - No test for XSS payloads
  - No test for regex validation bypass attempts

- ✗ **`render_*_field()` methods (lines 1026-1208)** - 8 render methods
  - No test for HTML output escaping
  - No test for default value rendering
  - No test for field validation messages

- ✗ **`enqueue_admin_styles()` (line 796)** - Asset loading
  - No test for CSS file existence
  - No test for proper hook execution

#### Event Processing (Partial Coverage)
- ⚠ **`send_post_event()` (line 1692)** - Core event logic
  - ✓ Tested for basic publish/update/delete
  - ✗ Missing test for custom post types
  - ✗ Missing test for post_type filtering
  - ✗ Missing test for revision handling
  - ✗ Missing test for autosave exclusion
  - ✗ Missing test for bulk operations

- ✗ **`create_event_envelope()` (line 1569)** - Event format
  - No test for envelope vs legacy format
  - No test for metadata inclusion
  - No test for CloudEvents specification compliance

- ✗ **`get_or_create_correlation_id()` (line 1587)** - Correlation tracking
  - ✓ Tested in integration for basic generation
  - ✗ Missing test for race conditions
  - ✗ Missing test for UUID collision handling

#### Async Processing (No Coverage)
- ✗ **`dispatch_event()` (line 1810)** - Async vs sync decision
  - No test for send_mode setting respect
  - No test for cron scheduling
  - No test for immediate execution path

- ✗ **`async_send_event()` (line 1851)** - Cron callback
  - No test for event payload reconstruction
  - No test for scheduled event execution

- ✗ **`handle_send_failure()` (line 1863)** - Failure handling
  - No test for retry scheduling
  - No test for dead letter queue logic

#### Metrics & Monitoring (No Coverage)
- ✗ **`load_metrics()` (line 1352)** - Metrics initialization
- ✗ **`save_metrics()` (line 1371)** - Metrics persistence
- ✗ **`record_success()` (line 1385)** - Success tracking
- ✗ **`record_failure()` (line 1398)** - Failure tracking
- ✗ **`track_event_result()` (line 1437)** - Result tracking

#### Admin UI (Minimal Coverage)
- ✗ **`display_failure_notice()` (line 1898)** - Error notifications
  - No test for notice display conditions
  - No test for transient failure vs persistent failure

- ✗ **`handle_notice_dismissal()` (line 1984)** - AJAX handling
  - No test for nonce validation
  - No test for user capability checks

- ✗ **`handle_test_connection()` (line 2021)** - Connection testing
  - No test for successful connection
  - No test for connection failure scenarios
  - No test for credential validation

- ✗ **`handle_reset_metrics()` (line 2103)** - Metrics reset
  - No test for metrics clearing
  - No test for permission checks

#### Instance Metadata (Partial Coverage)
- ⚠ **`get_instance_identity()` (line 1457)** - EC2 metadata
  - ✓ Basic success case tested
  - ✗ Missing test for IMDSv2 token expiration
  - ✗ Missing test for caching behavior

- ✗ **`get_instance_credentials()` (line 1470)** - IAM role credentials
  - No test for credential retrieval
  - No test for credential expiration
  - No test for role assumption

---

### 3. **Standalone Functions - Gaps**

- ⚠ **`eventbridge_get_imds_token()` (line 24)** - IMDSv2 token
  - Tested indirectly through region detection
  - ✗ Missing dedicated test for token TTL
  - ✗ Missing test for network timeout

- ⚠ **`eventbridge_get_instance_identity_imdsv2()` (line 47)** - Instance identity
  - Tested in RegionDetectionTest
  - ✗ Missing test for cache invalidation
  - ✗ Missing test for failed cache behavior

- ✗ **`eventbridge_check_instance_role_credentials()` (line 112)** - Role check
  - No tests at all
  - Critical for IAM role detection

---

### 4. **Activation/Deactivation - Gaps**

- ⚠ **`eventbridge_post_events_activate()` (line 2142)** - Activation
  - ✓ Basic structure tested
  - ✗ Missing test for first-time activation
  - ✗ Missing test for re-activation after deactivation
  - ✗ Missing test for database migration scenarios

- ⚠ **`eventbridge_post_events_deactivate()` (line 2234)** - Deactivation
  - ✓ Cron cleanup tested
  - ✗ Missing test for option preservation

---

### 5. **Uninstall Process - No Coverage**

**File:** `uninstall.php` (96 lines, 0% coverage)

- ✗ **`eventbridge_post_events_uninstall_remove_options()`** - Option cleanup
- ✗ **`eventbridge_post_events_uninstall_remove_transients()`** - Transient cleanup
- ✗ **`eventbridge_post_events_uninstall_remove_post_meta()`** - Metadata cleanup
- ✗ **`eventbridge_post_events_uninstall_clear_scheduled_events()`** - Cron cleanup
- ✗ **Main uninstall execution flow**

**Risk:** Data leakage on uninstall, orphaned database records

---

### 6. **Error Scenarios - Insufficient Coverage**

#### Missing Error Tests:
- ✗ Network failures during event sending
- ✗ Partial batch failures from EventBridge
- ✗ EventBridge service throttling (429 errors)
- ✗ Invalid AWS credentials during runtime
- ✗ Region endpoint unavailability
- ✗ Payload exceeding 256KB limit
- ✗ Malformed JSON in event detail
- ✗ Database connection failures
- ✗ WordPress cron system failures

---

### 7. **Integration Scenarios - Missing**

- ✗ **Multi-site WordPress** - No tests for network installations
- ✗ **Custom post types** - Only default 'post' type tested
- ✗ **Post revisions** - Auto-revisions triggering duplicate events
- ✗ **Bulk operations** - Publishing 100+ posts simultaneously
- ✗ **Import/Export** - WordPress XML import triggering events
- ✗ **REST API** - Posts created via REST API
- ✗ **Gutenberg blocks** - Block editor interactions
- ✗ **Plugin conflicts** - Interaction with popular plugins (Yoast SEO, WooCommerce, etc.)

---

### 8. **Performance & Load Testing - Missing**

- ✗ Memory usage under high load
- ✗ Event sending latency measurements
- ✗ Database query optimization
- ✗ Concurrent post creation handling
- ✗ Cron job performance with 1000+ queued events

---

### 9. **Security Testing - Insufficient**

- ✗ **Input sanitization** - Only basic validation tested
- ✗ **Nonce verification** - Not tested for AJAX endpoints
- ✗ **Capability checks** - Admin-only functions not tested for privilege escalation
- ✗ **SQL injection** - Settings inputs not tested with malicious SQL
- ✗ **XSS prevention** - Admin page output not tested for script injection
- ✗ **CSRF protection** - Form submissions not tested

---

## Proposed Test Improvements

### Priority 1: Critical Functionality (High Impact)

#### 1.1 Core Event Sending
```php
// tests/integration/EventSendingTest.php
- test_send_event_success_with_real_payload()
- test_send_event_with_large_payload()
- test_send_event_retry_on_500_error()
- test_send_event_no_retry_on_400_error()
- test_send_event_throttling_backoff()
- test_send_event_with_unicode_characters()
- test_send_event_exceeding_size_limit()
```

#### 1.2 Event Payload Validation
```php
// tests/unit/PayloadValidationTest.php
- test_encode_and_validate_success()
- test_encode_and_validate_invalid_json()
- test_encode_and_validate_exceeds_size_limit()
- test_encode_and_validate_special_characters()
- test_encode_and_validate_null_values()
```

#### 1.3 Settings Sanitization
```php
// tests/unit/SettingsSanitizationTest.php
- test_sanitize_setting_valid_input()
- test_sanitize_setting_sql_injection_attempt()
- test_sanitize_setting_xss_attempt()
- test_sanitize_setting_regex_bypass()
- test_sanitize_setting_empty_input()
```

### Priority 2: Async & Error Handling (High Impact)

#### 2.1 Async Event Processing
```php
// tests/integration/AsyncEventProcessingTest.php
- test_async_event_scheduled_correctly()
- test_async_event_executes_on_cron()
- test_sync_event_executes_immediately()
- test_dispatch_respects_send_mode_setting()
- test_async_event_with_large_queue()
```

#### 2.2 Failure Handling
```php
// tests/integration/FailureHandlingTest.php
- test_handle_send_failure_schedules_retry()
- test_handle_send_failure_records_metrics()
- test_handle_send_failure_creates_notice()
- test_failure_notice_dismissal()
- test_retry_backoff_strategy()
- test_max_retry_limit()
```

#### 2.3 Metrics Tracking
```php
// tests/integration/MetricsTrackingTest.php
- test_record_success_increments_counter()
- test_record_failure_increments_counter()
- test_load_metrics_from_database()
- test_save_metrics_to_database()
- test_reset_metrics()
- test_metrics_not_autoloaded()
```

### Priority 3: Admin UI & Security (Medium Impact)

#### 3.1 Admin Settings Page
```php
// tests/integration/AdminUITest.php
- test_settings_page_renders_correctly()
- test_settings_fields_display_values()
- test_test_connection_button_success()
- test_test_connection_button_failure()
- test_reset_metrics_button()
- test_settings_save_validation()
```

#### 3.2 Security Tests
```php
// tests/integration/SecurityTest.php
- test_nonce_verification_ajax_endpoints()
- test_capability_check_admin_only()
- test_settings_sanitization_prevents_xss()
- test_settings_sanitization_prevents_sql_injection()
- test_csrf_protection_settings_form()
```

#### 3.3 Admin Notices
```php
// tests/integration/AdminNoticesTest.php
- test_failure_notice_displays()
- test_failure_notice_dismissal()
- test_credential_missing_notice()
- test_region_missing_notice()
- test_transient_notice_behavior()
```

### Priority 4: Edge Cases & Scenarios (Medium Impact)

#### 4.1 Custom Post Types
```php
// tests/integration/CustomPostTypesTest.php
- test_custom_post_type_enabled_sends_event()
- test_custom_post_type_disabled_no_event()
- test_multiple_post_types_configuration()
- test_post_type_filtering_logic()
```

#### 4.2 Post Revisions & Autosave
```php
// tests/integration/RevisionsAutosaveTest.php
- test_revision_does_not_trigger_event()
- test_autosave_does_not_trigger_event()
- test_published_revision_triggers_event()
```

#### 4.3 Event Envelope Formats
```php
// tests/unit/EventEnvelopeTest.php
- test_create_envelope_format()
- test_create_legacy_format()
- test_envelope_includes_correlation_id()
- test_envelope_includes_metadata()
- test_envelope_cloudevents_compliant()
```

#### 4.4 Instance Credentials
```php
// tests/unit/InstanceCredentialsTest.php
- test_get_instance_credentials_from_role()
- test_instance_credentials_expiration()
- test_instance_credentials_refresh()
- test_instance_credentials_caching()
- test_fallback_to_constants_when_no_role()
```

### Priority 5: Uninstall & Cleanup (Low Impact)

#### 5.1 Uninstall Process
```php
// tests/integration/UninstallTest.php
- test_uninstall_removes_options()
- test_uninstall_removes_transients()
- test_uninstall_removes_post_meta()
- test_uninstall_clears_cron_events()
- test_uninstall_complete_cleanup()
- test_uninstall_does_not_affect_other_plugins()
```

### Priority 6: Advanced Scenarios (Low Impact)

#### 6.1 Bulk Operations
```php
// tests/integration/BulkOperationsTest.php
- test_bulk_publish_100_posts()
- test_bulk_delete_posts()
- test_import_posts_via_xml()
```

#### 6.2 REST API Integration
```php
// tests/integration/RestAPITest.php
- test_post_created_via_rest_api()
- test_post_updated_via_rest_api()
- test_post_deleted_via_rest_api()
```

---

## Test Infrastructure Improvements

### 1. Code Coverage Reporting
Add to CI/CD pipeline:
```bash
composer test -- --coverage-html tests/coverage/html --coverage-text
```

**Goal:** Achieve >80% code coverage

### 2. Performance Benchmarking
```php
// tests/performance/EventSendingBenchmark.php
- benchmark_event_sending_latency()
- benchmark_async_event_queue_processing()
- benchmark_signature_generation()
```

### 3. Test Fixtures Enhancement
- Add more AWS API response fixtures
- Add fixture for EventBridge batch responses
- Add fixture for IAM role credential responses

### 4. Mock Improvements
- Create reusable mock factory for AWS clients
- Add helpers for WordPress hook testing
- Create database state helpers

---

## Coverage Metrics Goals

| Category | Current Est. | Target | Priority |
|----------|-------------|--------|----------|
| Core Event Sending | 30% | 90% | P1 |
| Settings & Config | 50% | 85% | P1 |
| Error Handling | 40% | 90% | P1 |
| Async Processing | 10% | 80% | P2 |
| Metrics Tracking | 0% | 75% | P2 |
| Admin UI | 20% | 70% | P3 |
| Security | 15% | 90% | P3 |
| Uninstall | 0% | 100% | P5 |
| **Overall** | **~25%** | **>80%** | - |

---

## Implementation Roadmap

### Phase 1 (Week 1-2): Critical Coverage
- [ ] Core event sending tests
- [ ] Payload validation tests
- [ ] Settings sanitization tests
- [ ] Achieve 50% overall coverage

### Phase 2 (Week 3-4): Async & Reliability
- [ ] Async event processing tests
- [ ] Failure handling tests
- [ ] Metrics tracking tests
- [ ] Achieve 65% overall coverage

### Phase 3 (Week 5-6): UI & Security
- [ ] Admin settings UI tests
- [ ] Security tests (XSS, SQL injection, CSRF)
- [ ] Admin notices tests
- [ ] Achieve 75% overall coverage

### Phase 4 (Week 7-8): Edge Cases
- [ ] Custom post types tests
- [ ] Revisions & autosave tests
- [ ] Event envelope format tests
- [ ] Instance credentials tests
- [ ] Achieve 80% overall coverage

### Phase 5 (Week 9-10): Completeness
- [ ] Uninstall process tests
- [ ] Bulk operations tests
- [ ] REST API integration tests
- [ ] Achieve >85% overall coverage

---

## Recommendations

### Immediate Actions
1. **Add core event sending integration tests** - Highest business risk
2. **Add settings sanitization tests** - Security critical
3. **Add async processing tests** - High impact on reliability
4. **Set up code coverage reporting in CI** - Visibility into progress

### Long-term Improvements
1. **Add performance benchmarking** - Prevent regressions
2. **Add load testing** - Validate scalability
3. **Add mutation testing** - Verify test quality
4. **Add contract testing** - Validate AWS API assumptions

### Testing Best Practices
1. **Follow AAA pattern** (Arrange, Act, Assert)
2. **Use descriptive test names** (`test_sends_event_when_post_published`)
3. **One assertion per test** (or closely related assertions)
4. **Mock external dependencies** (AWS API, EC2 metadata)
5. **Use data providers** for parametrized tests
6. **Test both happy path and error cases**

---

## Conclusion

The current test suite provides a solid foundation with good coverage of AWS authentication, region detection, and basic integration flows. However, **critical gaps exist** in:

1. **Core event sending functionality** (30% coverage)
2. **Async event processing** (10% coverage)
3. **Metrics tracking** (0% coverage)
4. **Security validation** (15% coverage)
5. **Uninstall cleanup** (0% coverage)

**Estimated current coverage: ~25%**
**Target coverage: >80%**

Implementing the proposed tests will significantly improve reliability, security, and maintainability of the plugin.
