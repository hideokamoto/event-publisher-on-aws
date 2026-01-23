# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-23

### ⚠️ BREAKING CHANGES

#### Event Format Change: Legacy Format No Longer Supported

The plugin now **only supports the Envelope format** for event payloads. The legacy format has been completely removed.

**What Changed:**
- `VALID_EVENT_FORMATS` constant now only contains `'envelope'`
- The event_format settings field has been removed from the admin UI
- All events are now sent in envelope format exclusively
- The `render_event_format_field()` method has been removed
- Settings validation now always enforces envelope format

**Impact on Downstream Consumers:**

If your downstream systems are consuming events from this plugin, you **must** update them to expect the envelope format.

**Legacy Format (No Longer Supported):**
```json
{
  "id": "123",
  "title": "Post Title",
  "content": "Post content",
  "status": "publish"
}
```

**Envelope Format (Now Required):**
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_timestamp": "2026-01-23T10:00:00+00:00",
  "event_version": "1.0",
  "source_system": "https://example.com",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440001",
  "data": {
    "id": "123",
    "title": "Post Title",
    "content": "Post content",
    "status": "publish"
  }
}
```

### Migration Guide for Downstream Systems

#### For EventBridge Rules and Targets

If you have EventBridge rules that parse event properties, update your event patterns:

**Before (Legacy Format):**
```json
{
  "detail": {
    "id": [{ "numeric": [123] }],
    "status": ["publish"]
  }
}
```

**After (Envelope Format):**
```json
{
  "detail": {
    "data": {
      "id": [{ "numeric": [123] }],
      "status": ["publish"]
    }
  }
}
```

#### For Lambda Functions and Event Consumers

Update your event parsing code:

**Before (Legacy Format):**
```php
$post_id = $event['detail']['id'];
$title = $event['detail']['title'];
$status = $event['detail']['status'];
```

**After (Envelope Format):**
```php
$post_id = $event['detail']['data']['id'];
$title = $event['detail']['data']['title'];
$status = $event['detail']['data']['status'];

// Access envelope metadata
$event_id = $event['detail']['event_id'];
$correlation_id = $event['detail']['correlation_id'];
$event_timestamp = $event['detail']['event_timestamp'];
$source_system = $event['detail']['source_system'];
```

### Benefits of Envelope Format

- **Traceability:** Event ID and correlation ID for tracking event flows
- **Metadata:** Timestamp and source information for audit trails
- **Structured Data:** Clear separation between event metadata and payload
- **Standards Compliance:** Follows event envelope patterns used in enterprise systems

### Migration Timeline

- **Version 2.0.0 (Current):** Legacy format is no longer supported
- **Action Required:** Update all downstream consumers to expect envelope format
- **Testing:** Test EventBridge rules, Lambda functions, and other consumers with envelope format before upgrading

### Removed

- Legacy event format support
- `VALID_EVENT_FORMATS` no longer includes 'legacy'
- `render_event_format_field()` admin UI method
- Event format setting from admin settings page
- Conditional logic in `prepare_event_payload()` for format selection
- Conditional logic in `handle_test_connection()` for format selection

### Changed

- Plugin version bumped to 2.0.0
- `prepare_event_payload()` now always returns envelope format
- `handle_test_connection()` now always sends envelope-wrapped test events
- `sanitize_settings()` now enforces envelope format for all configurations
- Test connection feature now exclusively uses envelope format

### Added

- Refactored test event envelope creation to use `create_event_envelope()` helper method
- Enhanced test coverage for rejecting legacy format in settings sanitization

---

## [1.0] - Initial Release

### Added

- Initial release of EventBridge Post Events plugin
- Support for both legacy and envelope event formats
- Admin settings page for configuration
- Event sending to AWS EventBridge
- Debug logging system
- Integration with WordPress post status transitions
