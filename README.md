# EventBridge Post Events - WordPress Plugin

A WordPress plugin that sends events to Amazon EventBridge when posts are published, updated, deleted, or scheduled.

## Features

- **AWS SDK Integration**: Uses official AWS SDK for PHP v3 for reliable EventBridge communication
- **Flexible Credential Management**: Supports multiple credential sources via provider chain:
  - IAM instance profile (EC2/ECS)
  - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
  - WordPress constants (`AWS_EVENTBRIDGE_ACCESS_KEY_ID`, `AWS_EVENTBRIDGE_SECRET_ACCESS_KEY`)
- **Region Auto-Detection**: Automatically detects AWS region from EC2 metadata with fallback options
- **Post Event Tracking**: Tracks post lifecycle events:
  - `post.published` - New post published
  - `post.updated` - Published post updated
  - `post.scheduled` - Post scheduled for future publication
  - `post.deleted` - Post deleted
- **Admin Settings Page**: WordPress admin interface for configuration and diagnostics
- **Error Handling**: Comprehensive error handling with retry logic and admin notifications
- **Event Validation**: Validates payload size and post types before sending
- **Lifecycle Hooks**: Proper activation, deactivation, and uninstall hooks
- **Testing**: Full PHPUnit test suite with unit and integration tests

## Installation

1. Install dependencies using Composer:
   ```bash
   composer install --no-dev
   ```

2. Upload the plugin to your WordPress plugins directory

3. Configure AWS credentials (choose one method):
   - **IAM Instance Profile** (recommended for EC2/ECS): No configuration needed
   - **Environment Variables**: Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - **WordPress Constants**: Add to `wp-config.php`:
     ```php
     define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'your-access-key');
     define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'your-secret-key');
     ```

4. Configure AWS region (optional, will auto-detect if running on EC2):
   ```php
   define('EVENT_BRIDGE_REGION', 'us-east-1');
   ```

5. Configure EventBridge settings (optional):
   ```php
   define('EVENT_BUS_NAME', 'your-event-bus');
   define('EVENT_SOURCE_NAME', 'wordpress');
   ```

6. Activate the plugin through WordPress admin

## Configuration

### Constants (wp-config.php)

| Constant | Description | Default |
|----------|-------------|---------|
| `AWS_EVENTBRIDGE_ACCESS_KEY_ID` | AWS access key ID | - |
| `AWS_EVENTBRIDGE_SECRET_ACCESS_KEY` | AWS secret access key | - |
| `EVENT_BRIDGE_REGION` | AWS region override | Auto-detected |
| `EVENT_BUS_NAME` | EventBridge event bus name | `wp-kyoto` |
| `EVENT_SOURCE_NAME` | Event source identifier | `wordpress` |
| `EVENTBRIDGE_ALLOWED_POST_TYPES` | Array of allowed post types | `['post', 'page']` |

### Admin Settings

Navigate to **Settings → EventBridge** in WordPress admin to:
- Configure event bus name and source
- Override AWS region
- View diagnostics (region, credentials, metrics)
- Test EventBridge connection
- Reset metrics
- View failure details

## Event Schema

Events are sent with the following envelope structure:

```json
{
  "event_id": "uuid-v4",
  "event_timestamp": "2024-01-01T00:00:00+00:00",
  "event_version": "1.0",
  "source_system": "https://your-site.com",
  "correlation_id": "uuid-v4",
  "data": {
    "id": "123",
    "title": "Post Title",
    "status": "publish",
    "previous_status": "draft",
    "updated_at": 1234567890,
    "permalink": "https://your-site.com/post-slug",
    "api_url": "https://your-site.com/wp-json/wp/v2/posts/123",
    "post_type": "post"
  }
}
```

## Development

### Requirements

- PHP 7.4 or higher
- Composer
- WordPress 5.0 or higher

### Running Tests

```bash
# Install dev dependencies
composer install

# Run all tests
composer test

# Run unit tests only
composer test:unit

# Run integration tests only
composer test:integration
```

### Setting Up Integration Tests

Integration tests require WordPress test library:

```bash
# Install WordPress test library
bash bin/install-wp-tests.sh wordpress_test root '' localhost latest

# Run integration tests
composer test:integration
```

## IAM Permissions

The plugin requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "events:PutEvents"
      ],
      "Resource": "arn:aws:events:REGION:ACCOUNT_ID:event-bus/EVENT_BUS_NAME"
    }
  ]
}
```

## Troubleshooting

### Check Plugin Status

Go to **Settings → EventBridge** to view:
- Detected AWS region and source
- Credential provider being used
- Success/failure metrics
- Recent error messages

### Enable Debug Logging

Add to `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

Check `wp-content/debug.log` for detailed error messages.

### Test Connection

Use the "Test Connection" button in **Settings → EventBridge** to verify:
- AWS credentials are valid
- EventBridge client can connect
- Event bus exists and is accessible

## Version History

### 2.0.0
- Replaced manual AWS Signature V4 signing with AWS SDK for PHP v3
- Implemented credential provider chain (IAM → ENV → Constants)
- Added region auto-detection with validation
- Implemented WordPress Settings API admin page
- Added lifecycle hooks (activation, deactivation, uninstall)
- Enhanced error handling with AWS exception catching
- Added payload validation and post type filtering
- Implemented comprehensive PHPUnit test suite
- Added GitHub Actions CI pipeline

### 1.0.0
- Initial release with manual AWS signing

## License

GPL-2.0-or-later

## Author

Your Name
