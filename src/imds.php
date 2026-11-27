<?php
/**
 * Helper function to get IMDSv2 token
 * Used by both activation hook and main class
 *
 * @return string|null Token or null on failure
 */
function eventbridge_get_imds_token()
{
    $token_response = wp_remote_request('http://169.254.169.254/latest/api/token', array(
        'method' => 'PUT',
        'headers' => array('X-aws-ec2-metadata-token-ttl-seconds' => '21600'),
        'timeout' => 2,
    ));

    if (is_wp_error($token_response) || wp_remote_retrieve_response_code($token_response) !== 200) {
        return null;
    }

    $token = wp_remote_retrieve_body($token_response);
    return !empty($token) ? $token : null;
}

/**
 * Helper function to get instance identity using IMDSv2
 * Used by both activation hook and main class
 *
 * @param bool $use_cache Whether to use transient caching
 * @return array Instance identity data or empty array on failure
 */
function eventbridge_get_instance_identity_imdsv2($use_cache = true)
{
    $cache_key = 'eventbridge_imds_identity';
    $failed_cache_key = 'eventbridge_imds_failed';

    // Check cache if enabled
    if ($use_cache) {
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return $cached;
        }

        // Check failed cache to avoid repeated requests on non-EC2 environments
        if (get_transient($failed_cache_key) !== false) {
            return array();
        }
    }

    // Get IMDSv2 token
    $token = eventbridge_get_imds_token();
    if ($token === null) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300); // Cache failure for 5 minutes
        }
        return array();
    }

    // Fetch instance identity document with token
    $response = wp_remote_get('http://169.254.169.254/latest/dynamic/instance-identity/document', array(
        'headers' => array('X-aws-ec2-metadata-token' => $token),
        'timeout' => 2,
    ));

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300);
        }
        return array();
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
        if ($use_cache) {
            set_transient($failed_cache_key, true, 300);
        }
        return array();
    }

    // Cache successful result
    if ($use_cache) {
        set_transient($cache_key, $data, 3600); // Cache for 1 hour
    }

    return $data;
}

/**
 * Helper function to check if instance role credentials are available using IMDSv2
 * Used by activation hook to validate credential availability
 *
 * @return bool True if instance role credentials are available
 */
function eventbridge_check_instance_role_credentials()
{
    // Get IMDSv2 token
    $token = eventbridge_get_imds_token();
    if ($token === null) {
        return false;
    }

    // Try to get IAM role name
    $role_response = wp_remote_get('http://169.254.169.254/latest/meta-data/iam/security-credentials/', array(
        'headers' => array('X-aws-ec2-metadata-token' => $token),
        'timeout' => 2,
    ));

    if (is_wp_error($role_response) || wp_remote_retrieve_response_code($role_response) !== 200) {
        return false;
    }

    $role_name = trim(wp_remote_retrieve_body($role_response));
    return !empty($role_name);
}
