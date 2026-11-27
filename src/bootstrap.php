<?php
/**
 * Production loader (no Composer autoload in distribution).
 */

require_once __DIR__ . '/imds.php';
require_once __DIR__ . '/EventBridgePutEvents.php';
require_once __DIR__ . '/EventBridgePostEvents.php';
require_once __DIR__ . '/lifecycle.php';