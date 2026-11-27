<?php

/**
 * Load plugin implementation files without WordPress bootstrap side effects.
 */
$root = dirname(__DIR__, 2);

require_once $root . '/src/imds.php';
require_once $root . '/src/EventBridgePutEvents.php';
require_once $root . '/src/EventBridgePostEvents.php';