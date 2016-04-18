<?php

/**
 * This file implements a trimmed down version of the SSP module aware autoloader that can be used in tests.
 *
 * @author Patrick Radtke
 */

/**
 * Autoload function for local SimpleSAMLphp modules.
 *
 * @param string $className Name of the class.
 */
function SimpleSAML_test_module_autoload($className)
{
    $modulePrefixLength = strlen('sspmod_');
    $classPrefix = substr($className, 0, $modulePrefixLength);
    if ($classPrefix !== 'sspmod_') {
        return;
    }

    $modNameEnd = strpos($className, '_', $modulePrefixLength);
    $moduleClass = substr($className, $modNameEnd + 1);

    $file = dirname(dirname(__FILE__)) . '/lib/' . str_replace('_', '/', $moduleClass) . '.php';

    if (file_exists($file)) {
        require_once($file);
    }
}

spl_autoload_register('SimpleSAML_test_module_autoload');
