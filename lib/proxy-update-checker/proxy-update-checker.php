<?php
/**
 * Proxy Update Checker Library 1.0
 * https://froger.me/
 *
 * Copyright 2018 Alexandre Froger
 * Released under the MIT license. See license.txt for details.
 */


use YahnisElsts\PluginUpdateChecker\v5p4\Plugin;
use YahnisElsts\PluginUpdateChecker\v5p4\Theme;
use Anyape\ProxyUpdateChecker\Generic;
use YahnisElsts\PluginUpdateChecker\v5p4\Vcs;
use YahnisElsts\PluginUpdateChecker\v5p4\Vcs\GitHubApi;
use YahnisElsts\PluginUpdateChecker\v5p4\Vcs\GitLabApi;
use YahnisElsts\PluginUpdateChecker\v5p4\Vcs\BitBucketApi;

require dirname(__FILE__) . '/../yahnis-elsts/plugin-update-checker/plugin-update-checker.php';
require dirname(__FILE__) . '/Proxuc/Factory.php';
require dirname(__FILE__) . '/Proxuc/Autoloader.php';
new Proxuc_Autoloader();

//Register classes defined in this file with the factory.
Proxuc_Factory::setCheckerVersion('1.0');
Proxuc_Factory::addVersion('Vcs_PluginUpdateChecker', 'Proxuc_Vcs_PluginUpdateChecker', '1.0');
Proxuc_Factory::addVersion('Vcs_ThemeUpdateChecker', 'Proxuc_Vcs_ThemeUpdateChecker', '1.0');
Proxuc_Factory::addVersion('Vcs_GenericUpdateChecker', 'Proxuc_Vcs_GenericUpdateChecker', '1.0');

Proxuc_Factory::setApiVersion('5.0');
Proxuc_Factory::addVersion('GitHubApi', 'GitHubApi', '5.4');
Proxuc_Factory::addVersion('BitBucketApi', 'BitBucketApi', '5.4');
Proxuc_Factory::addVersion('GitLabApi', 'GitLabApi', '5.4');