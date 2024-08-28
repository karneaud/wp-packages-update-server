<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit9eb5e761c6eb64cbd4f8776c2ff0f597
{
    public static $files = array (
        'd05ecc14ff93fd612a81ec7e8ab4c2c9' => __DIR__ . '/..' . '/yahnis-elsts/plugin-update-checker/load-v5p4.php',
        '2c7c83aca3c888b4f75c8c6263f094f7' => __DIR__ . '/..' . '/yahnis-elsts/wp-update-server/loader.php',
        'ce8c46e7dcdbbcb8866883fd6959fe6a' => __DIR__ . '/..' . '/wp-update-server-extended/loader.php',
        '24200b209e22feccfa120827cc5e5740' => __DIR__ . '/..' . '/proxy-update-checker/proxy-update-checker.php',
        '32df762862f6b56ff8bd942c8e0c1a51' => __DIR__ . '/..' . '/PhpS3/PhpS3.php',
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'WP_Update_Migrate' => __DIR__ . '/..' . '/froger-me/wp-update-migrate/class-wp-update-migrate.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->classMap = ComposerStaticInit9eb5e761c6eb64cbd4f8776c2ff0f597::$classMap;

        }, null, ClassLoader::class);
    }
}