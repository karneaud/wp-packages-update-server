<?php
/*
Plugin Name: WP Packages Update Server
Plugin URI: https://github.com/froger-me/wp-packages-update-server/
Description: Run your own update server for plugins and themes.
Version: 2.0
Author: Alexandre Froger
Author URI: https://froger.me/
Text Domain: wppus
Domain Path: /languages
*/

if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
	global $wpdb, $wppus_mem_before, $wppus_scripts_before, $wppus_queries_before;

	$wppus_mem_before     = memory_get_peak_usage();
	$wppus_scripts_before = get_included_files();
	$wppus_queries_before = $wpdb->queries;
}

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

if ( ! defined( 'WPPUS_PLUGIN_PATH' ) ) {
	define( 'WPPUS_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );
}

if ( ! defined( 'WPPUS_PLUGIN_FILE' ) ) {
	define( 'WPPUS_PLUGIN_FILE', __FILE__ );
}

if ( ! defined( 'WPPUS_PLUGIN_URL' ) ) {
	define( 'WPPUS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}

if ( ! defined( 'WPPUS_MB_TO_B' ) ) {
	define( 'WPPUS_MB_TO_B', 1000000 );
}

if ( ! defined( 'WPPUS_DEFAULT_LOGS_MAX_SIZE' ) ) {
	define( 'WPPUS_DEFAULT_LOGS_MAX_SIZE', 10 );
}

if ( ! defined( 'WPPUS_DEFAULT_CACHE_MAX_SIZE' ) ) {
	define( 'WPPUS_DEFAULT_CACHE_MAX_SIZE', 100 );
}

if ( ! defined( 'WPPUS_PACKAGES_DIR' ) ) {
	define( 'WPPUS_PACKAGES_DIR', WP_CONTENT_DIR . '/uploads/' );
}


$require = array(
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-nonce.php',
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-data-manager.php',
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-cloud-storage-manager.php',
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-update-api.php',
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-license-api.php',
	WPPUS_PLUGIN_PATH . 'inc/class-wppus-webhook-api.php',
);

$require   = apply_filters( 'wppus_mu_require', $require );
$require[] = WPPUS_PLUGIN_PATH . 'lib/action-scheduler/action-scheduler.php';

foreach ( $require as $file ) {

	if ( file_exists( $file ) ) {
		require_once $file;
	}
}

if ( ! did_action( 'wppus_mu_init' ) ) {

	if ( class_exists( 'WPPUS_Nonce' ) ) {
		WPPUS_Nonce::register();
		WPPUS_Nonce::init_auth(
			array_merge(
				json_decode( get_option( 'wppus_package_private_api_keys', '{}' ), true ),
				json_decode( get_option( 'wppus_license_private_api_keys', '{}' ), true ),
			)
		);
	}

	if ( ! WPPUS_License_API::is_doing_api_request() ) {
		require_once WPPUS_PLUGIN_PATH . 'lib/wp-update-server/loader.php';
		require_once WPPUS_PLUGIN_PATH . 'lib/wp-update-server-extended/loader.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-update-server.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-package-api.php';
	}

	if (
		! WPPUS_Update_API::is_doing_api_request() &&
		! WPPUS_License_API::is_doing_api_request()
	) {
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wp-packages-update-server.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-remote-sources-manager.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-webhook-manager.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-package-manager.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-license-manager.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-api-manager.php';

		register_activation_hook( WPPUS_PLUGIN_FILE, array( 'WP_Packages_Update_Server', 'activate' ) );
		register_deactivation_hook( WPPUS_PLUGIN_FILE, array( 'WP_Packages_Update_Server', 'deactivate' ) );
		register_uninstall_hook( WPPUS_PLUGIN_FILE, array( 'WP_Packages_Update_Server', 'uninstall' ) );
		register_activation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_License_Manager', 'activate' ) );
		register_deactivation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_License_Manager', 'deactivate' ) );
		register_activation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Nonce', 'activate' ) );
		register_deactivation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Nonce', 'deactivate' ) );
		register_uninstall_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Nonce', 'uninstall' ) );
		register_activation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Webhook_manager', 'activate' ) );
		register_deactivation_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Webhook_manager', 'deactivate' ) );
		register_uninstall_hook( WPPUS_PLUGIN_FILE, array( 'WPPUS_Webhook_manager', 'uninstall' ) );
	}

	if ( defined( 'WP_CLI' ) && constant( 'WP_CLI' ) ) {
		require_once WPPUS_PLUGIN_PATH . 'functions.php';
		require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-cli.php';

		WP_CLI::add_command( 'wppus', 'WPPUS_CLI' );
	}
}

function wppus_run() {
	wp_cache_add_non_persistent_groups( 'wppus' );

	require_once WPPUS_PLUGIN_PATH . 'functions.php';

	$license_api_request  = wppus_is_doing_license_api_request();
	$priority_api_request = apply_filters( 'wppus_is_priority_api_request', $license_api_request );
	$is_api_request       = $priority_api_request;
	$objects              = apply_filters( 'wppus_objects', array() );

	if ( ! isset( $objects['license_api'] ) ) {
		$objects['license_api'] = new WPPUS_License_API( true, false );
	}

	if ( ! isset( $objects['webhook_api'] ) ) {
		$objects['webhook_api'] = new WPPUS_Webhook_API( true );
	}

	if ( ! $priority_api_request ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';

		do_action( 'wppus_no_priority_api_includes' );

		$is_api_request = (
			wppus_is_doing_update_api_request() ||
			wppus_is_doing_webhook_api_request() ||
			wppus_is_doing_package_api_request()
		);

		if ( ! isset( $objects['update_api'] ) ) {
			$objects['update_api'] = new WPPUS_Update_API( true );
		}

		if ( ! isset( $objects['package_api'] ) ) {
			$objects['package_api'] = new WPPUS_Package_API( true );
		}

		if ( ! isset( $objects['cloud_storage_manager'] ) ) {
			$objects['cloud_storage_manager'] = new WPPUS_Cloud_Storage_Manager( true );
		}
	}

	$is_api_request = apply_filters( 'wppus_is_api_request', $is_api_request );

	if ( ! $is_api_request ) {

		if ( ! class_exists( 'WP_List_Table' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
		}

		do_action( 'wppus_no_api_includes' );

		if ( ! isset( $objects['data_manager'] ) ) {
			$objects['data_manager'] = new WPPUS_Data_Manager( true );
		}

		if ( ! isset( $objects['remote_sources_manager'] ) ) {
			$objects['remote_sources_manager'] = new WPPUS_Remote_Sources_Manager( true );
		}

		if ( ! isset( $objects['webhook_manager'] ) ) {
			$objects['webhook_manager'] = new WPPUS_Webhook_Manager( true );
		}

		if ( ! isset( $objects['package_manager'] ) ) {
			require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-packages-table.php';

			$objects['package_manager'] = new WPPUS_Package_Manager( true );
		}

		if ( ! isset( $objects['license_manager'] ) ) {
			require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-licenses-table.php';

			$objects['license_manager'] = new WPPUS_License_Manager( true );
		}

		if ( ! isset( $objects['api_manager'] ) ) {
			$objects['api_manager'] = new WPPUS_API_Manager( true );
		}

		if ( ! isset( $objects['plugin'] ) ) {
			$objects['plugin'] = new WP_Packages_Update_Server( true );
		}
	}

	do_action( 'wppus_ready', $objects );
}
add_action( 'plugins_loaded', 'wppus_run', -99, 0 );

if ( ! WPPUS_Update_API::is_doing_api_request() && ! WPPUS_License_API::is_doing_api_request() ) {
	require_once __DIR__ . '/lib/wp-update-migrate/class-wp-update-migrate.php';

	if ( ! wp_doing_ajax() && is_admin() && ! wp_doing_cron() ) {
		add_action(
			'plugins_loaded',
			function () {
				$wppus_update_migrate = WP_Update_Migrate::get_instance( WPPUS_PLUGIN_FILE, 'wppus' );

				if ( false === $wppus_update_migrate->get_result() ) {

					if ( false !== has_action( 'plugins_loaded', 'wppus_run' ) ) {
						remove_action( 'plugins_loaded', 'wppus_run', -99 );
					}
				}
			},
			PHP_INT_MIN
		);
	}
}

if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {

	if ( WPPUS_Update_API::is_doing_api_request() || WPPUS_License_API::is_doing_api_request() ) {
		require_once WPPUS_PLUGIN_PATH . 'tests.php';
	}
}
