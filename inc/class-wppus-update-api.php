<?php

use YahnisElsts\PluginUpdateChecker\v5p4\Vcs\GitHubApi;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

class WPPUS_Update_API {
	protected static $instance;
	protected static $config;
	protected $update_server;
	protected static $api_version = 1;
	protected static $api_base_url = 'wppus';
	protected static $api_base_endpoint_url;
	protected static $doing_update_api_request = null;

	public function __construct($init_hooks = false, $version = 1) {
		self::$api_version = $version;
		self::$api_base_endpoint_url = sprintf("%s/v%d", self::$api_base_url ,self::$api_version);
		self::get_config();
		if($init_hooks) {
			$this->register_routes();
			add_action("init", function() { add_rewrite_rule( '^wppus/update/?$', 'index.php?$matches[1]&__wppus_update_api=1&action=download', 'top'); flush_rewrite_rules();  });
			add_filter('query_vars', function($vars) {
				$vars = array_merge(
					$vars,
					array(
						'__wppus_update_api',
						'action',
						'token',
						'package_id',
						'update_type',
					),
					array_keys($this->get_download_args())
				);
		
				return $vars;
			});
			add_action( 'parse_request', function(){
				global $wp;
				if ( isset( $wp->query_vars['__wppus_update_api'] ) ) {
					$request = new \WP_REST_Request('GET','');
					$request->set_query_params(array_intersect_key($wp->query_vars, $this->get_download_args() ));
					$this->download_package( $request );
				}
			}, 0 );
			
			add_action( 'wppus_checked_remote_package_update', array( $this, 'wppus_checked_remote_package_update' ), 10, 3 );
			add_action( 'wppus_removed_package', array( $this, 'wppus_removed_package' ), 10, 3 );
			add_action( 'wppus_primed_package_from_remote', array( $this, 'wppus_primed_package_from_remote' ), 10, 2 );
		}
		
		
	}
	/**
	 * Register the custom REST API routes based on action.
	 */
	public function register_routes() {
		add_action('rest_api_init', function () {
			// Route for getting metadata
			register_rest_route( self::$api_base_endpoint_url, '/packages/metadata', array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_metadata' ),
				'permission_callback' => '__return_true',//array( $this, 'permission_check' ),
				'args'                => $this->get_metadata_args(),
			));
			// Route for downloading packag
			register_rest_route(self::$api_base_endpoint_url, '/packages/download', array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'download_package' ),
				'permission_callback' => array( $this, 'permission_check' ),
				'args'                => $this->get_download_args(),
			));

			
		});
	}

	/**
	 * Check if the request has permission to run the update.
	 *
	 * @param WP_REST_Request $request
	 * @return bool|WP_Error
	 */
	public function permission_check( $request ) {
		if(!is_array(self::$config) || !array_key_exists('private_api_auth_keys', self::$config) || empty(self::$config['private_api_auth_keys'])) return true;

        $auth_header = $request->get_header('authorization');
        if (!$auth_header) {
            return new WP_Error('rest_forbidden', __('Authorization header not found.', 'wppus'), array('status' => 401));
        }
		

        list($token_type, $token) = explode(' ', $auth_header);
        if (strtolower($token_type) !== 'bearer' || !$token) {
            return new WP_Error('rest_forbidden', __('Invalid authorization header format.', 'wppus'), array('status' => 401));
        }

		define('EXPECTED_SECRET_KEY', self::$config['private_api_auth_keys'] );
        $secret_key = base64_decode($token);
        if (!$secret_key || !in_array($secret_key ,EXPECTED_SECRET_KEY))  { // Replace with the actual expected secret key
            return new WP_Error('rest_forbidden', __('Invalid secret key.', 'wppus'), array('status' => 401));
        }

        return true;
	}

	/**
	 * Handle the 'get_metadata' action.
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_metadata( $request ) {
		$params     = $request->get_params() + ['action'=>'get_metadata'];
		$params['slug'] = $params['package_id'];
		$status = 200;
		$this->init_server($params['package_id']);
		$params += ['license_key' => $params['update_license_key'] ?? null, 'license_signature' => $params['update_license_signature'] ?? null ];
		do_action( 'wppus_before_handle_update_request', $params );

		$response = $this->update_server->handleRequest($params);
		if ( is_wp_error( $response ) ) {
			$status = $response->get_error_code();
			$response = ['status' => $response->get_error_code(), 'message' => $response->get_error_message()];
		}

		return self::output_api_response($response, $status);
	}

	protected function output_api_response($args, $http_response_code = 200)
    {
        $args = (array) $args;
        if($http_response_code !== 200) $args = new \WP_Error(  $http_response_code, $args['message'], $args + ['status' => $http_response_code] );
        else $args = new \WP_Http_Response( $args, $http_response_code );

        return rest_ensure_response( $args );
    }

	/**
	 * Handle the 'download' action.
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response|WP_Error
	 */
	public function download_package( $request ) {
		$params     = $request->get_params();
		$package_id = $params['package_id'];
		$this->init_server($params['package_id']);
		$params = ['slug' => $params['package_id'] , 'action' => 'download'] + $params;
		do_action( 'wppus_before_handle_update_request', $params );

		$response = $this->update_server->handleRequest($params);
		if ( is_wp_error( $response ) ) {
			$status = $response->get_error_code();
			$response = ['status' => $response->get_error_code(), 'message' => $response->get_error_message()];
		}
	}

	/**
	 * Get the arguments for the 'get_metadata' endpoint.
	 *
	 * @return array
	 */
	protected function get_metadata_args() {
		return array(
			'package_id' => array(
				'description' => __( 'The package identifier.', 'wppus' ),
				'type'        => 'string',
				'required'    => true,
			),
			'installed_version' => array(
				'description' => __( 'The installed version of the package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			),
			'update_license_key' => array(
				'description' => __( 'The license key of the package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			),
			'update_license_signature' => array(
				'description' => __( 'The license signature of the package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			),
			'update_type' => array(
				'description' => __( 'The type of the update.', 'wppus' ),
				'type'        => 'string',
				'required'    => true,
				'enum'        => array( 'Generic', 'Plugin', 'Theme' ),
			),
			'checking_for_updates' => array(
				'description' => __( 'Bool to check for update', 'wppus' ),
				'type'        => 'int',
				'required'    => false,
			)
		);
	}

	/**
	 * Get the arguments for the 'download' endpoint.
	 *
	 * @return array
	 */
	protected function get_download_args() {
		return array(
			'package_id' => array(
				'description' => __( 'The package identifier.', 'wppus' ),
				'type'        => 'string',
				'required'    => true,
			),
			'token' => array(
				'description' => __( 'The token for the request.', 'wppus' ),
				'type'        => 'string',
				'required'    => true,
			),
			'license_key' => array(
				'description' => __( 'The license key of the package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			),
			'license_signature' => array(
				'description' => __( 'The license signature of the package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			),
			'update_type' => array(
				'description' => __( 'Type of package.', 'wppus' ),
				'type'        => 'string',
				'required'    => false,
			)
			
		);
	}

	/**
	 * Initialize the server with the necessary configuration.
	 *
	 * @param string $package_id The package identifier.
	 */
	protected function init_server( $package_id ) {
		$config            = self::get_config();
		$server_class_name = apply_filters(
			'wppus_server_class_name',
			'WPPUS_Update_Server',
			$package_id,
			$config
		);

		if ( ! isset( $this->update_server ) || ! is_a( $this->update_server, $server_class_name ) ) {
			$this->update_server = new $server_class_name(
				$config['use_remote_repository'],
				home_url( '/wppus/update/' ),
				$config['server_directory'],
				$config['repository_service_url'],
				$config['repository_branch'],
				$config['repository_credentials'],
				$config['repository_service_self_hosted'],
			);
		}

		$this->update_server = apply_filters(
			'wppus_update_server',
			$this->update_server,
			$config,
			$package_id
		);
	}

	public static function is_doing_api_request() {

		if ( null === self::$doing_update_api_request ) {
			self::$doing_update_api_request = ( false !== strpos( $_SERVER['REQUEST_URI'], 'wppus/update' ) );
		}

		return self::$doing_update_api_request;
	}

	public function wppus_checked_remote_package_update( $needs_update, $type, $slug ) {
		$this->schedule_check_remote_event( $slug );
	}

	public function wppus_primed_package_from_remote( $result, $slug ) {

		if ( $result ) {
			$this->schedule_check_remote_event( $slug );
		}
	}

	public function wppus_removed_package( $result, $type, $slug ) {

		if ( $result ) {
			as_unschedule_all_actions( 'wppus_check_remote_' . $slug );
		}
	}
	/**
	 * Validate the token for the request.
	 *
	 * @param string $token Token to validate.
	 * @param string $package_id Package ID associated with the token.
	 * @return bool
	 */
	protected function is_valid_token( $token, $package_id ) {
		// Implement token validation logic here.
		// Example: return ( $token === get_option( 'wppus_valid_token' ) );
		return true; // Replace this with actual validation logic
	}

	/**
	 * Get the configuration.
	 *
	 * @return array
	 */
	public static function get_config() {
		if ( ! self::$config ) {
			$config = array(
				'use_remote_repository'          => get_option( 'wppus_use_remote_repository' ),
				'server_directory'               => (new WPPUS_Data_Manager)::get_data_dir(),
				'repository_service_url'         => get_option( 'wppus_remote_repository_url' ),
				'repository_branch'              => get_option( 'wppus_remote_repository_branch', 'master' ),
				'repository_credentials'         => explode( '|', get_option( 'wppus_remote_repository_credentials' ) ),
				'repository_service_self_hosted' => get_option( 'wppus_remote_repository_self_hosted' ),
				'repository_check_frequency'     => get_option( 'wppus_remote_repository_check_frequency', 'daily' ),
			);

			$is_valid_schedule = in_array(
				strtolower( $config['repository_check_frequency'] ),
				array_keys( wp_get_schedules() ),
				true
			);

			if ( ! $is_valid_schedule ) {
				$config['repository_check_frequency'] = 'daily';
				update_option( 'wppus_remote_repository_check_frequency', 'daily' );
			}

			if ( 1 < count( $config['repository_credentials'] ) ) {
				$config['repository_credentials'] = array(
					'consumer_key'    => reset( $config['repository_credentials'] ),
					'consumer_secret' => end( $config['repository_credentials'] ),
				);
			} else {
				$config['repository_credentials'] = reset( $config['repository_credentials'] );
			}

			self::$config = $config;
		}

		return apply_filters( 'wppus_update_api_config', self::$config );
	}

	public static function get_instance() {

		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function check_remote_update( $slug, $type ) {
		$this->init_server( $slug );
		$this->update_server->set_type( $type );

		return $this->update_server->check_remote_package_update( $slug );
	}

	public function download_remote_package( $slug, $type = null, $force = false ) {
		$result = false;

		if ( ! $type ) {
			$types = array( 'Plugin', 'Theme', 'Generic' );

			foreach ( $types as $type ) {
				$result = $this->download_remote_package( $slug, $type, $force );

				if ( $result ) {
					break;
				}
			}

			return $result;
		}

		$this->init_server( $slug );
		$this->update_server->set_type( $type );

		if ( $force || $this->update_server->check_remote_package_update( $slug ) ) {
			$result = $this->update_server->save_remote_package_to_local( $slug );
		}

		return $result;
	}

	public function download_remote_package_from_url( $slug, $repo_url, $token, $type = 'Generic', $force = true ) {
		$result = false;
		self::$config['repository_credentials'] = $token;
		self::$config['repository_service_url'] = str_replace($slug,'',$repo_url);
		
		add_filter(
			'wppus_update_checker',
			function(
					$update_checker,
					$slug,
					$type,
					$repository_service_url,
					$repository_branch,
					$repository_credentials,
					$repository_service_self_hosted
				) use ($result) {
					$api = $update_checker->getVcsApi();
					$release = $api->getLatestRelease();
					$main_file = $api->getRemoteFile('style.css', $release->version) ? 'style.css' : "{$slug}.php";
					$asset = array_filter($release->apiResponse->assets, fn($a) => $a->name == "{$slug}.zip");
					$asset = array_shift(
						$asset
					);
					$result = (object) (compact('type','slug', 'main_file') + ['name'=> $slug, 'version' => $release->version, 'download_url' => $asset->browser_download_url ]);
					add_filter("puc_request_update_result-{$slug}", function($a,$b) use ($result) {
						if(empty($a)) $a = $result;
			
						return $a;
					} ,10, 2);

					return $update_checker;
			},
			10, 7
		);
		$this->init_server( $slug );
		$this->update_server->set_type( $type );
		//if ( $force || $this->update_server->check_remote_package_update( $slug ) ) {
			$result = $this->update_server->save_remote_package_to_local( $slug );
		//}

		return $result;
	}

	/*******************************************************************
	 * Protected methods
	 *******************************************************************/

	protected function schedule_check_remote_event( $slug ) {
		$config = self::get_config();

		if (
			apply_filters( 'wppus_use_recurring_schedule', true ) &&
			$config['use_remote_repository'] &&
			$config['repository_service_url']
		) {
			$hook   = 'wppus_check_remote_' . $slug;
			$params = array( $slug, null, false );

			if ( ! as_has_scheduled_action( $hook, $params ) ) {
				$frequency = apply_filters(
					'wppus_check_remote_frequency',
					$config['repository_check_frequency'],
					$slug
				);
				$timestamp = time();
				$schedules = wp_get_schedules();
				$result    = as_schedule_recurring_action(
					$timestamp,
					$schedules[ $frequency ]['interval'],
					$hook,
					$params
				);

				do_action( 'wppus_scheduled_check_remote_event', $result, $slug, $timestamp, $frequency, $hook, $params );
			}
		}
	}
}
