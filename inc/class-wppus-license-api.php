<?php
if (!defined('ABSPATH')) {
    exit;
}


class WPPUS_License_API {
    protected $license_server;
    protected $http_response_code = 200;
    protected $api_key_id;
    protected $api_access;
    protected static $doing_update_api_request = null;
    protected static $instance;
    protected static $config;
	protected static $api_version = 1;
	protected static $api_base_url = 'wppus';
	protected static $api_base_endpoint_url;

    public function __construct($init_hooks = false, $local_request = true, $version = 1)  {
		
        if (get_option('wppus_use_licenses')) {
			require_once WPPUS_PLUGIN_PATH . 'inc/class-wppus-license-server.php';
			
			self::$api_version = $version;
			self::$api_base_endpoint_url = sprintf("%s/v%d", self::$api_base_url ,self::$api_version);
			self::get_config();
			$this->init_server();
			$this->register_routes();
			
            add_action( 'wppus_pre_activate_license', array( $this, 'wppus_bypass_did_edit_license_action' ), 10, 0 );
            add_action( 'wppus_did_activate_license', array( $this, 'wppus_did_license_action' ), 10, 2 );
            add_action( 'wppus_pre_deactivate_license', array( $this, 'wppus_bypass_did_edit_license_action' ), 10, 0 );
            add_action( 'wppus_did_deactivate_license', array( $this, 'wppus_did_license_action' ), 10, 2 );
            add_action( 'wppus_did_add_license', array( $this, 'wppus_did_license_action' ), 10, 2 );
            add_action( 'wppus_did_edit_license', array( $this, 'wppus_did_license_action' ), 10, 3 );
            add_action( 'wppus_did_delete_license', array( $this, 'wppus_did_license_action' ), 10, 2 );
            add_filter( 'wppus_api_webhook_events', array( $this, 'wppus_api_webhook_events' ), 0, 1 );
        }
    }

    public function wppus_bypass_did_edit_license_action() {
		remove_action( 'wppus_did_edit_license', array( $this, 'wppus_did_license_action' ), 10 );
	}

    public function wppus_did_license_action( $result, $payload, $original = null ) {
		$format = '';
		$event  = 'license_' . str_replace(
			array( 'wppus_did_', '_license' ),
			array( '', '' ),
			current_action()
		);

		if ( ! is_object( $result ) ) {
			// translators: %s is operation slug
			$description = sprintf( esc_html__( 'An error occured for License operation `%s` on WPPUS.' ), $event );
			$content     = array(
				'error'   => true,
				'result'  => $result,
				'payload' => $payload,
			);
		} else {

			if ( null !== $original ) {
				unset( $original->id );
			}

			unset( $result->id );

			$content = null !== $original ?
				array(
					'new'      => $result,
					'original' => $original,
				) :
				$result;

			switch ( $event ) {
				case 'license_edit':
					// translators: %s is the license key
					$format = esc_html__( 'The license `%s` has been edited on WPPUS' );
					break;
				case 'license_add':
					// translators: %s is the license key
					$format = esc_html__( 'The license `%s` has been added on WPPUS' );
					break;
				case 'license_delete':
					// translators: %s is the license key
					$format = esc_html__( 'The license `%s` has been deleted on WPPUS' );
					break;
				case 'license_activate':
					// translators: %s is the license key
					$format = esc_html__( 'The license `%s` has been activated on WPPUS' );
					break;
				case 'license_deactivate':
					// translators: %s is the license key
					$format = esc_html__( 'The license `%s` has been deactivated on WPPUS' );
					break;
				default:
					return;
			}

			$description = sprintf( $format, $result->license_key );
		}

		$payload = array(
			'event'       => $event,
			'description' => $description,
			'content'     => $content,
		);

		add_filter( 'wppus_webhook_fire', array( $this, 'wppus_webhook_fire' ), 10, 4 );
		wppus_schedule_webhook( $payload, 'license' );
		remove_filter( 'wppus_webhook_fire', array( $this, 'wppus_webhook_fire' ), 10 );
	}

    public function wppus_webhook_fire( $fire, $payload, $url, $info ) {

		if ( ! isset( $info['licenseAPIKey'] ) || empty( $info['licenseAPIKey'] ) ) {
			return $fire;
		}

		$owner = false;

		if (
			is_array( $payload['content'] ) &&
			isset( $payload['content']['new'] ) &&
			isset( $payload['content']['new']->data['api_owner'] )
		) {
			$owner = $payload['content']['new']->data['api_owner'];
		} elseif (
			is_object( $payload['content'] ) &&
			isset( $payload['content']->data['api_owner'] )
		) {
			$owner = $payload['content']->data['api_owner'];
		}

		$config     = self::get_config();
		$api_access = false;

		foreach ( $config['private_api_auth_keys'] as $id => $values ) {

			if (
				$id === $info['licenseAPIKey'] &&
				isset( $values['access'] ) &&
				is_array( $values['access'] )
			) {
				$api_access = $values['access'];

				break;
			}
		}

		if ( $api_access && in_array( 'other', $api_access, true ) ) {
			$fire = true;
		} elseif ( $api_access ) {
			$action = str_replace( 'license_', '', $payload['event'] );

			if (
				in_array( 'all', $api_access, true ) ||
				in_array( 'read', $api_access, true ) ||
				in_array( 'browse', $api_access, true ) ||
				(
					in_array( $action, array( 'edit', 'add', 'delete' ), true ) &&
					in_array( $action, $api_access, true )
				)
			) {
				$fire = $owner === $info['licenseAPIKey'];
			} else {
				$fire = false;
			}
		} else {
			$fire = $owner === $info['licenseAPIKey'];
		}

		return $fire;
	}

    public function register_routes() {
        add_action('rest_api_init', function () {
            register_rest_route(self::$api_base_endpoint_url, '/licenses/browse', array(
                'methods' => 'POST',
                'callback' => array($this, 'api_browse'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_browse_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/read', array(
                'methods' => 'GET',
                'callback' => array($this, 'api_read'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/add', array(
                'methods' => 'POST',
                'callback' => array($this, 'api_add'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/edit', array(
                'methods' => 'PUT',
                'callback' => array($this, 'api_edit'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/delete', array(
                'methods' => 'DELETE',
                'callback' => array($this, 'api_delete'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/check', array(
                'methods' => 'GET',
                'callback' => array($this, 'api_check'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/activate', array(
                'methods' => 'POST',
                'callback' => array($this, 'api_activate'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));

            register_rest_route(self::$api_base_endpoint_url, '/licenses/deactivate', array(
                'methods' => 'POST',
                'callback' => array($this, 'api_deactivate'),
                'permission_callback' => array($this, 'verify_bearer_token'),
                'args' => $this->get_license_args()
            ));
        });
    }

    public function verify_bearer_token(WP_REST_Request $request) {

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

    protected function get_browse_args() {
        return array(
            'query' => array(
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field'
            )
        );
    }

    protected function get_license_args() {
        return array(
            'license_key' => array(
                'required' => true,
                'sanitize_callback' => 'sanitize_text_field'
            ),
            'allowed_domains' => array(
                //'sanitize_callback' => 'sanitize_text_field',
                'default' => array()
            ),
            'package_slug' => array(
                'sanitize_callback' => 'sanitize_text_field'
            )
        );
    }
    
    protected function init_server() {
        $this->license_server = apply_filters('wppus_license_server', new WPPUS_License_Server());
    }

    public static function get_instance() {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

	public static function is_doing_api_request() {

		if ( null === self::$doing_update_api_request ) {
			self::$doing_update_api_request = ( false !== strpos( $_SERVER['REQUEST_URI'], 'wppus-license-api' ) );
		}

		return self::$doing_update_api_request;
	}

	public static function get_config() {

		if ( ! self::$config ) {
			$keys   = json_decode( get_option( 'wppus_license_private_api_keys', '{}' ), true );
			$config = array(
				'private_api_auth_keys' => $keys,
				'ip_whitelist'          => get_option( 'wppus_license_private_api_ip_whitelist' ),
			);

			self::$config = $config;
		}

		return apply_filters( 'wppus_license_api_config', self::$config );
	}

    protected function output_api_response($args)
    {
        $args = (array) $args;
        if($this->http_response_code !== 200) $args = new \WP_Error(  $this->http_response_code, $args['message'], $args + ['status' => $this->http_response_code] );
        else $args = new \WP_Http_Response( $args, $this->http_response_code );

        return rest_ensure_response( $args );
    }

    public function edit( $license_data ) {
		unset( $license_data['data']['api_owner'] );

		$result = $this->license_server->edit_license( $license_data );

		if ( ! is_object( $result ) ) {
			if ( isset( $result['license_not_found'] ) ) {
				$this->http_response_code = 404;
			} else {
				$this->http_response_code = 400;
			}
		} else {

			if ( ! isset( $result->license_key ) ) {
				$this->http_response_code = 404;
				$result                   = array(
					'message' => __( 'License not found.', 'wppus' ),
				);
			}

			unset( $result->id );
		}

		return $result;
	}

    public function read($args = null) {
        $license_data = $args ? $args : array();
        $result = $this->license_server->read_license($license_data);
    
        if (!is_object($result)) {
            if (isset($result['license_not_found'])) {
                $this->http_response_code = 404;
            } else {
                $this->http_response_code = 400;
            }
        } else {
            if (!isset($result->license_key)) {
                $this->http_response_code = 404;
                $result = array('message' => __('License not found.', 'wppus'));
            }
        }
    
        return $result;
    }
    
    public function add($args = null) {
        $license_data = $args ? $args : array();
        if ($this->api_key_id) {
            $license_data['data']['api_owner'] = $this->api_key_id;
        }
        $result = $this->license_server->add_license($license_data);
    
        if (is_object($result)) {
            $result->result = 'success';
            $result->message = 'License successfully created';
            $result->key = $result->license_key;
            unset($result->id);
        } else {
            $this->http_response_code = 400;
        }
    
        return $result;
    }
    
    public function delete($args = null) {
        $license_data = $args ? $args : array();
        $result = $this->license_server->delete_license($license_data);
    
        if (!is_object($result)) {
            if (isset($license['license_not_found'])) {
                $this->http_response_code = 404;
            } else {
                $this->http_response_code = 400;
            }
        } elseif (!isset($result->license_key)) {
            $this->http_response_code = 404;
            $result = array('message' => __('License not found.', 'wppus'));
        }
    
        return $result;
    }
    
    public function activate($args = null) {
        $license_data = apply_filters('wppus_activate_license_dirty_payload', $args ? $args : array());
        $request_slug = isset($license_data['package_slug']) ? $license_data['package_slug'] : false;
        $license = $this->license_server->read_license($license_data);
        $result = array();
        $raw_result = array();
        do_action('wppus_pre_activate_license', $license);
    
        if (!isset($license_data['allowed_domains'])) {
            $license_data['allowed_domains'] = array();
        } elseif (!is_array($license_data['allowed_domains'])) {
            $license_data['allowed_domains'] = array($license_data['allowed_domains']);
        } else {
            $license_data['allowed_domains'] = array(reset($license_data['allowed_domains']));
        }
    
        if (in_array($license->status, array('expired', 'blocked', 'on-hold'), true)) {
            $this->http_response_code = 400;
            $result['status'] = $license->status;
            $result['message'] = __("License {$license->status}",'wppus');
        }
    
        if (is_object($license) && !empty($license_data['allowed_domains']) && $request_slug === $license->package_slug) {
            $domain_count = count($license_data['allowed_domains']) + count($license->allowed_domains);
    
            if ($domain_count > absint($license->max_allowed_domains)) {
                $result['max_allowed_domains'] = $license->max_allowed_domains;
                $result['message'] = __("License max {$license->max_allowed_domains}",'wppus');
                $this->http_response_code = 429;
            }
    
            if (empty($result)) {
                $payload = array(
                    'id' => $license->id,
                    'status' => 'activated',
                    'allowed_domains' => array_unique(array_merge($license_data['allowed_domains'], $license->allowed_domains)),
                );
                $result = $this->license_server->edit_license(apply_filters('wppus_activate_license_payload', $payload));
    
                if (is_object($result)) {
                    $result->license_signature = $this->license_server->generate_license_signature($license, reset($license_data['allowed_domains']));
                    unset($result->hmac_key);
                    unset($result->crypto_key);
                    unset($result->data);
                    unset($result->owner_name);
                    unset($result->email);
                    unset($result->company_name);
                    unset($result->id);
                    $raw_result = clone $result;
                } else {
                    $raw_result = $result;
                }
            }
        } else {
            $result['license_key'] = isset($license_data['license_key']) ? $license_data['license_key'] : false;
            $raw_result = $result;
        }
    
        if ($license_data['package_slug'] && $license->package_slug !== $license_data['package_slug']) {
            $result['package_slug'] = __('Plugin not valid','wppus');
            $result['message'] = __('Plugin/ Theme not valid','wppus');
            $this->http_response_code = 404;
        }
    
        $result = apply_filters('wppus_activate_license_result', $result, $license_data, $license);
        do_action('wppus_did_activate_license', $raw_result, $license_data);
    
        if (!is_object($result)) {
            $this->http_response_code = 400;
        }
    
        return $result;
    }
    
    public function deactivate($args = null) {
        $license_data = apply_filters('wppus_deactivate_license_dirty_payload', $args ? $args : array());
        $request_slug = isset($license_data['package_slug']) ? $license_data['package_slug'] : false;
        $license = $this->license_server->read_license($license_data);
        $result = array();
        $raw_result = array();
    
        do_action('wppus_pre_deactivate_license', $license);
    
        if (!isset($license_data['allowed_domains'])) {
            $license_data['allowed_domains'] = array();
        } elseif (!is_array($license_data['allowed_domains'])) {
            $license_data['allowed_domains'] = array($license_data['allowed_domains']);
        }
    
        if (is_object($license) && !empty($license_data['allowed_domains']) && $request_slug === $license->package_slug) {
            if ('expired' === $license->status) {
                $result['status'] = $license->status;
                $result['date_expiry'] = $license->date_expiry;
                $result['message'] = __('License has expired','wppus');
                $this->http_response_code = 400;
            } elseif ('blocked' === $license->status || 'on-hold' === $license->status) {
                $result['status'] = $license->status;
                $result['message'] = __('License not valid','wppus');
                $this->http_response_code = 404;
            } elseif ('deactivated' === $license->status || empty(array_intersect($license_data['allowed_domains'], $license->allowed_domains))) {
                $result['allowed_domains'] = $license_data['allowed_domains'];
                $result['message'] = __('License already deactivated','wppus');
                $this->http_response_code = 400;
            } elseif (isset($license->data, $license->data['next_deactivate']) && $license->data['next_deactivate'] > time()) {
                $result['next_deactivate'] = $license->data['next_deactivate'];
            }
    
            if (empty($result)) {
                $data = isset($license->data) ? $license->data : array();
                $data['next_deactivate'] = (bool)(defined('WP_DEBUG') && WP_DEBUG) ? time() : time() + MONTH_IN_SECONDS;
                $allowed_domains = array_diff($license->allowed_domains, $license_data['allowed_domains']);
                $payload = array(
                    'id' => $license->id,
                    'status' => empty($allowed_domains) ? 'deactivated' : $license->status,
                    'allowed_domains' => $allowed_domains,
                    'data' => $data,
                );
                $result = $this->license_server->edit_license(apply_filters('wppus_deactivate_license_payload', $payload));
    
                if (is_object($result)) {
                    $result->license_signature = $this->license_server->generate_license_signature($license, reset($license_data['allowed_domains']));
                    unset($result->hmac_key);
                    unset($result->crypto_key);
                    unset($result->data);
                    unset($result->owner_name);
                    unset($result->email);
                    unset($result->company_name);
                    unset($result->id);
                    $raw_result = clone $result;
                } else {
                    $result['message'] = __('License not deactivated','wppus');
                    $this->http_response_code = 404;
                    $raw_result = $result;
                    
                }
            }
        } else {
            $result['license_key'] = isset($license_data['license_key']) ? $license_data['license_key'] : false;
            $result['message'] = __('Plugn/ Theme or domain not valid','wppus');
            $raw_result = $result;
           
            $this->http_response_code = 404;
        }
    
        $result = apply_filters('wppus_deactivate_license_result', $result, $license_data, $license);
        do_action('wppus_did_deactivate_license', $raw_result, $license_data);
    
        if (!is_object($result)) {
            $this->http_response_code = 400;
        }
    
        return $result;
    }
    
    public function check($args = null) {
        $license_data = apply_filters('wppus_check_license_dirty_payload', $args ? $args : array());
        $result = $this->license_server->read_license($license_data);
        $raw_result = array();
    
        if (is_object($result)) {
            $raw_result = clone $result;
            unset($result->hmac_key);
            unset($result->crypto_key);
            unset($result->data);
            unset($result->owner_name);
            unset($result->email);
            unset($result->company_name);
            unset($result->id);
        } else {
            $result = array(
                'license_key' => isset($license_data['license_key']) ? $license_data['license_key'] : false,
            );
            $raw_result = $result;
        }
    
        $result = apply_filters('wppus_check_license_result', $result, $license_data);
        do_action('wppus_did_check_license', $raw_result);
    
        if (!is_object($result)) {
            $result['message'] = __('License not valid','wppus');
            $this->http_response_code = 404;
        }
    
        return $result;
    }
    
    public function browse($args = null) {
        $query = isset($args['query']) ? $args['query'] : null;
        $payload = json_decode(wp_unslash($query), true);
    
        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                if (!empty($payload['criteria'])) {
                    foreach ($payload['criteria'] as $index => $criteria) {
                        if ('id' === $criteria['field']) {
                            unset($payload['criteria'][$index]);
                        }
                    }
                }
                $result = $this->license_server->browse_licenses($payload);
                if (is_array($result) && !empty($result) && $this->api_access && $this->api_key_id && !in_array('other', $this->api_access, true)) {
                    foreach ($result as $index => $license) {
                        if (!isset($license->data, $license->data['api_owner']) || $license->data['api_owner'] !== $this->api_key_id) {
                            unset($result[$index]);
                        } else {
                            unset($result[$index]->id);
                        }
                    }
                }
                break;
            case JSON_ERROR_DEPTH:
                $result = 'JSON parse error - Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $result = 'JSON parse error - Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $result = 'JSON parse error - Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                $result = 'JSON parse error - Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                $result = 'JSON parse error - Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $result = 'JSON parse error - Unknown error';
                break;
        }
    
        if (!is_array($result)) {
            $result = array($result);
            $this->http_response_code = 400;
        } elseif (empty($result)) {
            $this->http_response_code = 404;
            $result = __('Licenses not found.', 'wppus');
        }
    
        return $result;
    }
    
    public function api_read(WP_REST_Request $request) {
        $response = $this->read($request->get_params());
        
        return $this->output_api_response($response);
    }
    
    public function api_add(WP_REST_Request $request) {
        $response = $this->add($request->get_params());
       
        return $this->output_api_response($response);
    }
    
    public function api_delete(WP_REST_Request $request) {
        $response = $this->delete($request->get_params());
        
        return $this->output_api_response($response);
    }
    
    public function api_activate(WP_REST_Request $request) {
        $response = $this->activate($request->get_params());
        
        return $this->output_api_response($response);
    }
    
    public function api_deactivate(WP_REST_Request $request) {
        $response = $this->deactivate($request->get_params());
        
        return $this->output_api_response($response);
    }
    
    public function api_check(WP_REST_Request $request) {
        $response = $this->check($request->get_params());
        
        return $this->output_api_response($response);
    }
    
    public function api_browse(WP_REST_Request $request) {
        $response = $this->browse($request->get_params());
        
        return $this->output_api_response($response);
    }
    
}
