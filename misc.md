# WP Packages Update Server - Miscellaneous - Developer documentation
(Looking for the main documentation page instead? [See here](https://github.com/froger-me/wp-packages-update-server/blob/master/README.md))

WP Packages Update Server provides an API and offers a series of functions, actions and filters for developers to use in their own plugins and themes to modify the behavior of the plugin. Below is the documentation to interface with miscellaneous aspects of WP Packages Update Server. 

* [WP Packages Update Server - Miscellaneous - Developer documentation](#wp-packages-update-server---miscellaneous---developer-documentation)
	* [Nonce API](#nonce-api)
	* [Functions](#functions)
		* [php\_log](#php_log)
		* [cidr\_match](#cidr_match)
		* [wppus\_is\_doing\_api\_request](#wppus_is_doing_api_request)
			* [wppus\_is\_doing\_webhook\_api\_request](#wppus_is_doing_webhook_api_request)
			* [wppus\_init\_nonce\_auth](#wppus_init_nonce_auth)
			* [wppus\_create\_nonce](#wppus_create_nonce)
			* [wppus\_get\_nonce\_expiry](#wppus_get_nonce_expiry)
			* [wppus\_validate\_nonce](#wppus_validate_nonce)
			* [wppus\_delete\_nonce](#wppus_delete_nonce)
			* [wppus\_delete\_nonce](#wppus_delete_nonce-1)
	* [Actions](#actions)
		* [wppus\_no\_api\_includes](#wppus_no_api_includes)
		* [wppus\_no\_license\_api\_includes](#wppus_no_license_api_includes)
	* [Filters](#filters)
		* [wppus\_is\_api\_request](#wppus_is_api_request)
		* [wppus\_page\_wppus\_scripts\_l10n](#wppus_page_wppus_scripts_l10n)
		* [wppus\_nonce\_api\_code](#wppus_nonce_api_code)
		* [wppus\_nonce\_api\_response](#wppus_nonce_api_response)
		* [wppus\_created\_nonce](#wppus_created_nonce)
		* [wppus\_clear\_nonces\_query](#wppus_clear_nonces_query)
		* [wppus\_clear\_nonces\_query\_args](#wppus_clear_nonces_query_args)
		* [wppus\_expire\_nonce](#wppus_expire_nonce)
		* [wppus\_delete\_nonce](#wppus_delete_nonce-2)
		* [wppus\_fetch\_nonce](#wppus_fetch_nonce)

## Nonce API

The nonce API is accessible via `POST` and `GET` requests on the `/wppus-token/` endpoint to acquire a reusable token, and `/wppus-nonce/` to acquire a true nonce.  
It accepts form-data payloads (arrays, basically). This documentation page uses `wp_remote_post`, but `wp_remote_get` would work as well.

Authorization is granted with either the `HTTP_X_WPPUS_PRIVATE_PACKAGE_API_KEY` header in `POST` (recommended) or with the `api_auth_key` parameter for both `POST` and `GET` ; the key is the Private API Authentication Key of the Packages API by default (authorization key and header may be overriden with the `wppus_init_nonce_auth` [function](#wppus_init_nonce_auth)).  
**Using `GET` requests directly in the browser, whether through the URL bar or JavaScript, is strongly discouraged due to security concerns** ; it should be avoided at all cost to prevent the inadvertent exposure of the authorization key.

In case the Private API Authentication Key is invalid, the API will return the following response (message's language depending on availabe translations), with HTTP response code set to `403`:

Response `$data` - forbidden access:
```json
{
	"message": "Unauthorized access"
}
```

The description of the API below is using the following code as reference, where `$params` are the parameters passed to the API (other parameters can be adjusted, they are just WordPress' default) and `$data` is the JSON response:

```php
$url = 'https://domain.tld/wppus-nonce/'; // Replace domain.tld with the domain where WP Packages Update Server is installed.
$url = 'https://domain.tld/wppus-token/'; // Replace domain.tld with the domain where WP Packages Update Server is installed.

$response = wp_remote_post(
	$url,
	array(
		'method'      => 'POST',
		'timeout'     => 45,
		'redirection' => 5,
		'httpversion' => '1.0',
		'blocking'    => true,
		'headers'     => array(),
		'body'        => $params,
		'cookies'     => array(),
	);
);

if ( is_wp_error( $response ) ) {
	printf( esc_html__( 'Something went wrong: %s', 'text-domain' ), esc_html( $response->get_error_message() ) );
} else {
	$data         = wp_remote_retrieve_body( $response );
	$decoded_data = json_decode( $data );

	if ( '200' === $response->code ) {
		// Handle success with $decoded_data
	} else {
		// Handle failure with $decoded_data
	}
}
```

Parameters to aquire a reusable token or a true nonce:

```php
$params = array(
	'expiry_length' => 999,          // The expiry length in seconds (optional - default value to WPPUS_Nonce::DEFAULT_EXPIRY_LENGTH - 30 seconds)
	'data' => array(                 // Data to store along the token or true nonce (optional)
		'permanent' => false,        // set to a truthy value to create a nonce that never expires
		'key1'      => 'value1',     // custom data
		'key2'      => array(        // custom data can be as nested as needed
			'subkey1' => 'subval1',
			'subkey2' => 'subval2'
		),
	),
	'api_auth_key'  => 'secret',     // The Private API Authentication Key (optional - must provided via X-WPPUS-Private-Package-API-Key headers, or overriden header name, if absent)
);
```

Response `$data` - **success**:
```json
{
	"nonce": "nonce_value",
    "true_nonce": true|false,
    "expiry": 9999999999,
    "data": {
		"key1": "value1",
		"key2": "value2",
		"key3": {
			"subkey1": "subval1",
			"subkey2": "subval2"
		},
	}
}
```
## Functions

The functions listed below are made publicly available by the plugin for theme and plugin developers. They can be used after the action `plugins_loaded` has been fired, or in a `plugins_loaded` action (just make sure the priority is above `-99`).  
Although the main classes can theoretically be instanciated without side effect if the `$hook_init` parameter is set to `false`, it is recommended to use only the following functions as there is no guarantee future updates won't introduce changes of behaviors.

___
### php_log

```php
php_log( mixed $message = '', string $prefix = '' );
```

**Description**  
Convenience function to log a message to `error_log`.

**Parameters**  
`$message`
> (mixed) the message to log ; can be any variable  

`$prefix`
> (string) a prefix to add before the variable ; useful to add context  

___
### cidr_match

```php
cidr_match( $ip, $range );
```

**Description**  
Check whether an IP address is a match for the provided CIDR range.

**Parameters**  
`$ip`
> (string) the IP address to check  

`$range`
> (string) a CIDR range  

**Return value**
> (bool) whether an IP address is a match for the provided CIDR range

___
### wppus_is_doing_api_request

```php
wppus_is_doing_api_request()
```

**Description**  
Determine whether the current request is made by a remote client interacting with any of the APIs.

**Return value**
> (bool) `true` if the current request is made by a remote client interacting with any of the APIs, `false` otherwise

___
#### wppus_is_doing_webhook_api_request

```php
wppus_is_doing_webhook_api_request()
```

**Description**  
Determine wether the current request is made by a Webhook.

**Return value**
> (bool) `true` if the current request is made by a Webhook, `false` otherwise

___
#### wppus_init_nonce_auth

```php
wppus_init_nonce_auth( string $private_auth_key, string|null $auth_header_name = null )
```

**Description**  
Set the Private Authorization Key and the Authorization Header name used to request nonces via the `wppus-token` and `wppus-nonce` endpoints.  
If the Authentication Header name is not set, the `api_auth_key` variable set in `POST` method is used instead when requesting nonces.

**Parameters**  
`$private_auth_key`
> (string) the Private Authorization Key  

`$auth_header_name`
> (string|null) the Authorization Header name  

___
#### wppus_create_nonce

```php
wppus_create_nonce( bool $true_nonce = true, int $expiry_length = WPPUS_Nonce::DEFAULT_EXPIRY_LENGTH, array $data = array(), int $return_type = WPPUS_Nonce::NONCE_ONLY, bool $store = true, bool|callable )
```

**Description**  
Creates a cryptographic token - allows creation of tokens that are true one-time-use nonces, with custom expiry length and custom associated data.

**Parameters**  
`$true_nonce`
> (bool) whether the nonce is one-time-use ; default `true`  

`$expiry_length`
> (int) the number of seconds after which the nonce expires ; default `WPPUS_Nonce::DEFAULT_EXPIRY_LENGTH` - 30 seconds 

`$data`
> (array) custom data to save along with the nonce ; set an element with key `permanent` to a truthy value to create a nonce that never expires ; default `array()`  

`$return_type`
> (int) whether to return the nonce, or an array of information ; default `WPPUS_Nonce::NONCE_ONLY` ; other accepted value is `WPPUS_Nonce::NONCE_INFO_ARRAY`  

`$store`
> (bool) whether to store the nonce, or let a third party mechanism take care of it ; default `true`  

**Return value**
> (bool|string|array) `false` in case of failure ; the cryptographic token string if `$return_type` is set to `WPPUS_Nonce::NONCE_ONLY` ; an array of information if `$return_type` is set to `WPPUS_Nonce::NONCE_INFO_ARRAY` with the following format:
```php
array(
	'nonce'      => 'some_value',	// cryptographic token
	'true_nonce' => true,			// whether the nonce is one-time-use
	'expiry'     => 9999,			// the expiry timestamp
	'data'       => array(),		// custom data saved along with the nonce
);
```

___
#### wppus_get_nonce_expiry

```php
wppus_get_nonce_expiry( string $nonce )
```

**Description**  
Get the expiry timestamp of a nonce.  

**Parameters**  
`$nonce`
> (string) the nonce  

**Return value**
> (int) the expiry timestamp  

___
#### wppus_validate_nonce

```php
wppus_validate_nonce( string $value )
```

**Description**  
Check whether the value is a valid nonce.  
Note: if the nonce is a true nonce, it will be invalidated and further calls to this function with the same `$value` will return `false`.  

**Parameters**  
`$value`
> (string) the value to check  

**Return value**
> (bool) whether the value is a valid nonce  

___
#### wppus_delete_nonce

```php
wppus_delete_nonce( string $value )
```

**Description**  
Delete a nonce from the system if the corresponding value exists.  

**Parameters**  
`$value`
> (string) the value to delete  

**Return value**
> (bool) whether the nonce was deleted  

___
#### wppus_delete_nonce

```php
wppus_clear_nonces()
```

**Description**  
Clear expired nonces from the system.  

**Return value**
> (bool) whether some nonces were cleared  

___
## Actions

WP Packages Update Server gives developers the possibility to have their plugins react to some events with a series of custom actions.  
**Warning**: the filters below with the mention "Fired during API requests" need to be used with caution. Although they may be triggered when using the functions above, these filters will possibly be called when the Update API, License API, Packages API or a Webhook is called. Registering functions doing heavy computation to these filters can seriously degrade the server's performances.  

___
### wppus_no_api_includes

```php
do_action( 'wppus_no_api_includes' );
```

**Description**  
Fired when the plugin is including files and the current request is not made by a remote client interacting with any of the plugin's API.

___
### wppus_no_license_api_includes

```php
do_action( 'wppus_no_license_api_includes' );
```

**Description**  
Fired when the plugin is including files and the current request is not made by a client plugin or theme interacting with the plugin's license API.

___
## Filters

WP Packages Update Server gives developers the possibility to customise its behavior with a series of custom filters.  
**Warning**: the filters below with the mention "Fired during API requests" need to be used with caution. Although they may be triggered when using the functions above, these filters will possibly be called when the Update API, License API, Packages API or a Webhook is called. Registering functions doing heavy computation to these filters can seriously degrade the server's performances.  

___
### wppus_is_api_request

```php
apply_filters( 'wppus_is_api_request', bool $is_api_request );
```

**Description**  
Filter whether the current request must be treated as an API request.  

**Parameters**  
`$is_api_request`
> (bool) whether the current request must be treated as an API request  

___
### wppus_page_wppus_scripts_l10n

```php
apply_filters( 'wppus_page_wppus_scripts_l10n', array $l10n );
```

**Description**  
Filter the internationalization strings passed to the frontend scripts.  

**Parameters**  
`$l10n`
> (array) the internationalization strings passed to the frontend scripts  

___
### wppus_nonce_api_code

```php
apply_filters( 'wppus_nonce_api_code', string $code, array $request_params );
```

**Description**  
Filter the HTTP response code to be sent by the Nonce API.  

**Parameters**  
`$code`
> (string) the HTTP response code to be sent by the Nonce API  

`$request_params`
> (array) the request's parameters  

___
### wppus_nonce_api_response

```php
apply_filters( 'wppus_nonce_api_response', array $response, string $code, array $request_params );
```

**Description**  
Filter the response to be sent by the Nonce API.  

**Parameters**  
`$response`
> (array) the response to be sent by the Nonce API  

`$code`
> (string) the HTTP response code sent by the Nonce API  

`$request_params`
> (array) the request's parameters  

___
### wppus_created_nonce

```php
apply_filters( 'wppus_created_nonce', bool|string|array $nonce_value, bool $true_nonce, int $expiry_length, array $data, int $return_type );
```

**Description**  
Filter the value of the nonce before it is created ; if `$nonce_value` is truthy, the value is used as nonce and the default generation algorithm is bypassed ; developers must respect the `$return_type`.

**Parameters**  
`$nonce_value`
> (bool|string|array) the value of the nonce before it is created - if truthy, the nonce is considered created with this value  

`$true_nonce`
> (bool) whether the nonce is a true, one-time-use nonce  

`$expiry_length`
> (int) the expiry length of the nonce in seconds  

`$data`
> (array) data to store along the nonce  

`$return_type`
> (int) `WPPUS_Nonce::NONCE_ONLY` or `WPPUS_Nonce::NONCE_INFO_ARRAY`  

___
### wppus_clear_nonces_query

```php
apply_filters( 'wppus_clear_nonces_query', string $sql, array $sql_args );
```

**Description**  
Filter the SQL query used to clear expired nonces.

**Parameters**  
`$sql`
> (string) the SQL query used to clear expired nonces  

`$sql_args`
> (array) the arguments passed to the SQL query used to clear expired nonces  

___
### wppus_clear_nonces_query_args

```php
apply_filters( 'wppus_clear_nonces_query_args', array $sql_args, string $sql );
```

**Description**  
Filter the arguments passed to the SQL query used to clear expired nonces.

**Parameters**  
`$sql_args`
> (array) the arguments passed to the SQL query used to clear expired nonces  

`$sql`
> (string) the SQL query used to clear expired nonces  

___
### wppus_expire_nonce

```php
apply_filters( 'wppus_expire_nonce', bool $expire_nonce, string $nonce_value, bool $true_nonce, int $expiry, array $data, object $row );
```

**Description**  
Filter whether to consider the nonce has expired.

**Parameters**  
`$expire_nonce`
> (bool) whether to consider the nonce has expired  

`$nonce_value`
> (string) the value of the nonce  

`$true_nonce`
> (bool) whether the nonce is a true, one-time-use nonce  

`$expiry`
> (int) the timestamp at which the nonce expires  

`$data`
> (array) data stored along the nonce  

`$row`
> (object) the database record corresponding to the nonce  

___
### wppus_delete_nonce

```php
apply_filters( 'wppus_delete_nonce', bool $delete, string $nonce_value, bool $true_nonce, int $expiry, array $data, object $row );
```

**Description**  
Filter whether to delete the nonce.

**Parameters**  
`$delete`
> (bool) whether to delete the nonce  

`$nonce_value`
> (string) the value of the nonce  

`$true_nonce`
> (bool) whether the nonce is a true, one-time-use nonce  

`$expiry`
> (int) the timestamp at which the nonce expires  

`$data`
> (array) data stored along the nonce  

`$row`
> (object) the database record corresponding to the nonce  

___
### wppus_fetch_nonce

```php
apply_filters( 'wppus_fetch_nonce', string $nonce_value, bool $true_nonce, int $expiry, array $data, object $row );
```

**Description**  
Filter the value of the nonce after it has been fetched from the database.

**Parameters**  
`$nonce_value`
> (string) the value of the nonce after it has been fetched from the database  

`$true_nonce`
> (bool) whether the nonce is a true, one-time-use nonce  

`$expiry`
> (int) the timestamp at which the nonce expires  

`$data`
> (array) data stored along the nonce  

`$row`
> (object) the database record corresponding to the nonce  

___