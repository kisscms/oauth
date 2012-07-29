<?php 

class KISS_OAuth_v2 {
	
	public $url;
	public $redirect_uri;
	
	public $client_id;
	public $client_secret;
	
	public $token;
	public $refresh_token;
	
	public $api;
	
	function  __construct( $api=false, $url=false ) {
		
		// create the oauth array if this is the first run
		if( !array_key_exists("oauth", $_SESSION) ) $_SESSION['oauth'] = array();
		
		// get the attributes of a specific API
		if( $api ){ 
			// set redirect uri only if necessary
			if( empty($this->redirect_uri) ) $this->redirect_uri = url("/oauth/api/". $api);
			
			// create the $api array if this is the first run
			if( !array_key_exists("$api", $_SESSION['oauth']) ) $_SESSION['oauth'][$api] = array();
		
			if( !empty($GLOBALS['config'][$api]['key']) ) $this->client_id = $GLOBALS['config'][$api]['key'];
	 		if( !empty($GLOBALS['config'][$api]['secret']) ) $this->client_secret = $GLOBALS['config'][$api]['secret'];
			
			// OAuth v2 tokens
			if( !empty($_SESSION['oauth'][$api]['access_token']) ) $this->token = $_SESSION['oauth'][$api]['access_token'];
	 		if( !empty($_SESSION['oauth'][$api]['refresh_token']) ) $this->refresh_token =  $_SESSION['oauth'][$api]['refresh_token'];
			
			// save for reference
			$this->api = $api;
			
		}
		
	}
	
	
	// Generating Links
	// - Using GET
	public static function link( $scope='', $custom=NULL ){
		$class = get_called_class();
		$oauth = new $class();
			
		// create the request
		$request = array(
			"url" => $oauth->url['authorize'],
			"params" => array( 
					"client_id" => $oauth->client_id, 
					"scope" => $scope, 
					"redirect_uri" => $oauth->redirect_uri,
					"response_type" => "code"
			)
		);
		
		// check if we have additional parameters
		if( !empty($custom) ){ 
			if( array_key_exists("url", $custom) ) $request['url'] =  $custom['url'];
			if( array_key_exists("params", $custom) ) $request['params'] = array_merge( $request['params'], $custom['params'] );
		}
		
		$query = http_build_query( $request["params"] );
		
		echo $request['url'] ."?". $query;
		
	}
	
	
	// Manage Tokens
	
	// - Access a token given a code (GET method)
	function access_token( $params, $custom=array() ){
		
		$request = array( 
			"url" => $this->url['access_token'], 
			"params" => array( 
					"client_id" => $this->client_id, 
					"client_secret" => $this->client_secret, 
					"redirect_uri" => $this->redirect_uri, 
					"code" => $params['code'],
			)
		);
		
		// check if we have additional parameters
		if( !empty($custom) ){ 
			if( array_key_exists("url", $custom) ) $request['url'] =  $custom['url'];
			if( array_key_exists("params", $custom) ) $request['params'] = array_merge( $request['params'], $custom['params'] );
		}
		
		$http = new Http();
		$http->setMethod('POST');
		$http->setParams( $request["params"] );
		
		$http->execute( $request["url"] );
		// save the response
		$this->save($http->result);
		
	}

	// - Refresh a token with a refresh_token
	function refreshToken( $custom=array() ){
					
		$request = array( 
			"url" => $this->url['refresh_token'], 
			"params" => array( 
					"client_id" => $this->client_id, 
					"client_secret" => $this->client_secret,
					"redirect_uri" => $this->redirect_uri, 
					"refresh_token" => $this->refresh_token,
			)
		);
		
		// check if we have additional parameters
		if( !empty($custom) ){ 
			if( array_key_exists("url", $custom) ) $request['url'] =  $custom['url'];
			if( array_key_exists("params", $custom) ) $request['params'] = array_merge( $request['params'], $custom['params'] );
		}
		
		$http = new Http();
		$http->setMethod('POST');
		$http->setParams( $request["params"] );
		
		$http->execute( $request["url"] );
		// save the response
		$this->save($http->result);
		
	}
	
	
	function checkToken(){
		
		// check if theres's an expiry date
		$expiry = ( empty($_SESSION['oauth'][$this->api]['expiry']) ) ? false : $_SESSION['oauth'][$this->api]['expiry'];
		
		// reset the authentication
		if( !$expiry || !$this->refresh_token) {
			// something is seriously wrong - reinstate authentication
			return false;
		}
		
		$expires_in = strtotime("now") - strtotime( $expiry ); // seconds
		
		// 500 seconds is a random number... should it be configurable?
		if( $expires_in < 500 ){
			$this->refreshToken();
		}
		
		// all good...
		return true;
	
	}
	
	
	function creds( $data=NULL ){
		
		// restore credentials externally (from db?)
		if( !empty($data) && empty($_SESSION['oauth'][$this->api]) ) $_SESSION['oauth'][$this->api] = (array) $data;
		
		// check if the token is valid
		$this->checkToken();
		
		// return the details from the session
		return ( empty($_SESSION['oauth'][$this->api]) ) ? false : $_SESSION['oauth'][$this->api];
		
	}
	
	
	function save( $response ){
		// do something with the response...
	}
	
	
	// Helper functions
	function urlencode_oauth($str) {
	  return
		str_replace('+',' ',str_replace('%7E','~',rawurlencode($str)));
	}
	
	
}


class KISS_OAuth_v1 {
	
	public $url;
	public $redirect_uri;
	
	public $client_id;
	public $client_secret;
	
	private $token;
	
	private $consumer;
	private $sha1_method;
	
	function  __construct( $api=false, $url=false ) {
		// create the oauth array if this is the first run
		if( !array_key_exists("oauth", $_SESSION) ) $_SESSION['oauth'] = array();
		
		// get the attributes of a specific API
		if( $api ){ 
			$this->redirect_uri = url("/oauth/api/". $api);
			
			// create the $api array if this is the first run
			if( !array_key_exists("$api", $_SESSION) ) $_SESSION['oauth'][$api] = array();
		
			if( !empty($GLOBALS['config'][$api]['key']) ) $this->client_id = $GLOBALS['config'][$api]['key'];
	 		if( !empty($GLOBALS['config'][$api]['secret']) ) $this->client_secret = $GLOBALS['config'][$api]['secret'];
			
			// OAuth v1 tokens
			if( !empty($_SESSION['oauth'][$api]['oauth_token']) ) $oauth_token = $_SESSION['oauth'][$api]['oauth_token'];
	 		if( !empty($_SESSION['oauth'][$api]['oauth_token_secret']) ) $oauth_token_secret =  $_SESSION['oauth'][$api]['oauth_token_secret'];
		
			$this->sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
			$this->consumer = new OAuthConsumer($this->client_id, $this->client_secret);
			if (!empty($oauth_token) && !empty($oauth_token_secret)) {
			  $this->token = new OAuthConsumer($oauth_token, $oauth_token_secret);
			} else {
			  $this->token = NULL;
			}
		}
	}
	
	
	
	// Generating Links
	// - Using the HMAC-SHA1 signature
	public static function link( $scope="", $params=NULL ){
		
		$class = get_called_class();
		$oauth = new $class();
		
		$request = $oauth->request( $oauth->url['request_token'], "GET", $params);
		
		parse_str($request, $response);
		
		// save the token/secret for later
		$oauth->save($response);
		
    	echo $oauth->url['authorize'] . "?oauth_token=" . $response['oauth_token'];
	}
	
	
	
	// Manage Tokens
	
	// - Access a token given a code (GET method)
	function access_token( $params, $custom=array() ){
			
		$query = array( 
			"url" => $this->url['access_token'], 
			"params" => array( 
					"oauth_token" => $params['oauth_token'], 
					"oauth_verifier" => $params['oauth_verifier']
			)
		);
		
		$request = $this->request( $query['url'], "GET", $query['params']);
		
		parse_str($request, $response);
		
		// save the response
		$this->save($response);
		
	}

	// - Refresh a token with a refresh_token
	function refreshToken( $custom=array() ){
					
		$request = array( 
			"url" => $this->url['refresh_token'], 
			"params" => array( 
					"client_id" => $this->client_id, 
					"client_secret" => $this->client_secret,
					"refresh_token" => $this->refresh_token,
			)
		);
		
		// check if we have additional parameters
		if( !empty($custom) ){ 
			if( array_key_exists("url", $custom) ) $request['url'] =  $custom['url'];
			if( array_key_exists("params", $custom) ) $request['params'] = array_merge( $request['params'], $custom['params'] );
		}
		
		$http = new Http();
		$http->setMethod('POST');
		$http->setParams( $request["params"] );
		
		$http->execute( $request["url"] );
		// save the response
		$this->save($http->result);
		
		// return true
		
	}
	
	// compile the request for OAuth v1
	function request( $url="", $method="GET", $params=NULL){
		
		$request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $params);
		$request->sign_request($this->sha1_method, $this->consumer, $this->token);
		
		$http = new Http();
		$http->setMethod($method);
		
		switch ($method) {
		case 'GET':
		  $url = $request->to_url();
		  break;
		default:
		  parse_str($request->to_postdata(), $params);
		  $http->setParams( $params );
		  $url = $request->get_normalized_http_url();
		  break;
		}
		
		$http->execute( $url );
		  
		return ($http->error) ? die($http->error) : $http->result;
	}
	
	
	function save( $response ){
		// do something with the response...
	}
	
	
	// Helper functions
	function urlencode_oauth($str) {
	  return
		str_replace('+',' ',str_replace('%7E','~',rawurlencode($str)));
	}

	
}

?>