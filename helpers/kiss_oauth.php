<?php 

class KISS_OAuth {
	
	public $url;
	public $redirect_uri;
	
	public $client_id;
	public $client_secret;
	
	public $token;
	public $refresh_token;
		
	function  __construct( $api=false, $url=false ) {
		if( $api ){ 
			$this->redirect_uri = url("/oauth/api/". $api);
		
			if( !empty($GLOBALS['config'][$api]['key']) ) $this->client_id = $GLOBALS['config'][$api]['key'];
	 		if( !empty($GLOBALS['config'][$api]['secret']) ) $this->client_secret = $GLOBALS['config'][$api]['secret'];
		
			if( !empty($_SESSION['oauth'][$api]['access_token']) ) $this->token = $_SESSION['oauth'][$api]['access_token'];
	 		if( !empty($_SESSION['oauth'][$api]['refresh_token']) ) $this->refresh_token =  $_SESSION['oauth'][$api]['refresh_token'];
		}
	}
	
	
	// API specific (no generic method)
	public static function link( $scope="" ){
		// redirect to either link_get() or link_request, depending on the OAuth implementation
	}
	
	function save( $response ){
		// do something with the response...
	}
	
	
	
	// Generating Links
	
	// - Using GET
	function link_get( $scope="", $params=false ){
		
		// create the request
		$request = array(
			"url" => $this->url['authorize'],
			"params" => array( 
					"client_id" => $this->client_id, 
					"scope" => $scope, 
					"redirect_uri" => $this->redirect_uri,
					"response_type" => "code"
			)
		);
		
		// check if we have additional parameters
		if( !empty($params) ) $request['params'] = array_merge( $request['params'], $params );
		
		$query = http_build_query( $request["params"] );
		
		return $request['url'] ."?". $query;
	}
	
	// - Using the HMAC-SHA1 signature
	function link_request( $scope="" ){
		
		$consumer = new OAuthConsumer($this->client_id, $this->client_secret, $this->redirect_uri);
		$signature_method = new OAuthSignatureMethod_HMAC_SHA1();
	
		$request = OAuthRequest::from_consumer_and_token($consumer, NULL, "GET", $this->url['request_token']);
		$request->set_parameter("oauth_callback", $this->redirect_uri);
		$request->sign_request($signature_method, $consumer, NULL);
		
		$url = $request->to_url();
		
		$http = new Http();
		$http->setMethod('GET');
		$http->execute( $url );	
		parse_str($http->result, $response);
	
		$request_token = new OAuthConsumer($response['oauth_token'], $response['oauth_token_secret'], 1);
		
    	return $this->url['authorize'] . "?oauth_token=" . $request_token->key;
	}
	
	
	
	// Manage Tokens
	
	// - Access a token given a code (GET method)
	function access_token( $code, $custom=array() ){
		
		$request = array( 
			"url" => $this->url['access_token'], 
			"params" => array( 
					"client_id" => $this->client_id, 
					"client_secret" => $this->client_secret, 
					"redirect_uri" => $this->redirect_uri, 
					"code" => $code,
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

	// - Refresh a token with a refresh_token
	function refresh_token( $custom=array() ){
					
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
	
	
	// Helper functions
	function urlencode_oauth($str) {
	  return
		str_replace('+',' ',str_replace('%7E','~',rawurlencode($str)));
	}
}

?>