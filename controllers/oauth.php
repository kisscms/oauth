<?php
/*
 *	OAuth for KISSCMS (v.0.5)
 *	Straightforward implementation of the OAuth protocol to connect to most opular APIs
 *	Homepage: http://kisscms.com/plugins
 *	Created by Makis Tracend (@tracend)
 *	Dependencies: 
 *	- Http() class that comes bundled with KISSCMS
*/

class OAuth extends Controller {
	
	public function index( $params ){
		// add extra filtering if necessery...
		
		// point to the appropriate sub-routine based on the variables
		if( !empty( $params['code'] ) )
			$this->code( $params );
		if( !empty( $params['oauth_token']) )
			$this->save( $params );
		
		// redirect back to the homepage
		header('Location: '. url() );
	}
	
	// Get code method
	private function code( $params ){
		$class = ucfirst($params["api"])."_OAuth";
		$oauth = new $class();
		$code = $params['code'];
		$oauth->access_token( $code );
		
	}
	
	// Request token with the HMAC-SHA1 signature
	private function save( $params ){
		$class = ucfirst($params["api"])."_OAuth";
		$oauth = new $class();
		$oauth->save( $params );
		
	}
	
}

?>