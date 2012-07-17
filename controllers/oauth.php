<?php
/*
 *	OAuth for KISSCMS 
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
		if( !empty( $params['code'] ) ||  !empty( $params['oauth_token']) )
			$this->access_token( $params );
		
		// redirect back to the homepage
		header('Location: '. url() );
	}
	
	// Get the access token 
	private function access_token( $params ){
		$class = ucfirst($params["api"])."_OAuth";
		$oauth = new $class();
		$oauth->access_token( $params );
		
	}
	
	
}

?>