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

		$this->finish($params["api"]);

	}

	// Get the access token
	private function access_token( $params ){
		$class = ucfirst($params["api"])."_OAuth";
		$oauth = new $class();
		$oauth->access_token( $params );

	}

	// #6 - supporting client side authentication
	private function finish( $api ){
		// to lower case...
		$api = strtolower( $api );
		$class = ucfirst($api)."_OAuth";
		$oauth = new $class();
		// variables
		$config = $oauth->config();
		$creds = $oauth->creds();

		if( !array_key_exists("client_auth", $config ) || !$config["client_auth"] ){
		// if( !empty($_SESSION['oauth']['foursquare']['access_token']) && ($_SERVER['REQUEST_URI'] ==  WEB_FOLDER) ){
			// redirect back to the homepage
		   header('Location: '. url() );

		} else {
			// assume there's going to be a controller to handle 'access_token'
			header("Location: ". url("access_token#". $creds['access_token']) );
			exit;
		}
	}


}

?>