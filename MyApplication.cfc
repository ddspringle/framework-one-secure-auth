/**
*
* @file MyApplication.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the webroot MyApplication component for extending and configuring fw/1
*
*/

component extends="framework.one" {

	/**
	* @displayname setupApplication
	* @description I'm run by fw/1 during onApplicationStart() to configure application level settings
	*/		
	function setupApplication() {}

	/**
	* @displayname setupSession
	* @description I'm run by fw/1 during onSessiontart() to configure session level settings
	*/	
	function setupSession() {

		// check if we're in the 'admin' subsystem
		if( getSubsystem()  eq 'admin' ) {
			// we are, call the security controller's session action to configure the session 
			controller( 'admin:security.session' );
		}

	}

	/**
	* @displayname setupRequest
	* @description I'm run by fw/1 during onRequestStart() to configure request level settings
	*/	
	function setupRequest() {

		// get the http request headers
		var headers = getHTTPRequestData().headers;
		var ipAddress = '';

		// check if we're in the production environment 
		if( findNoCase( 'prod', getEnvironment() ) ) {

			// we are, check if this server sits behind a load balancer, proxy or firewall
			if( structKeyExists( headers, 'x-forwarded-for' ) ) {
				// it does, get the ip address this request has been forwarded for
				ipAddress = headers[ 'x-forwarded-for' ];
			// otherwise
			} else {
				// it doesn't, get the ip address of the remote client
				ipAddress = CGI.REMOTE_ADDR;
			}

			// check if this ip address is blocked
			if( application.securityService.isBlockedIP( ipAddress ) ) {

				// switch on the block mode
				switch( application.blockMode ) {
					// redirect
					case 'redirect':
						// redirect the browser to an html page for notification
						location( '/ipBlocked.html', 'false', '302' );
					break;

					// abort
					default:
						abort;
					break;
				}

			}

			// check if the query string contains SQL injection attempts
			// if sql injection is detected an error is thrown and caught
			// by home.main.error
			application.securityService.checkSqlInjectionAttempt( CGI.QUERY_STRING );

		}

		// check if we're in the 'admin' subsystem
		if( getSubsystem() eq 'admin' ) {
			// we are, call the security controller's authorize action to perform session management
			controller( 'admin:security.authorize' );
			// set HTTP headers to disallow caching of admin pages
			getPageContext().getResponse().addHeader( 'Cache-Control', 'no-cache, no-store, must-revalidate' );
			getPageContext().getResponse().addHeader( 'Pragma', 'no-cache' );
		// otherwise
		} else {
			// we aren't in the admin subsystem, set a practical age for cache control for performance
			// in seconds (86400 = 1 day)
			getPageContext().getResponse().addHeader( 'Cache-Control', 'max-age=86400' );
		}

		// use HTTP headers to help protect against common attack vectors
		getPageContext().getResponse().addHeader( 'X-Frame-Options', 'deny' );
		getPageContext().getResponse().addHeader( 'X-XSS-Protection', '1; mode=block' );
		getPageContext().getResponse().addHeader( 'X-Content-Type-Options', 'nosniff' );
		getPageContext().getResponse().addHeader( 'Strict-Transport-Security', 'max-age=31536000; includeSubDomains' );
		getPageContext().getResponse().addHeader( 'Expires', '-1' );
		getPageContext().getResponse().addHeader( 'X-Permitted-Cross-Domain-Policies', 'master-only' );

		// check if there is a url variable for flushing the page cache 
		if( structKeyExists( url, 'flushCache') ) {
			// there is, flush the page cache
			cfcache( action='flush' );
		}

	}

	/**
	* @displayname getEnvironment
	* @description I'm run by fw/1 during onRequest() to configure environment specific settings
	*/	
	public function getEnvironment() {

		return application.securityService.getEnvironment();

	}

}
