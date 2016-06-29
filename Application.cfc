/**
*
* @file Application.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the webroot Application component for extending and configuring fw/1
*
*/

component extends="framework.one" {

	this.name = "secure_auth";
	this.applicationTimeout = CreateTimeSpan(30, 0, 0, 0);
	this.sessionManagement = true;
	this.sessionTimeout = CreateTimeSpan(0, 0, 30, 0); // 30 minutes
	this.datasource = 'secureauth';
	this.scriptprotect = 'all';
	// CF10+ uncomment the following line to make your cfid/cftoken cookies httpOnly
	// this.sessioncookie.httpOnly;
	
	variables.framework = {
		usingSubsystems = true
	};

	/**
	* @displayname setupApplication
	* @description I'm run by fw/1 during onApplicationStart() to configure application level settings
	*/		
	function setupApplication() {
		// load the security functions for session management
		// NOTE: These keys should normally be stored in a secured file on the filesystem and read in by the application
		// NOTE: This could also be done using DI/AOP instead of loading it into the application scope
		application.securityService = createObject( 'component', 'model.services.SecurityService').init(
			encryptionKey1 			= '<key1>',
			encryptionAlgorithm1 	= 'AES/CBC/PKCS5Padding',
			encryptionEncoding1 	= 'HEX',
			encryptionKey2 			= '<key2>',
			encryptionAlgorithm2 	= 'BLOWFISH/CBC/PKCS5Padding',
			encryptionEncoding2 	= 'HEX',
			encryptionKey3 			= '<key3>',
			encryptionAlgorithm3 	= 'AES/CBC/PKCS5Padding',
			encryptionEncoding3 	= 'HEX',
			hmacKey					= generateSecretKey( 'HMACSHA512' ),
			hmacAlgorithm			= 'HMACSHA512',
			hmacEncoding			= 'utf-8'
		);

		// set the name of the cookie to use for session management (*DO NOT USE* cfid, cftoken or jsessionid)
		application.cookieName = '__secure_auth_id';

		// set number of minutes before a session is timed out
		application.timeoutMinutes = 30; // 30 minutes

	}

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

		// check if we're in the 'admin' subsystem
		if( getSubsystem()  eq 'admin' ) {
			// we are, call the security controller's authorize action to perform session management
			controller( 'admin:security.authorize' );
			// set HTTP headers to disallow caching of admin pages
			getPageContext().getResponse().addHeader( 'Cache-Control', 'no-cache, no-store, must-revalidate' );
			getPageContext().getResponse().addHeader( 'Pragma', 'no-cache' );
		// otherwise
		} else {
			// we aren't in the admin subsystem, set a paractical age for cache control for performance
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

	}

}
