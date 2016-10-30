/**
*
* @file Application.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the webroot Application component for extending and configuring fw/1
*
*/

component extends="framework.one" {

	this.name = 'secure_auth';
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

		// load and initialize the SecurityService with keyring path and master key
		// NOTE: The keyRingPath should be placed in a secure directory *outside* of  
		// your web root to prevent key disclosure over the internet. 
		// ex: keyRingPath = '/opt/secure/keyrings/' & hash( 'secure_auth', 'MD5', 'UTF-8', 420 ) & '.bin'
		// this path should be accessible *only* to the user the CFML application server is
		// running under and to root/Administrator users
		application.securityService = new model.services.SecurityService(
			keyRingPath = expandPath( 'keyrings/' ) & hash( 'secure_auth_keyring', 'MD5', 'UTF-8', 173 ) & '.bin',
			masterKey = mid( lCase( hash( 'secure_auth_master_key', 'SHA-512', 'UTF-8', 512 ) ), 38, 22 ) & '=='
		);

		// use the SecurityService to read the encryption keys from disk
		application.keyRing = application.securityService.readKeyRingFromDisk();

		// check if the keyring is a valid array of keys
		if( !isArray( application.keyRing ) or !arrayLen( application.keyRing ) ) {
			// it isn't, try
			try {
				// to generate a new keyring file (for new application launch only)
				// you should throw an error instead of attempting to generate a new
				// keyring once a keyring has already been established
				// ex: throw( 'The keyring file could not be found' );
				application.keyRing = application.securityService.generateKeyRing();
			// catch any errors
			} catch ( any e ) {
				// and dump the error
				// writeDump( e );
				// or throw a new error
				// throw( 'The keyring file could not be found' );
				// or otherwise log, etc. and abort
				abort; 
			}
		}

		// (re)initialize the SecurityService with the keyring
		application.securityService = application.securityService.init( 
			encryptionKey1 			= application.keyRing[1].key,
			encryptionAlgorithm1 	= application.keyRing[1].alg,
			encryptionEncoding1 	= application.keyRing[1].enc,
			encryptionKey2 			= application.keyRing[2].key,
			encryptionAlgorithm2 	= application.keyRing[2].alg,
			encryptionEncoding2 	= application.keyRing[2].enc,
			encryptionKey3 			= application.keyRing[3].key,
			encryptionAlgorithm3 	= application.keyRing[3].alg,
			encryptionEncoding3 	= application.keyRing[3].enc,
			hmacKey					= generateSecretKey( 'HMACSHA512' ),
			hmacAlgorithm			= 'HMACSHA512',
			hmacEncoding			= 'UTF-8'
		);

		// clear the keyring from the application scope
		structDelete( application, 'keyRing' );

		// set the name of the cookie to use for session management 
		// (*DO NOT USE* cfid, cftoken or jsessionid)
		// Obscuring your cookie name using common tracker names
		// can help throw a would-be hacker off course
		// ex: __ga_utm_source, __imgur_ref_id, __fb_beacon_id, etc.
		application.cookieName = '__secure_auth_id';

		// set number of minutes before a session is timed out
		application.timeoutMinutes = 30; // 30 minutes

		// set the directory where the blocked ip json file is stored
		// if this file is web accessible you can share your blocked ip's 
		// with other sites more easily when using the
		// importBlockedIPFileFromUrl() function of the security service
		application.blockedIpDir = '/blocked/';

		// set the number of times an ip address can attempt
		// hacker like activity before being automatically added
		// to the blocked ip list.
		application.blockIpThreshold = 15;

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
		
		// get the http request headers
		var headers = getHTTPRequestData().headers;
		var ipAddress = '';

		// check if this server sits behind a load balancer, proxy or firewall
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
			// it is, redirect here to an HTML page with *no links in the html* 
			// (bots follow links) if you would prefer to give feedback to the end user
			// otherwise simply abort further processing
			location( 'ipBlocked.html', 'false', '301' )
		}

		// check if the query string contains SQL injection attempts
		// if sql injection is detected an error is thrown and caught
		// by home.main.error
		application.securityService.checkSqlInjectionAttempt( CGI.QUERY_STRING );

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

	}

}
