/**
*
* @file home/controllers/main.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the controller for the home:main section
*
*/

component accessors="true" {

	property beanFactory;
	property formatterService;
	property userService;
	property smsProviderService;
	//property mailService;

	/**
	* @displayname init
	* @description I am the constructor method for main
	* @return      this
	*/  	
	public any function init( fw ) {
		variables.fw = fw;
		return this;
	}

	/**
	* @displayname default
	* @description I use the existing fw/1 example code
	*/  	
	public void function default( rc ) {
		// keep existing basic example fw/1 code
		var instant = variables.beanFactory.getBean( "instant" );
		rc.today = variables.formatterService.longdate( instant.created() );
	}

	/**
	* @displayname register
	* @description I present the registration view
	*/ 
	public void function register( rc ) {

		// check for the existence of the 'msg' url paramter
		if( structKeyExists( rc, 'msg') ) {
			// and generate a message to be displayed
			if( rc.msg eq 501 ) {
				rc.message = 'You must provide a valid value for all fields to register.';
			} else if( rc.msg eq 502 ) {
				rc.message = 'Your password and confirmation password do not match. Please try again.';
			} else if( rc.msg eq 503 ) {
				rc.message = 'A user account already exists for this email address. Please log in.';
			} else if( rc.msg eq 504 ) {
				rc.message = 'Your password cannot be the same or similar to your email address. Please try another password.';
			} else if( rc.msg eq 505 ) {
				rc.message = 'The password you have chosen is known to be a disclosed password available to hackers. If you are using this password with any other services then we strongly suggest you change your password with those services. Please try another password.';
			} else {
				rc.message = '';
			}
		// if it doesn't exist
		} else {
			// create it
			rc.msg = 0;
			// and set a null message string
			rc.message = '';
		}

		// check if we're using two factor authentication
		if( application.use2FA ) {
			// we are, get the list of SMS providers to select from
			rc.qGetSmsProviders = smsProviderService.filter( isActive = true, orderby = 'provider', cache = true, cacheTime = CreateTimeSpan( 1, 0, 0, 0 ) );
		}

	}

	/**
	* @displayname process
	* @description I process registration requests and display the process view
	*/ 
	public void function process( rc ) {

		var qGetUser = '';
		var fieldList = 'username,password,confirm,firstName,lastName';
		var ix = 0;
		
		// check if we're using two factor authentication
		if( application.use2FA ) {
			// we are, add to the list of required fields
			fieldList &= ',providerId,phone';
		}

		// loop through fields
		for( ix = 1; ix <= listLen( fieldList ); ix++ ) {
			// ensure the username, password, confirm, firstName and lastName have been passed in
			if( !structKeyExists( rc, listGetAt( fieldList, ix ) ) OR !len( rc[ listGetAt( fieldList, ix ) ] ) ) {
				// missing something, redirect to registration page
				variables.fw.redirect( action = 'main.register', queryString = "msg=501" );
			}
		}

		// check if the password and confirmation are the same 
		if( compareNoCase( rc.password, rc.confirm ) NEQ 0 ) {
			// password mismatch, redirect to registration page
			variables.fw.redirect( action = 'main.register', queryString = "msg=502" );			
		}

		// get the user from the database by encrypted username passed in
		qGetUser = userService.filter( username = application.securityService.dataEnc( rc.username, 'repeatable' ) );

		// check if there is a record for the passed username
		if( qGetUser.recordCount ) {
			// user exists, redirect to register page
			variables.fw.redirect( action = 'main.register', queryString = "msg=503" );			
		}

		// ensure the password is not found in the username 
		if( findNoCase( rc.password, rc.username ) ) {
			// password found in username, redirect to register page
			variables.fw.redirect( action = 'main.register', queryString = "msg=504" );			
		}

		// if hacked password checking is enabled, and the  
		// chosen password is found in the hacked password list
		if( application.rejectHackedPasswords and application.securityService.isPasswordHacked( rc.password ) ) {
			// password hacked, redirect to registration page
			variables.fw.redirect( action = 'main.register', queryString = "msg=505" );			
		}

		// get a user object to populate
		rc.userObj = userService.getUserById( 0 );

		// populate the user object encrypting and hashing as needed
		rc.userObj.setProviderId( rc.providerId );
		rc.userObj.setUsername( application.securityService.dataEnc( rc.username, 'repeatable' ) );
		rc.userObj.setPassword( application.securityService.dataEnc( hash( rc.password, 'SHA-384' ), 'db' ) );
		rc.userObj.setFirstName( application.securityService.dataEnc( encodeForHTML( rc.firstName ), 'db' ) );
		rc.userObj.setLastName( application.securityService.dataEnc( encodeForHTML( rc.lastName ), 'db' ) );
		rc.userObj.setPhone( application.securityService.dataEnc( reReplace( rc.phone, '[^0-9]', '', 'ALL' ), 'db' ) );
		rc.userObj.setRole( 0 );
		rc.userObj.setIsActive( 1 );

		// save the user object
		userService.saveUser( rc.userObj );

	}

	/**
	* @displayname reset
	* @description I present the reset view
	*/ 
	public void function reset( rc ) {

		// check for the existence of the 'msg' url paramter
		if( structKeyExists( rc, 'msg') ) {
			// and generate a message to be displayed
			if( rc.msg eq 403 ) {
				rc.message = 'A user account could not be located for this email address. Please register for an account.';
			} else if( rc.msg eq 200 ) {
				rc.message = 'An email has been sent with your new password. Please check your email and login with the new password provided.';
			} else {
				rc.message = '';
			}
		// if it doesn't exist
		} else {
			// create it
			rc.msg = 0;
			// and set a null message string
			rc.message = '';
		}
	}

	/**
	* @displayname resetpass
	* @description I reset the users password
	*/ 
	public void function resetpass( rc ) {

		// disabled until you write a mailService to handle emailing the user their new password
		abort;

		var qGetUser = userService.filter( username = application.securityService.dataEnc( rc.username, 'repeatable' ) );
		var randomPass = application.securityService.getRandomPassword();

		// check if there isn't a record for the passed username
		if( !qGetUser.recordCount ) {
			// user does not exist, redirect to reset page
			variables.fw.redirect( action = 'main.reset', queryString = "msg=403" );
		}

		// get a user object to modify
		rc.userObj = userService.getUserById( qGetUser.userId );

		rc.userObj.setPassword( application.securityService.dataEnc( hash( randomPass, 'SHA-384' ), 'db' ) );

		// save the user object
		userService.saveUser( rc.userObj );

		// email the customer their new password
		//mailService.sendPasswordResetEmail( rc.userObj, randomPass );

		// password reset, redirect to reset page
		variables.fw.redirect( action = 'main.reset', queryString = "msg=200" );
	}
	
	public void function error( rc ) {

		// check if we're in a production environment 
		if( findNoCase( 'prod', application.securityService.getEnvironment() ) ) {

			// we are, get the http request headers
			rc.headers = getHTTPRequestData().headers;

			// check if this server sits behind a load balancer, proxy or firewall
			if( structKeyExists( rc.headers, 'x-forwarded-for' ) ) {
				// it does, get the ip address this request has been forwarded for
				rc.ipAddress = rc.headers[ 'x-forwarded-for' ];
			// otherwise
			} else {
				// it doesn't, get the ip address of the remote client
				rc.ipAddress = CGI.REMOTE_ADDR;
			}

			// check if the user is requesting a view not found (when onMissingView() isn't being used)
			if( request.exception.cause.type eq 'FW1.viewNotFound' ) {
				// and redirect to the root of the site
				location( '/', 'false', '302' );
			}

			// check for sql injection errors
			if( findNoCase( 'SQLInjection', request.exception.cause.type ) ) {
				// sql injection attempt detected, add this ip address to the blocked ip list
				application.securityService.addBlockedIP( ipAddress = rc.ipAddress, reason = request.exception.cause.message );

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

			// check for parameter tampering
			if( 
				( findNoCase( 'key', request.exception.cause.message ) and ( findNoCase( "doesn't exist", request.exception.cause.message )  or findNoCase( "does not exist" , request.exception.cause.message ) ) )
				or findNoCase( 'invalid hexadecimal string', request.exception.cause.message )
				or findNoCase( 'given final block not properly padded', request.exception.cause.message )
			) {

				// parameter tampering likely, get this ip's record from the watched ip list
				watchedIp = application.securityService.getWatchedIp( rc.ipAddress );

				// check if the ip is currently being watched
				if( watchedIp.isWatched ) {
					// it is, check if the total number of times the ip has been flagged
					// exceeds the total set in the Application.cfc
					if( watchedIp.totalCount gt application.blockIpThreshold ) {
						// it has, add this ip address to the blocked ip list
						application.securityService.addBlockedIP( ipAddress = rc.ipAddress, reason = 'parameter tampering more than #application.blockIpThreshold# times' );
						// and remove it from the watched ip list
						application.securityService.removeWatchedIP( rc.ipAddress );
					// otherwise
					} else {
						// the ip has not exceeded the total flags required to be blocked
						// increase the total times this ip has been flagged
						application.securityService.increaseWatchedIpCount( ipAddress = rc.ipAddress, reason = request.exception.cause.message );
					}
				// otherwise
				} else {
					// this ip is not currently being watched, so add it to the watch list
					application.securityService.addWatchedIP( ipAddress = rc.ipAddress, reason = request.exception.cause.message );
				}
				// redirect the browser to an html page for notification
				location( '/ipFlagged.html', 'false', '302' );
			}

		} // end checking if we're in a production environment

	}
}
