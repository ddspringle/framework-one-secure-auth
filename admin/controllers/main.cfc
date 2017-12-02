/**
*
* @file admin/controllers/main.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the controller for the admin:main section
*
*/

component accessors="true" {

	property userService;
	property smsProviderService;
	property mailService;

	/**
	* @displayname init
	* @description I am the constructor method for main
	* @return 	   this
	*/	
	public any function init( fw ) {
		variables.fw = fw;
		return this;
	}

	/**
	* @displayname default
	* @description I clear session data and present the login view
	*/	
	public void function default( rc ) {

		// disable the admin layout since the login page has it's own html
		variables.fw.disableLayout();
		
		// set a zero session cookie when hitting the login page (federate the login)
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero primary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieOne#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero secondary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieTwo#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero tertiary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieThree#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// lock and clear the sessionObj
		lock scope='session' timeout='10' {			
			session.sessionObj = new model.beans.Session();
		}

		// check for the existence of the 'msg' url paramter
		if( structKeyExists( rc, 'msg' ) ) {
			// and generate a message to be displayed
			if( rc.msg eq 500 ) {
				rc.message = 'Both Email and Password fields are required to login.';
			} else if( rc.msg eq 404 or rc.msg eq 403 ) {
				rc.message = 'Account not found with provided credentials. Please try again.';
			} else if( rc.msg eq 555 ) {
				rc.message = 'Account is disabled. Please contact your system administrator.';
			} else if( rc.msg eq 200 ) {
				rc.message = "You have been successfully logged out.";
			} else if( rc.msg eq 410 ) {
				rc.message = 'Second factor was not provided. Please login again.';
			} else if( rc.msg eq 411 ) {
				rc.message = 'Second factor does not match. Please login again.';
			} else {
				rc.message = 'Your session has timed out. Please log in again to continue.';
			}
		// if it doesn't exist
		} else {
			// create it
			rc.msg = 0;
			// and set a null message string
			rc.message = '';
		}

		// set a title for the login page to render
		rc.title = 'Secure Authentication Sign In';

	}

	/**
	* @displayname dashboard
	* @description I present the dashbaord view
	*/ 
	public void function dashboard( rc ) {}

	/**
	* @displayname authenticate
	* @description I authenticate a user login and redirect to the dashboard view if valid
	*/	
	public void function authenticate( rc ) {

		var qGetUser = '';
		var hashedPwd = '';

		// check if the host and referrer match (federate the login)
		if( !findNoCase( CGI.HTTP_HOST, CGI.HTTP_REFERER ) ) {
			// they don't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=503' );		
		}

		// check if the session cookie exists (federate the login)
		if( !structKeyExists( cookie, application.cookieName ) ) {
			// it doesn't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=504' );			
		}

		// ensure a username and password were sent
		if( !len( rc.username ) OR !len( rc.password ) ) {
			// they weren't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=500' );
		}

		// ensure the CSRF token is provided and valid
		if( !structKeyExists( rc, 'f' & application.securityService.uberHash( 'token', 'SHA-512', 150 ) ) OR !CSRFVerifyToken( rc[ 'f' & application.securityService.uberHash( 'token', 'SHA-512', 150 ) ] ) ) {
			// it doesn't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=505' );
		}

		// get the user from the database by encrypted username
		qGetUser = userService.filter( username = application.securityService.dataEnc( rc.username, 'repeatable' ) );

		// check if there is a record for the passed username
		if( !qGetUser.recordCount ) {
			// there isn't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=404' );
		}

		// check to be sure this user has an active account
		if( !qGetUser.isActive ) {
			// they don't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=555' );
		}

		// hash the users stored password with the passed heartbeat for comparison
		hashedPwd = hash( lcase( application.securityService.dataDec( qGetUser.password, 'db' ) ) & rc.heartbeat, 'SHA-384' );

		// compare the hashed stored password with the passed password
		if( !findNoCase( hashedPwd, rc.password ) ) {
			// they don't match, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=403' );
		}

		// lock the session scope and create a sessionObj for this user
		lock scope='session' timeout='10' {
			session.sessionObj = application.securityService.createUserSession(
				userId = qGetUser.userId,
				role = qGetUser.role,
				firstName = application.securityService.dataDec( qGetUser.firstName, 'db' ),
				lastName = application.securityService.dataDec( qGetUser.lastName, 'db' )
			);
		}

		// check if we're using two factor authentication
		if( application.use2FA ) {
			// we are, send the mfa code to this user for this session
			mailService.sendMfaCode( phone = application.securityService.dataDec( qGetUser.phone, 'db' ), providerEmail = variables.smsProviderService.getSmsProviderById( qGetUser.providerId ).getEmail(), mfaCode = session.sessionObj.getMfaCode() );
		}

		// set the session cookie with the new encrypted session id
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=#application.securityService.setSessionIdForCookie( session.sessionObj.getSessionId() )#;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a new primary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieOne#=#application.securityService.generateDummyCookieValue( 'BASE64' )#;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a new secondary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieTwo#=#application.securityService.generateDummyCookieValue( 'UU' )#;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a new tertiary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieThree#=#application.securityService.generateDummyCookieValue( 'HEX' )#;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// rotate the cfid/cftoken session to prevent session fixation
		// NOTE: This does *not* work with J2EE (jsessionid) sessions
		sessionRotate();
		// check if we're using two factor authentication
		if( application.use2FA ) {
			// we are, go to the twofactor view
			variables.fw.redirect( 'main.twofactor' );
		// otherwise
		} else {
			// we're not, go to the dashboard view
			variables.fw.redirect( 'main.dashboard' );
		}

	}
	
	/**
	* @displayname twofactor
	* @description I present the two-factor view
	*/
	public void function twofactor( rc ) {

		// disable the admin layout since the two-factor page has it's own html
		variables.fw.disableLayout();

		// set a title for the login page to render
		rc.title = 'Secure Authentication Sign In &raquo; Second Factor';

	}

	/**
	* @displayname authfactor
	* @description I authenticate the second factor
	*/
	public void function authfactor( rc ) {

		if( !structKeyExists( rc, 'twofactor' ) OR !len( rc.twofactor ) ) {
			// they don't match, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=410' );
		}

		// ensure the CSRF token is provided and valid
		if( !structKeyExists( rc, 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1700 ) ) OR !CSRFVerifyToken( rc[ 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1700 ) ] ) ) {
			// it doesn't, redirect to the logout page
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=510' );
		}

		if( compareNoCase( rc.twofactor, session.sessionObj.getMfaCode() ) NEQ 0 ) {
			variables.fw.redirect( action = 'main.logout', queryString = 'msg=411' );
		}

		// lock the session scope and create a sessionObj for this user
		lock scope='session' timeout='10' {
			session.sessionObj.setMfaCode( '' );
			session.sessionObj.setIsAuthenticated( true );
		}

		// and go to the dashboard view
		variables.fw.redirect( 'main.dashboard' );

	}
	/**
	* @displayname logout
	* @description I clear session data and present the login view
	*/	
	public void function logout( rc ) {

		// check if we have a session object to clear 
		if( structKeyExists( session, 'sessionObj' ) ) {

			// we do, clear the users session object from cache
			application.securityService.clearUserSession( session.sessionObj );

		}

		// lock and clear the sessionObj
		lock scope='session' timeout='10' {			
			session.sessionObj = new model.beans.Session();
		}

		// set a zero session cookie when logging out (clear the session cookie)
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero primary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieOne#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero secondary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieTwo#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// send a zero tertiary dummy cookie
		getPageContext().getResponse().addHeader("Set-Cookie", "#application.dummyCookieThree#=0;path=/;domain=#listFirst( CGI.HTTP_HOST, ':' )#;HTTPOnly");

		// invalidate the cfid/cftoken session
		// NOTE: This does *not* work with J2EE (jsessionid) sessions
		sessionInvalidate();

		// check if a message was passed into the logout function
		if( !structKeyExists( rc, 'msg') ) {
			// it wasn't, regular logout by the user, set the msg to 200
			rc.msg = 200;
		}

		// go to the login page
		variables.fw.redirect( action = 'main.default', queryString = 'msg=' & rc.msg );

	}
	
}
