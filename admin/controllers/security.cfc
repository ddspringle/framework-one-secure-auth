/**
*
* @file admin\controllers\security.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the security controller for session management for the admin subsystem
*
*/

component {

	/**
	* @displayname init
	* @description I am the constructor method for security
	* @return      this
	*/  
	function init( fw ) {
		variables.fw = fw;
	}

	/**
	* @displayname session
	* @description I setup a sessionObj for this Session
	*/  
	function session( rc ) {
		
		// lock and clear the sessionObj
		lock scope='session' timeout='10' {
			session.sessionObj = new model.beans.Session();
		}

	}

	/**
	* @displayname authorize
	* @description I authenticate and rotate a session on each request
	*/  
	function authorize( rc ) {

		var actionArr = [ 'admin:main.default', 'admin:main.authenticate', 'admin:main.twofactor', 'admin:main.authfactor' ];

		// check if we're already logging in
		if( !arrayFind( actionArr, rc.action )) {

			// we're not, check if the session cookie is defined
			if( !structKeyExists( cookie, application.cookieName ) ) {
				// it isn't, redirect to the login page
				variables.fw.redirect( action = 'main.default', queryString = "msg=501" );  
			}

			// try 
			try {
				// decrypt the cookie
				rc.sessionId = application.securityService.getSessionIdFromCookie( cookie[ application.cookieName ] );
			// catch any decryption errors
			} catch ( any e ) {
				// decryption failed (invalid cookie value), redirect to the login page
				variables.fw.redirect( action = 'main.default', queryString = "msg=501" );
			}

			// lock the session and get the sessionObj from the cache
			lock scope='session' timeout='10' {
				session.sessionObj = application.securityService.checkUserSession( rc.sessionId );
			}

			// check if the sessionObj returned is valid
			if( session.sessionObj.getUserId() EQ 0 ) {
				// it isn't, redirect to the login page
				variables.fw.redirect( action = 'main.default', queryString = "msg=502" );            
			}

			// check if the second factor is required and has been completed
			if( application.use2FA and !session.sessionObj.getIsAuthenticated() ) {
				// it hasn't, redirect to the login page
				variables.fw.redirect( action = 'main.default', queryString = "msg=507" );
			}

			// lock the session and rotate the session id (for every request)
			// NOTE: This rotation can cause decryption errors in some browsers when the back button is used 
			// due to the browser sending the cookie associated with that request. If this is an issue for 
			// your code, simply comment out the following three lines and sessions will not be rotated.
			lock scope='session' timeout='10' {
				session.sessionObj = application.securityService.rotateUserSession( session.sessionObj );
			}

			// Update session's last action datetime and save session
			lock scope='session' timeout='10' {
				session.sessionObj = application.securityService.updateUserSession( session.sessionObj );
			}

			// send a new cookie with the new encrypted session id
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

		}

	}

}
