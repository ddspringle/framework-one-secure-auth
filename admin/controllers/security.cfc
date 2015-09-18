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
            session.sessionObj = createObject( 'component', 'model.beans.Session').init();
        }

    }

    /**
    * @displayname authorize
    * @description I authenticate and rotate a session on each request
    */  
    function authorize( rc ) {

        var actionArr = [ 'admin:main.default', 'admin:main.authenticate' ];

        // check if we're already logging in
        if( !arrayFind( actionArr, rc.action )) {

            // we're not, check if the session cookie is defined
            if( !structKeyExists( cookie, application.cookieName ) ) {
                // it isn't, redirect to the login page
                variables.fw.redirect( action = 'main.default', queryString = "msg=#urlEncodedFOrmat( '501: Your session has timed out. Please log in again to continue.')#" );  
            }

            // lock the session and get the sessionObj from the cache
            lock scope='session' timeout='10' {
                session.sessionObj = application.securityService.checkUserSession( application.securityService.getSessionIdFromCookie( cookie[ application.cookieName ] ) );
            }

            // check if the sessionObj returned is valid
            if( session.sessionObj.getUserId() EQ 0 ) {
                // it isn't, redirect to the login page
                variables.fw.redirect( action = 'main.default', queryString = "msg=#urlEncodedFOrmat( '502: Your session has timed out. Please log in again to continue.')#" );            
            }

            // lock the session and rotate the session id (for every request)
            lock scope='session' timeout='10' {
                session.sessionObj = application.securityService.rotateUserSession( session.sessionObj );
            }

            // send a new cookie with the new encrypted session id
            getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=#application.securityService.setSessionIdForCookie( session.sessionObj.getSessionId() )#;path=/;domain=.#CGI.HTTP_HOST#;HTTPOnly");

        }

    }

}
