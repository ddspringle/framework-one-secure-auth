component {

    this.name = 'secure_auth';
    this.applicationTimeout = createTimeSpan( 30, 0, 0, 0 ); // 30 days
    this.sessionManagement = true;
    this.sessionTimeout = createTimeSpan( 0, 0, 30, 0 ); // 30 minutes
    this.datasource = 'secureauth';
    this.scriptprotect = 'all';
    // CF10+ uncomment the following line to make your cfid/cftoken cookies httpOnly
    // this.sessioncookie.httpOnly;
    
    // set application specific variables
    variables.framework = {
        usingSubsystems = true
    };

    // set environment variables - one of 'dev' (default), 'test' or 'prod'
    // The 'prod' (production) environment is the only one that executes IP watching and blocking.
    // This helps prevent being added to the watched or blocked IP list while
    // in development or testing. NOTE: You can specify any other environments here,
    // such as QA, or rename any other environment except 'prod' as needed
    // You can also specify environment specific framework settings here.
    // See the Environment Control section of the FW/1 Developing Applications Manual:
    // https://github.com/framework-one/fw1/wiki/Developing-Applications-Manual
    variables.framework.environments = {
        dev = {},
        test = {},
        prod = {}
    }

    function _get_framework_one() {
        if ( !structKeyExists( request, '_framework_one' ) ) {

            // create your FW/1 application:
            request._framework_one = new MyApplication( variables.framework );

        }
        return request._framework_one;
    }

    // delegation of lifecycle methods to FW/1:
    function onApplicationStart() {

        // load and initialize the SecurityService with keyring path and master key
        // NOTE: The keyRingPath should be placed in a secure directory *outside* of  
        // your web root to prevent key disclosure over the internet. 
        // ex: keyRingPath = '/opt/secure/keyrings/' & hash( 'secure_auth', 'MD5', 'UTF-8', 420 ) & '.bin'
        // this path should be accessible *only* to the user the CFML application server is
        // running under and to root/Administrator users
        
        application.securityService = new model.services.SecurityService(
            keyRingPath = expandPath( '../keyrings/' ) & hash( 'secure_auth_keyring', 'MD5', 'UTF-8', 173 ) & '.bin',
            masterKey = mid( lCase( hash( 'secure_auth_master_key', 'SHA-512', 'UTF-8', 512 ) ), 38, 22 ) & '=='
        );

        /*application.securityService = new model.services.SecurityService(
            keyRingPath = expandPath( 'keyrings/' ) & hash( 'secure_auth_keyring', 'MD5', 'UTF-8', 173 ) & '.bin',
            masterKey = mid( lCase( hash( 'secure_auth_master_key', 'SHA-512', 'UTF-8', 512 ) ), 38, 22 ) & '=='
        );*/

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
            encryptionKey1          = application.keyRing[1].key,
            encryptionAlgorithm1    = application.keyRing[1].alg,
            encryptionEncoding1     = application.keyRing[1].enc,
            encryptionKey2          = application.keyRing[2].key,
            encryptionAlgorithm2    = application.keyRing[2].alg,
            encryptionEncoding2     = application.keyRing[2].enc,
            encryptionKey3          = application.keyRing[3].key,
            encryptionAlgorithm3    = application.keyRing[3].alg,
            encryptionEncoding3     = application.keyRing[3].enc,
            hmacKey                 = generateSecretKey( 'HMACSHA512' ),
            hmacAlgorithm           = 'HMACSHA512',
            hmacEncoding            = 'UTF-8'
        );

        // clear the keyring from the application scope
        structDelete( application, 'keyRing' );

        // set the name of the cookie to use for session management 
        // (*DO NOT USE* cfid, cftoken or jsessionid)
        // Obscuring your cookie name using common tracker names
        // can help throw a would-be hacker off course
        // ex: __ga_utm_source, __imgur_ref_id, __fb_beacon_token, etc.
        application.cookieName = '__ga_utm_source';

        // set the name of the dummy cookies to use to help
        // obfuscate the actual session cookie 
        // (*DO NOT USE* cfid, cftoken or jsessionid)
        // Using obscure and/or common session cookie names
        // here can help throw a would-be hacker off course
        // ex: __secure_auth_id, session_id, _fb__beacon__token, etc.
        application.dummyCookieOne = '__secure_auth_id';
        application.dummyCookieTwo = 'session_id';
        application.dummyCookieThree = '_fb__beacon__token_';

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

        // choose the way an ip address that is in the blocklist
        // is handled by the application. One of three modes are
        // available:
        // *
        // 'abort' - this simply aborts all further processing 
        // 'redirect' - this redirects to the ipBlocked.html file (default)
        // *
        application.blockMode = 'redirect';
        
        return _get_framework_one().onApplicationStart();
    }
    function onError( exception, event ) {
        return _get_framework_one().onError( exception, event );
    }
    function onRequest( targetPath ) {
        return _get_framework_one().onRequest( targetPath );
    }
    function onRequestEnd() {
        return _get_framework_one().onRequestEnd();
    }
    function onRequestStart( targetPath ) {
        return _get_framework_one().onRequestStart( targetPath );
    }
    function onSessionStart() {
        return _get_framework_one().onSessionStart();
    }
}
