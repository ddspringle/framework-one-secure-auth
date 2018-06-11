component {

    this.name = 'secure_auth_combined';
    this.applicationTimeout = createTimeSpan( 30, 0, 0, 0 ); // 30 days
    this.sessionManagement = true;
    this.sessionTimeout = createTimeSpan( 0, 0, 30, 0 ); // 30 minutes
    this.datasource = 'twofactorauth';
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
    };

    function _get_framework_one() {
        if ( !structKeyExists( request, '_framework_one' ) ) {

            // create your FW/1 application:
            request._framework_one = new MyApplication( variables.framework );

        }
        return request._framework_one;
    }

    // delegation of lifecycle methods to FW/1:
    function onApplicationStart() {

        // Lucee 5+ added the function generatePBKDFKey() which is a much 
        // more secure way of handling the keyring master key than the 
        // legacy hashing routine this code previously used. To maintain 
        // backwards compatibility with Lucee 4.5, a few hoops have been 
        // introduced to determine which version of the Lucee engine is in 
        // use, and select the appropriate routine (PBKDF or legacy) based 
        // on the version information.

        // If you'll be using Lucee 5+, then you can remove the code below 
        // that applies only if Lucee is running v4.5. Likewise, if you're 
        // using Lucee 4.5 then you can remove the code below that applies 
        // only if Lucee is running v5+.

        // NOTE: toBase64(), toBinary() and toString() are used in lieu if using
        // charsetDecode() and charsetEncode() to aid in obfuscating
        // sensitive data in case of accidental code disclosure
        // This is not security, it is simply obfuscation that would
        // confuse only those who are not programmers themselves

        // set use of PBKDF master key to false
        application.usePBKDF = false;

        // define a password for the application's master key
        // defined using toBase64( 'secure_auth_master_key', 'UTF-8' )
        // which provides some obfuscation if this code ever leaks
        // define your own password using the same technique
        application.password = toBinary( 'c2VjdXJlX2F1dGhfbWFzdGVyX2tleQ==' );

        // define the salt to use with PBKDF
        // defined using toBase64( 'RtTpPAKXNBh0zoWb', 'UTF-8' )
        // which provides some obfuscation if this code ever leaks
        // define your own salt using the same technique
        // salt should be a minimum of 16 chars (128 bits) long
        application.salt = toBinary( 'UnRUcFBBS1hOQmgwem9XYg==' );

        // define the keyring filename to use
        // defined using toBase64( 'secure_auth_keyring', 'UTF-8' )
        // which provides some obfuscation if this code ever leaks
        // define your own keyring filename using the same technique
        application.keyRingFilename = toBinary( 'c2VjdXJlX2F1dGhfa2V5cmluZw==' );        

        // set the path to the keyring file location on disk
        // NOTE: The keyRingPath should be placed in a secure directory *outside* of  
        // your web root to prevent key disclosure over the internet.
        // this path should be accessible *only* to the user the CFML application server is
        // running under and to root/Administrator users
        // you can change the number of hash iterations (173 by default) to further
        // distinguish this application from others using this framework example 
        // ex: keyRingPath = expandPath( '/opt/secure/keyrings/' ) & hash( 'toString( application.keyRingFilename, 'UTF-8' ), 'MD5', 'UTF-8', 420 ) & '.bin'
        application.keyRingPath = expandPath( 'keyrings/' ) & hash( toString( application.keyRingFilename, 'UTF-8' ), 'MD5', 'UTF-8', 173 ) & '.bin';

        // get the engine we're currently deployed on
        application.engine = server.coldfusion.productname;

        // check if we're using Lucee
        if( findNoCase( 'lucee', application.engine ) ) {
            // we are, get the version of lucee we're running
            application.engineVersion = server.lucee.version;
            // check if it is version 5 or above
            if( listFirst( application.engineVersion, '.' ) gte 5 ) {
                // it is, we can use a PBKDF master key
                application.usePBKDF = true;
            }
        // otherwise, check if we're running Railo
        } else if( findNoCase( 'railo', application.engine ) ) {
            // we are, get the version of Railo we're running
            application.engineVersion = server.railo.version;
        // otherwise, assume we're running ACF
        } else {
            // get the version of ACF we're running
            application.engineVersion = listFirst( server.coldfusion.productversion );
            // check if it is version 11 or above
            if( listFirst( application.engineVersion ) gte 11 ) {
                // it is, we can use a PBKDF master key
                application.usePBKDF = true;
            }
        }

        // NOTE: If upgrading from a previous release that already has 
        // a generated and used keyring file, and you are running Lucee 5+
        // or ACF 11+, then you risk either generating a new keyring file, 
        // or throwing a decryption error, as this version will try to use  
        // PBKDF for the master key instead of legacy hashing of previous versions. 
        // You can either first rekey your keyring using the new PBKDF master
        // key and then proceed (see function rekeyKeyRing() in model/services/SecurityService.cfc),
        // or you can uncomment the following line to prevent these conditions 
        // by forcing the use of the legacy master key

        // application.usePBKDF = false;

        // check if we can use a PBKDF master key
        if( application.usePBKDF ) {
            // we can, generate the master key using PBKDF
            // in addition to differences in passwords and salts used
            // you can change the algorithm (PBKDF2WithHmacSHA1 by default)
            // and the number of iterations (2048 by default) to futher distinguish
            // this application from others using this framework example
            application.masterKey = generatePBKDFKey( 'PBKDF2WithHmacSHA1', toString( application.password, 'UTF-8' ), toString( application.salt, 'UTF-8' ), 2048, 128 );
        // otherwise
        } else {
            // we cannot, generate the master key using legacy hashing
            // in addition to differences in passwords used
            // you can change the hash algorithm (SHA-512 by default)
            // the number of iterations (512 by default) and the 
            // starting position of the mid() statement (38 by default - range from 1 to 106 with SHA-512)
            // to further distinguish this application from others using this
            // framework example
            application.masterKey = mid( lCase( hash( toString( application.password, 'UTF-8' ), 'SHA-512', 'UTF-8', 512 ) ), 38, 22 ) & '==';
        }

        // provide a static HMAC key using generateSecretKey( 'HMACSHA512' )
        // to be used in development environments where application reload
        // forcing re-login is undesireable (currently any environment other than 'prod')
        application.developmentHmacKey = '1Srai7KJK/oUD/pNHvaCJdb5JLJfyPOOjIyYSLvttJs0PaA9HskfJlz2YsXjyokh4fDTC0utupQ4SREklCCZ4w==';

        // load and initialize the SecurityService with keyring path and master key
        application.securityService = new model.services.SecurityService(
            keyRingPath = application.keyRingPath,
            masterKey = application.masterKey
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
        // NOTE: To avoid being forced to login every time the framework 
        // is reloaded (reload=true), the 'hmacKey' value below is set to a 
        // static HMAC key instead of creating a new one each time.
        // This is randomized (using 'generateSecretKey( 'HMACSHA512' )')
        // in production for increased security, but can be static in development
        // to avoid the cookies being improperly signed on reload.
        // You should change this HMAC key in your environment.
        application.securityService = application.securityService.init( 
            encryptionKey1          = application.keyRing[1].key,
            encryptionAlgorithm1    = application.keyRing[1].alg,
            encryptionEncoding1     = application.keyRing[1].enc,
            encryptionIV1           = binaryDecode( application.keyRing[1].iv, 'BASE64' ),
            encryptionKey2          = application.keyRing[2].key,
            encryptionAlgorithm2    = application.keyRing[2].alg,
            encryptionEncoding2     = application.keyRing[2].enc,
            encryptionIV2           = binaryDecode( application.keyRing[2].iv, 'BASE64' ),
            encryptionKey3          = application.keyRing[3].key,
            encryptionAlgorithm3    = application.keyRing[3].alg,
            encryptionEncoding3     = application.keyRing[3].enc,
            encryptionIV3           = binaryDecode( application.keyRing[3].iv, 'BASE64' ),
            hmacKey                 = ( ( application.securityService.getEnvironment() eq 'prod' ) ? generateSecretKey( 'HMACSHA512' ) : application.developmentHmacKey ),
            hmacAlgorithm           = 'HMACSHA512',
            hmacEncoding            = 'UTF-8'
        );

        // clear out temp keys from the application scope
        for( item in [ 'password', 'salt', 'keyRingFilename', 'keyRingPath', 'keyRing', 'masterKey', 'developmentHmacKey', 'usePBKDF' ] ) {
            structDelete( application, item );
        }

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
        // is handled by the application. One of two modes are
        // available:
        // *
        // 'abort' - this simply aborts all further processing 
        // 'redirect' - this redirects to the ipBlocked.html file (default)
        // *
        application.blockMode = 'redirect';
	
    	// configure if this application will use two factor authentication
    	// two factor authentication uses the users SMS Provider and telephone
    	// number to send an authorization code as a second security factor
    	// for logging into the application.
        // NOTE: Registration depends on this being set to either true or false 
        // If set to false, the providerId will be set to zero (0) and the 
        // phone number will be blank. If you turn on TFA after users have 
        // registered, they will not be able to login until these values 
        // are assigned in the database.
    	application.use2FA = false;

        // configure if the application will reject hacked passwords on
        // system password generation and password changes by the user
        // This is set to 'false' by default to maintain backwards compatibility
        // however it is recommended that you turn this feature on by setting
        // this value to 'true' instead.
        application.rejectHackedPasswords = false;

        // set the path to the top 100,000 hacked password list
        // you can replace this list with any list you choose. The format
        // of the file should be a single password entry per line. Lines
        // can be terminated with a cariage-return and linefeed combined, a linefeed
        // only or a carriage-return only.
        // Additional password files can be downloaded from:
        // https://github.com/danielmiessler/SecLists/tree/master/Passwords
        application.passwordFilePath = expandPath( 'data/top_100000_hacked_passwords.txt' );
        
        // fire off framework one's method
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
