/**
*
* @file model\services\SecurityService.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I provide security and session related functions
*
*/

component displayname="SecurityService" accessors="true" {

	property encryptionKey1;
	property encryptionAlgorithm1;
	property encryptionEncoding1;
	property encryptionIV1;
	property encryptionKey2;
	property encryptionAlgorithm2;
	property encryptionEncoding2;
	property encryptionIV2;
	property encryptionKey3;
	property encryptionAlgorithm3;
	property encryptionEncoding3;
	property encryptionIV3;
	property hmacKey;
	property hmacAlgorithm;
	property hmacEncoding;
	property keyRingPath;
	property masterKey;

	/**
	* @displayname init
	* @description I am the constructor method for SecurityService
	* @param	encryptionKey1 {String} - I am the encryption key used for pass number 1
	* @param	encryptionAlgorithm1 {String} - I am the encryption algorithm used for pass number 1
	* @param	encryptionEncoding1 {String} - I am the encryption encoding used for pass number 1
	* @param	encryptionIV1 {String} - I am the encryption initialization vector used for pass number 1
	* @param	encryptionKey2 {String} - I am the encryption key used for pass number 2
	* @param	encryptionAlgorithm2 {String} - I am the encryption algorithm used for pass number 2
	* @param	encryptionEncoding2 {String} - I am the encryption encoding used for pass number 2
	* @param	encryptionIV2 {String} - I am the encryption initialization vector used for pass number 2
	* @param	encryptionKey3 {String} - I am the encryption key used for pass number 3
	* @param	encryptionAlgorithm3 {String} - I am the encryption algorithm used for pass number 3
	* @param	encryptionEncoding3 {String} - I am the encryption encoding used for pass number 3
	* @param	encryptionIV3 {String} - I am the encryption initialization vector used for pass number 3
	* @param	hmacKey {String} - I am the key used for hmac hashing
	* @param	hmacAlgorithm {String} - I am the hashing algorithm used for hmac hashing
	* @param	hmacEncoding {String} - I am the encoding used for hmac hashing
	* @param	keyRingPath {String} - I am the path to the keyring file on disk
	* @param	masterKey {String} - I am the master key used for encryption/decryption of the keyring
	* @return 	this
	*/	
	public function init( 
		string encryptionKey1 = '',
		string encryptionAlgorithm1 = '',
		string encryptionEncoding1 = '',
		any encryptionIV1 = '',
		string encryptionKey2 = '',
		string encryptionAlgorithm2 = '',
		string encryptionEncoding2 = '',
		any encryptionIV2 = '',
		string encryptionKey3 = '',
		string encryptionAlgorithm3 = '',
		string encryptionEncoding3 = '',
		any encryptionIV3 = '',
		string hmacKey = '',
		string hmacAlgorithm = '',
		string hmacEncoding = '',
		string keyRingPath = '',
		string masterKey = ''
		) {

		variables.encryptionKey1 = arguments.encryptionKey1;
		variables.encryptionAlgorithm1 = arguments.encryptionAlgorithm1;
		variables.encryptionEncoding1 = arguments.encryptionEncoding1;
		variables.encryptionIV1 = arguments.encryptionIV1;
		variables.encryptionKey2 = arguments.encryptionKey2;
		variables.encryptionAlgorithm2 = arguments.encryptionAlgorithm2;
		variables.encryptionEncoding2 = arguments.encryptionEncoding2;
		variables.encryptionIV2 = arguments.encryptionIV2;
		variables.encryptionKey3 = arguments.encryptionKey3;
		variables.encryptionAlgorithm3 = arguments.encryptionAlgorithm3;
		variables.encryptionEncoding3 = arguments.encryptionEncoding3;
		variables.encryptionIV3 = arguments.encryptionIV3;
		variables.hmacKey = arguments.hmacKey;
		variables.hmacAlgorithm = arguments.hmacAlgorithm;
		variables.hmacEncoding = arguments.hmacEncoding;
		variables.keyRingPath = arguments.keyRingPath;
		variables.masterKey = arguments.masterKey;

		return this;
	}

	/* DATA ENCRYPTION

		This section of the security service provides functions to
		help manage encrypting values in the application.

		Functions include:
			encrypting a plain text input value by mode

			Modes include:
				db - triple-pass encryption for database storage of values
				repeatable - triple-pass repeatable encryption (for storing usernames)
				url - single-pass encryption for values passed on the url
				form - single-pass encryption using a different key for values passed in the form
				rform - double-pass repeatable encryption (for encrypting uid's in form selects)
				cookie - single-pass encryption using a different key for values passed in cookies
				master - double-pass encryption of the keyring using CBC and CTR

	*/

	/**
	* @displayname 	dataEnc
	* @description 	I encrypt passed in values based on scope
	* @param		value {String} required - I am the value to encrypt
	* @param		mode {String} default: db - I am the mode of encryption to use - one of db, repeatable, url, form, cookie or master
	* @return		string
	*/
	public string function dataEnc( required string value, string mode = 'db' ) {
		
		var onePass = '';
		var twoPass = '';
		var lastPass = '';
		
		// check if the passed value has length
		// cannot use `arguments.value.len()` with Lucee when `value` is numeric.
		// https://luceeserver.atlassian.net/browse/LDEV-332
		if( len( arguments.value ) ) {

			// switch on the encryption mode
			switch( arguments.mode ) {

				// database
				case 'db':
					// using database encryption, encrypt with the first set of keys and algorithm
					onepass = encrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1, variables.encryptionIV1 );
					// and again with the second set of keys and algorithm
					twopass = encrypt( onepass, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2, variables.encryptionIV2 );
					// and again with the third set of keys and algorithm
					lastPass = encrypt( twopass, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3, variables.encryptionIV3 );
				break;

				// repeatable database
				case 'repeatable':
					// using repeatable database encryption, encrypt with the first set of keys and algorithm
					onepass = encrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1, variables.encryptionIV1 );
					// and again with the second set of keys and algorithm
					twopass = encrypt( onepass, variables.encryptionKey2,  listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2, variables.encryptionIV2 );
					// and again with the third set of keys and algorithm
					lastPass = encrypt( twopass, variables.encryptionKey3,  listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3, variables.encryptionIV3);
				break;

				// master
				case 'master':
					// using master encryption, encrypt with the master key
					onePass = encrypt( arguments.value, variables.masterKey, 'AES/CBC/PKCS5Padding', 'HEX' );
					lastPass = encrypt( onePass, variables.masterKey, 'BLOWFISH/CTR/PKCS5Padding', 'HEX' );
				break;

				// URL
				case 'url':				
					// using url encryption, check if using BASE64 encoding on the URL key
					if( findNoCase( 'BASE64', variables.encryptionEncoding1 ) ) {
					
						// we are, encrypt with the first set of keys and repeatable algorithm
						lastPass = encrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1, variables.encryptionIV1);
						// using BASE64 encoding, URL encode the value
						lastPass = URLEncodedFormat( lastPass );
					
					// otherwise
					} else {
					
						// not BASE64 encoded, encrypt with the first set of keys and algorithm
						lastPass = encrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1, variables.encryptionIV1 );
					
					// end checking if useing BASE64 encoding on the URL key	
					}
				break;

				// FORM
				case 'form':
					// using form encryption, encrypt with the second set of keys and algorithm
					lastPass = encrypt( arguments.value, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2, variables.encryptionIV2 );
				break;

				// REPEATABLE FORM
				case 'rform':
					// using rform encryption, encrypt with the second set of keys and repeatable algorithm
					onePass = encrypt( arguments.value, variables.encryptionKey2,  listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2, variables.encryptionIV2 );
					// and encrypt with the third set of keys and repeatable algorithm
					lastPass = encrypt( onePass, variables.encryptionKey3,  listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3, variables.encryptionIV3 );
				break;

				// COOKIE
				case 'cookie':
					// using cookie encryption, encrypt with the first set of keys and algorithm
					lastPass = encrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3, variables.encryptionIV3 );
				break;

				// default
				default:
					return lastPass;
				break;

			}

		// end checking if the passed value has length
		}
		
		// return the encrypted value (or null if passed value has no length)
		return lastPass;
	}

	/* DATA DECRYPTION

		This section of the security service provides functions to
		help manage decrypting values in the application.

		Functions include:
			decrypting an encrypted input value by mode

			Modes include:
				db - triple-pass decryption for values stored in the database
				repeatable - triple-pass repeatable decryption (for decrypting usernames)
				url - single-pass decryption for values passed on the url
				form - single-pass decryption using a different key for values passed in the form
				rform - double-pass repeatable decryption (for decrypting uid's from form selects)
				cookie - single-pass decryption using a different key for values passed in cookies
				master - double-pass decryption of the keyring using CBC and CTR

	*/

	/**
	* @displayname	dataDec
	* @description	I decrypt passed in values based on scope
	* @param		value {String} required - I am the value to decrypt
	* @param		mode {String} default: db - I am the mode of decryption to use - one of db, repeatable, url, form, cookie or master
	* @return		string
	*/
	public string function dataDec( required string value, string mode = 'db' ) {

		// var scope
		var onePass = '';
		var twoPass = '';
		var lastPass = '';
		
		// check if the passed value has length
		// cannot use `arguments.value.len()` with Lucee when `value` is numeric.
		// https://luceeserver.atlassian.net/browse/LDEV-332
		if( len( arguments.value ) ) {

			// switch on the encryption mode
			switch( arguments.mode ) {

				// database
				case 'db':
					// using database encryption, decrypt with the third set of keys and algorithm
					var onePass = decrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3, variables.encryptionIV3 );
					// and again with the second set of keys and algorithm
					var twoPass = decrypt( onepass, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2, variables.encryptionIV2 );
					// and again with the first set of keys and algorithm
					var lastPass = decrypt( twopass, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1, variables.encryptionIV1 );
				break;

				// repeatable database
				case 'repeatable':
					// using database encryption, decrypt with the third set of keys and algorithm
					var onePass = decrypt( arguments.value, variables.encryptionKey3, listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3, variables.encryptionIV3 );
					// and again with the second set of keys and algorithm
					var twoPass = decrypt( onepass, variables.encryptionKey2, listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2, variables.encryptionIV2 );
					// and again with the first set of keys and algorithm
					var lastPass = decrypt( twopass, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1, variables.encryptionIV1 );
				break;

				// master
				case 'master':
					// using master encryption, decrypt with the master key and second algorithm
					onePass = decrypt( arguments.value, variables.masterKey, 'BLOWFISH/CTR/PKCS5Padding', 'HEX' );
					lastPass = decrypt( onePass, variables.masterKey, 'AES/CBC/PKCS5Padding', 'HEX' );
				break;

				// URL
				case 'url':
					// using url encryption, check if useing BASE64 encoding on the URL key
					if( findNoCase( 'BASE64', variables.encryptionEncoding1 ) ) {

						// using BASE64 encoding, URL decode the value
						arguments.value = urlDecode( arguments.value );
						// replace spaces with +
						arguments.value = replace( arguments.value, chr(32), '+', 'ALL' );
						// decrypt with the first set of keys and repeatable algorithm
						lastPass = decrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1, variables.encryptionIV1 );

					// otherwise
					} else {

						// not BASE64 encoded, decrypt with the first set of keys and algorithm
						lastPass = decrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1, variables.encryptionIV1 );

					// end checking if useing BASE64 encoding on the URL key	
					}
				break;

				// FORM
				case 'form':
					// using form encryption, decrypt with the second set of keys and algorithm
					lastPass = decrypt( arguments.value, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2, variables.encryptionIV2 );
				break;

				// REPEATABLE FORM
				case 'rform':
					// using rform encryption, decrypt with the third set of keys and repeatable algorithm
					onePass = decrypt( arguments.value, variables.encryptionKey3,  listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3, variables.encryptionIV3 );
					// and decrypt with the second set of keys and repeatable algorithm
					lastPass = decrypt( onePass, variables.encryptionKey2,  listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2, variables.encryptionIV2 );
				break;

				// COOKIE
				case 'cookie':
					// using cookie encryption, decrypt with the first set of keys and algorithm
					lastPass = decrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3, variables.encryptionIV3 );
				break;

				// default
				default:
					return lastPass;
				break;
			}

		// end checking if the passed value has length
		}

		// return the decrypted value (or null if passed value has no length)
		return lastPass;

	}

	/* HMAC

		This section of the security service provides functions to
		help manage keyed-hash method authentication code (HMAC) 
		requirements for sessions.

		Functions include:
			generating a signed HMAC value from input using the HMAC
			key and algorithm given to this security service upon 
			initialization.

	*/

	/**
	* @displayname  dataHmac
	* @description  I hash and return passed in values based on HMAC
	* @param		input {String} required - I am the string to HMAC
	* @return		string
	*/
	public string function dataHmac( required string input ) {

		return hmac( arguments.input, variables.hmacKey, variables.hmacAlgorithm, variables.hmacEncoding );

	}

	/* HASHING

		This section of the security service provides functions to
		help manage obfuscation with hashing.

		Functions include:
			generating a hash by passing in the input, method, iterations 
			and flags for case and date addition
			NOTE: Breaking change in this release: 
				  outcase (lower/upper) {String} parameter has been removed 
				  it has been replaced with useLowercase {Boolean} instead
				  the default remains 'true' so unless you specified 'outcase'
				  when calling this function, it will not affect you. If you have
				  I apologize but hope you agree this function is now more descriptive
				  while also reducing the code required to execute.
			NOTE: This function has found new use with the addition of an additional
				  parameter: addDate {Boolean}. This defaults to false to maintain
				  backwards compatibility, however, seting addDate to true now appends
				  the current date in yyyymmdd format to the input string before being
				  hashed - providing increased day to day protection for obfuscated
				  url parameter names against would-be hackers. It is recommended that
				  you use addDate = true on internal, non-public or otherwise non-indexed
				  views within your application. Use of addDate on public/indexed pages
				  will break the link and is, obviously, *not* recommended.


	*/

	/**
	* @displayname	uberHash
	* @description	I hash and return passed in values based on method and iterations (ACF support)
	* @param		input {String} required - I am the string to hash
	* @param		method {String} default: SHA-384 - I am the encoding to use for this hash
	* @param		iterations {Numeric} default: 1000 - I am the number of times to has the value
	* @param		useLowercase {Boolean} default: true - I flag if the hash should be returned lowercase (true) or uppercase (false)
	* @param		addDate {Boolean} default: false - I flag if the current date should be appended to the input when hashing
	* @return		string
	*/
	public string function uberHash( required string input, string method = 'SHA-384', numeric iterations = 1000, boolean useLowercase = true, boolean addDate = false ) {

		// use the native hash() function with UTF-8 encoding to encode the input string
		var output = hash( arguments.input & ( ( arguments.addDate ) ? dateFormat( now(), 'yyyymmdd' ) : '' ), arguments.method, 'UTF-8', arguments.iterations );

		// check if we're returning lowercase
		if( arguments.useLowercase ) {
			// we are, set the case of the hash to lowercase
			output = lCase( output );
		}

		// return the hashed input value 
		return output;

	}

	/* RANDOM PASSWORD

		This section of the security service provides functions to
		help manage generating random passwords for users (new, reset).

		Functions include:
			generating a random password of a specified or random length

	*/

	/**
	* @displayname	getRandomPassword
	* @description	I generate a random password of random length
	* @param		length {Numeric} default: 0 - I am the length of the password to generate, if not specified then a random length between 12 and 18 characters is chosen
	* @return		string
	*/
	public string function getRandomPassword( numeric length = 0 ) {

		// configure special chars to use
		var special = '!,@,##,$,%,^,&,*';
		var password = '';
		var ix = 0;
		var pattern = '';
		var char = '';

		// check if a password length was specified
		if( !arguments.length ) {
			// it wasn't specified, set a random length
			arguments.length = randRange( 12, 18, 'SHA1PRNG' );
		}

		// loop through the length of the password
		for( ix = 1; ix <= arguments.length; ix++ ) {

			// choose a random pattern (1 to 4)
			pattern = randRange( 1, 4, 'SHA1PRNG' );

			// switch on the pattern of 1 to 4
			switch( pattern ) {
				// case 1 - lowercase alpha
				case 1:
					// select random lowercase alpha character
					char = chr( randRange( 97, 122, 'SHA1PRNG' ) );
				break;

				// case 2 - uppercase alpha
				case 2:
					// select random uppercase alpha character
					char = chr( randRange( 65, 90, 'SHA1PRNG' ) );
				break;

				// case 3 - numeric
				case 3:
					// select random numeric character
					char = chr( randRange( 48, 57, 'SHA1PRNG' ) );
				break;

				// case 4 - special
				case 4:
					// select random special character from the list
					char = listGetAt( special, randRange( 1, listLen( special ), 'SHA1PRNG' ) );
				break;
			}

			// add this character to the password
			password &= char;
		}

		// if hacked password checking is enabled, and this system  
		// generated password is found in the hacked password list
		if( application.rejectHackedPasswords and isPasswordHacked( password ) ) {
			// call this function recursively
			return getRandomPassword( arguments.length );
		}

		// return the random password
		return password;

	}

	/* SESSION MANAGEMENT

		This section of the security service provides functions to
		help manage logged on user sessions.

		Functions include:
			checking if a user's session exists in the cache 
			creating a new user session after authentication 
			storing, clearing, and updating a user's session object
			generating and rotating a user's session id
			setting and retreiving the encrypted session id used in cookies

	*/

	/**
	* @displayname	checkUserSession
	* @description	I retrieve the users session object from cache, and return it if it exists, else I return a blank session object
	* @param		sessionId {String} required - I am the session id to check
	* @return		any
	*/
	public any function checkUserSession( required string sessionId ) {

		// get the session object from the cache
		var sessionObj = cacheGet( uberHash( arguments.sessionId, 'MD5', 3000 ) );

		// ensure it is still in the cache
		if( isNull( sessionObj ) ) {

			// it isn't, return an empty session object
			return new model.beans.Session();

		// otherwise, ensure the session shouldn't have already expired (30 mins)
		} else if( dateDiff('n', sessionObj.getLastActionAt(), now() ) GTE application.timeoutMinutes ) {

			// it should have expired, return an empty session object
			return new model.beans.Session();

		// otherwise, ensure that the hmac code matches for this session
		} else if( len( sessionObj.getHmacCode() ) and dataHmac( arguments.sessionId ) neq sessionObj.getHmacCode() ) {

			// it doesn't match, return an empty session object
			return new model.beans.Session();

		// otherwise
		} else {

			// session is valid, return the session object
			return sessionObj;

		}

	}

	/**
	* @displayname	createUserSession
	* @description	I generate and return a session object based on passed in values
	* @param		userId {Numeric} required - I am the user id of the user to generate a session for
	* @param		role {Numeric} required - I am the role assigned to the user
	* @param		firstName {String} required - I am the first name of the user
	* @param		lastName {String} required - I am the last name of the user
	* @return		any
	*/
	public any function createUserSession( required numeric userId, required numeric role, required string firstName, required string lastName ) {

		// create a session object based on the passed in arguments
		var sessionObj = new model.beans.Session(
			sessionId = getSessionId(),
			userId = arguments.userId,
			role = arguments.role,
			firstName = arguments.firstName,
			lastName = arguments.lastName,
			mfaCode = getMfaCode(),
			isAuthenticated = false,
			lastActionAt = now()
		);

		// save the user session to the cache
		setUserSession( sessionObj );

		// and return the session object
		return sessionObj;

	}

	/**
	* @displayname	setUserSession
	* @description	I store a sessio0n object in the cache
	* @param		sessionObj {Any} required - I am the session object to store in the cache
	* @return		void
	*/
	public void function setUserSession( required any sessionObj ) {

		// put the user's session object into the cache
		cachePut( uberHash( arguments.sessionObj.getSessionId(), 'MD5', 3000 ), arguments.sessionObj, createTimeSpan( 0, 0, application.timeoutMinutes, 0), createTimeSpan( 0, 0, application.timeoutMinutes, 0 ) );

	}

	/**
	* @displayname	clearUserSession
	* @description	I remove a sessio0n object from the cache
	* @param		sessionObj {Any} required - I am the session object to clear from the cache
	* @return		void
	*/
	public void function clearUserSession( required any sessionObj ) {

		// remove the user's session object from the cache
		cacheRemove( uberHash( arguments.sessionObj.getSessionId(), 'MD5', 3000 ) );

	}

	/**
	* @displayname	rotateUserSession
	* @description	I update the session id of a session object 
	* @param		sessionObj {Any} required - I am the session object to rotate the id for
	* @return		any
	*/
	public any function rotateUserSession( required any sessionObj ) {

		// assign a new session id to the session object
		arguments.sessionObj.setSessionId( getSessionId() );

		// and return the session object
		return arguments.sessionObj;

	}

	/**
	* @displayname	updateUserSession
	* @description	I update the last action at of a session object, remove the old session and save the new one 
	* @param		sessionObj {Any} required - I am the session object to update
	* @return		any
	*/
	public any function updateUserSession( required any sessionObj ) {

		// clear out the existing user's session
		clearUserSession( arguments.sessionObj );
		// set the last action time to now
		arguments.sessionObj.setLastActionAt( now() );
		// set the hmac code for the session cookie
		arguments.sessionObj.setHmacCode( dataHmac( arguments.sessionObj.getSessionId() ) );
		// save the session to the cache
		setUserSession( arguments.sessionObj );

		// and return the session object
		return arguments.sessionObj;

	}

	/**
	* @displayname	getSessionId
	* @description	I generate a random hashed session id
	* @return		string
	*/
	public string function getSessionId() {

		// generate a random session id hash and return it
		return uberHash( createUUID() & now(), 'SHA-384', 2000 );

	}

	/**
	* @displayname	setSessionIdForCookie
	* @description	I encrypt the session id of a session object for cookie storage
	* @param		sessionId {Any} required - I am the session id to get for the cookie
	* @return		string
	*/
	public string function setSessionIdForCookie( required string sessionId ) {

		// encrypt the session id for cookie storage and return it
		return dataEnc( arguments.sessionId, 'cookie' );

	}

	/**
	* @displayname	getSessionIdFromCookie
	* @description	I decrypt the session id of a session object from cookie storage
	* @param		cookieId {Any} required - I am the cookie id to get the session id from
	* @return		string
	*/
	public string function getSessionIdFromCookie( required string cookieId ) {

		// return the value of the session id from the cookie
		return dataDec( arguments.cookieId, 'cookie' );

	}

	/* AUTHENTICATION

		This section of the security service provides functions to
		help manage authentication with the application.

		Functions include:
			generating a random heartbeat used to hash passwords during login
			generating a random two-factor auth code to be sent to the user when using 2FA

	*/

	/**
	* @displayname	getHeartbeat
	* @description	I generate a random hash of random length for use in authentication (to prevent password disclosure)
	* @return		string
	*/
	public string function getHeartbeat() {

		// get a random value for the heartbeat of the login form and return it
		return lCase( left( uberHash( now() & createUUID() & randRange( 1000, 9999, 'SHA1PRNG' ), 'SHA-384', randRange( 1000, 3000, 'SHA1PRNG' ) ), randRange( 32, 64, 'SHA1PRNG' ) ) );

	}

	/**
	* @displayname	getMfaCode
	* @description	I generate a random hashed two-factor authentication code of a random length
	* @return		string
	*/
	public string function getMfaCode() {

		// get a random auth code of a random length for multi-factor authentication and return it
		return left( uberHash( createUUID() & now(), 'MD5', randRange( 1000, 3000, 'SHA1PRNG' ) ), randRange( 4, 8, 'SHA1PRNG' ) );

	}

	/* CSRF

		This section of the security service provides functions to
		help manage Cross-Site Request Forgery (CSRF) attacks.

		Functions include:
			generating a random token key used as the session variable 
			used to store the token in when using 
			CSRFGenerateToken( [token key] [,forceNew] )

	*/

	/**
	* @displayname	generateTokenKey
	* @description	I generate a random value to use as the CSRF token key
	* @return		string
	*/
	public string function generateTokenKey() {
		// return randomly generated, random length valid variable (key) name
		return chr( randRange( 97, 122, 'SHA1PRNG' ) ) & left( lCase( uberHash( createUUID() & randRange( 1000, 100000, 'SHA1PRNG' ), 'SHA-384', randRange( 25, 150, 'SHA1PRNG' ) ) ), randRange( 31, 63, 'SHA1PRNG' ) );
	}

	/* KEYRING MANAGEMENT

		This section of the security service provides functions to
		help manage the security (encryption) keys used by the application.

		Functions include:
			generating a new random keyring (for new applications only)
			reading and writing the keyring file from the disk (on app start/restart)

	*/

	/**
	* @displayname	generateKeyRing
	* @description	I generate a new random keyring and save it to disk
	* @param		keyLength {Numeric} default: 128 - I am the keylength to use when generating encryption keys (128 or 256 are supported)
	* @return		array
	*/
	public array function generateKeyRing( numeric keyLength = 128 ) {

		// set up a new array to hold the keyring
		variables.keyRing = arrayNew(1);

		// loop 3 times to generate 3 keys
		for( i=1; i<=3; i++ ) {
			// randomly choose between AES and BLOWFISH algorithms for this key
			variables.algorithm = ( ( randRange( 0, 1, 'SHA1PRNG' ) ) ? 'AES' : 'BLOWFISH' );

			// set up a struct to hold the key
			variables.keyStruct = {};
			// generate an encryption key based on the algorithm
			variables.keyStruct['key'] = generateSecretKey( variables.algorithm, arguments.keyLength );
			// set the algoritm to use CBC/PKCS5Padding
			variables.keyStruct['alg'] = variables.algorithm & '/CBC/PKCS5Padding';
			// set the encoding to HEX
			variables.keyStruct['enc'] = 'HEX';
			// set the initialization vector
			variables.keyStruct['iv'] = generateInitializationVector( 'BASE64', variables.algorithm, arguments.keyLength );

			// add this key to the keyring
			variables.keyRing[i] = variables.keyStruct;
		}

		// save the keyring to disk
		saveKeyRingToDisk( variables.keyRing );

		// and return the keyring
		return variables.keyRing;

	}

	/**
	* @displayname	readKeyRingFromDisk
	* @description	I read the keyRing from disk
	* @return		array
	*/
	public array function readKeyRingFromDisk() {

		// check if the keyring file exists
		if( !fileExists( variables.keyRingPath ) ) {

			// it doesn't exist, return an empty array
			return arrayNew(1);

		}

		// and return the JSON as an array
		return deserializeJSON( dataDec( charsetEncode( fileReadBinary( variables.keyRingPath ), 'utf-8' ), 'master' ) );

	}

	/**
	* @displayname	saveKeyRingToDisk
	* @description	I save the keyRing to disk
	* @param		keyRing {Array} I am the Key Ring array
	* @return		void
	*/
	private void function saveKeyRingToDisk( required array keyRing ) {

		// write the keyring file to disk
		fileWrite( variables.keyRingPath, charsetDecode( dataEnc( serializeJSON( arguments.keyRing ), 'master' ), 'utf-8' ) );

	}

	/**
	* @displayname	rekeyKeyRing
	* @description	I rekey the keyring file
	* @param		oldKey {String} I am the old key used to encrypt the keyring file (default: currently defined master key)
	* @param 		newKey {String} required - I am the new key to use to encrypt the keyring file
	* @return		boolean
	*/
	private boolean function rekeyKeyRing( string oldKey = '', required string newKey ) {

		var currentKey = variables.masterKey;
		var keyRing = '';

		// check if the keyring file exists
		if( !fileExists( variables.keyRingPath ) ) {

			// it doesn't exist, return false
			return false;

		}

		// check if the oldKey is provided 
		if( !len( arguments.oldKey ) ) {
			// it isn't, assign to the current master key
			arguments.oldKey = currentKey;
		}

		// try 
		try {

			// ensure the master key matches the old key used to encrypt the keyring
			variables.masterKey = arguments.oldKey;

			// and get the JSON as an array
			keyRing = deserializeJSON( dataDec( charsetEncode( fileReadBinary( variables.keyRingPath ), 'utf-8' ), 'master' ) );

			// ensure the master key matches the new key to use to encrypt the keyring
			variables.masterKey = arguments.newKey;

			// and write the keyring file to disk
			fileWrite( variables.keyRingPath, charsetDecode( dataEnc( serializeJSON( keyRing ), 'master' ), 'utf-8' ) );

			// set the master key back to the original key
			variables.masterKey = currentKey;

		// catch any errors (e.g. decryption)
		} catch( any e ) {
			// set the master key back to the original key 
			variables.masterKey = currentKey;
			// uncomment the following line to diagnose the issue
			// writeDump( e ); abort;
			// and return false
			return false;
		}

		// all went well, return true
		return true;

	}

	/* IP BLOCKING 

		This section of the security service provides functions to
		help manage blocking of hackers/bots by IP address.

		Functions include:
			checking if an IP is on the blocked IP list
			adding and removing IP's from the blocked IP list
			reading and writing the blocked IP list to disk
			importing blocked ip lists from other hosts via http
	
	*/

	/**
	* @displayname	isBlockedIp
	* @description	I parse the blocked ip array and determine if the passed ip is blocked
	* @param		ipAddress {String} required - I am the ip address to check
	* @param		blockReserved {Boolean} default: false - I am a flag to determine if reserved (internal) ip addresses should be blocked (10.x.x.x, 192.168.x.x, etc. )
	* @return 		boolean
	*/
	public boolean function isBlockedIP( required string ipAddress, boolean blockReserved = false ) {

		// get blocked IP's from the cache
		var blockedIpArr = cacheGet( uberHash( 'blockedIpArr', 'MD5', 120 ) );
		var blockedIp = '';

		if( arguments.blockReserved ) {
			// check if the ip address is a 10.x.x.x address
			if( listFirst( arguments.ipAddress, '.') eq 10 ) {
				// it is, return true
				return true;
			// otherwise, check if it's a 127.0.0.x address, but not 127.0.0.1
			} else if( listFirst( arguments.ipAddress, '.') eq 127 and !argument.ipAddress eq '127.0.0.1' ) {
				// it is, return true
				return true;
			// otherwise, check if it's a 172.16-31.x.x address
			} else if( listFirst( arguments.ipAddress, '.') eq 172 and listFind( '16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31', listGetAt( arguments.ipAddress, 2, '.' ) ) ) {
				// it is, return true
				return true;
			// otherwise, check if it's a 192.168.x.x address
			} else if( listFirst( arguments.ipAddress, '.') eq 192 and listGetAt( arguments.ipAddress, 2, '.' ) eq 168 ) {
				// it is, return true
				return true;
			}
		}

		// check if the cached version of the blocked IP array exists
		if( isNull( blockedIpArr ) ) {
			// it doesn't, read in the blocked ip file
			blockedIpArr = readBlockedIPFileFromDisk();
			// and save the blocked ip array to the cache
			cachePut( uberHash( 'blockedIpArr', 'MD5', 120 ), blockedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );
		}

		// loop through the blocked ip array
		for( blockedIp in blockedIpArr ) {
			// and check if this ip address exists in the array
			if( blockedIp.ipAddress eq arguments.ipAddress ) {
				// it does, so it is blocked, return true
				return true;
			}
		}

		// ip address was not found in the array, return false
		return false;
	}

	/**
	* @displayname	addBlockedIp
	* @description	I add an ip address to the blocked ip array
	* @param		ipAddress {String} required - I am the ip address to add
	* @param		reason {String} - I am the reason why this IP is being blocked
	* @return		void
	*/
	public void function addBlockedIP( required string ipAddress, string reason = '' ) {

		// get blocked IP's from the cache
		var blockedIpArr = cacheGet( uberHash( 'blockedIpArr', 'MD5', 120 ) );
		var blockedIp = '';
		var ipRecord = structNew();
		var found = false;

		// check if the cached version of the blocked IP array exists
		if( isNull( blockedIPs ) ) {
			// it doesn't, read in the blocked ip file
			blockedIpArr = readBlockedIPFileFromDisk();
		}

		// loop through the blocked ip array
		for( blockedIp in blockedIpArr ) {
			// check if this ip address exists in the blocked ip list
			if( blockedIp.ipAddress eq arguments.ipAddress ) {
				// it does, set found to true
				found = true;
			}
		}

		// check if the ip address was already found in the array
		if( !found ) {

			// it wasn't found, create a json friendly struct
			ipRecord[ 'ipAddress' ] = arguments.ipAddress;
			ipRecord[ 'timestamp' ] = now();
			ipRecord[ 'reason' ] = arguments.reason;

			// and add it to the array
			blockedIpArr.append( ipRecord );

			// remove the existing cached blocked ip array
			cacheRemove( uberHash( 'blockedIpArr', 'MD5', 120 ) );

			// and save the blocked ip array to the cache
			cachePut( uberHash( 'blockedIpArr', 'MD5', 120 ), blockedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );

			// save the blocked ip's as a json file
			saveBlockedIPFileToDisk( blockedIpArr );

		}

	}

	/**
	* @displayname	removeBlockedIp
	* @description	I remove an ip address from the blocked ip array
	* @param		ipAddress {String} required - I am the ip address to remove
	* @return		void
	*/
	public void function removeBlockedIP( required string ipAddress ) {

		// get blocked IP's from the cache
		var blockedIpArr = cacheGet( uberHash( 'blockedIpArr', 'MD5', 120 ) );
		var blockedIp = '';
		var ix = 0;
		var found = false;

		// check if the cached version of the blocked IP array exists
		if( isNull( blockedIPs ) ) {
			// it doesn't, read in the blocked ip file
			blockedIpArr = readBlockedIPFileFromDisk();
		}

		// loop through the blocked ip array
		for( blockedIp in blockedIpArr ) {
			// increase the array index
			ix++;
			// check if this ip address exists in the blocked ip list
			if( blockedIp.ipAddress eq arguments.ipAddress ) {
				// it does, remove the element from the array
				blockedIpArr.deleteAt( ix );
				// and set found to true
				found = true;
			}
		}

		// check if the ip address was found
		if( found ) {

			// remove the existing cached blocked ip array
			cacheRemove( uberHash( 'blockedIpArr', 'MD5', 120 ) );

			// and save the blocked ip array to the cache
			cachePut( uberHash( 'blockedIpArr', 'MD5', 120 ), blockedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );

			// save the blocked ip's as a json file
			saveBlockedIPFileToDisk( blockedIpArr );

		}
	}

	/**
	* @displayname	saveBlockedIPFileToDiskToDisk
	* @description	I convert the blocked ip array into json and save it to disk
	* @param		blockedIpArr {Array} required - I am the blocked ip array to save
	* @return		void
	*/
	public void function saveBlockedIPFileToDisk( required array blockedIpArr ) {

		// convert the array to json
		var blockedIpJson = serializeJSON( arguments.blockedIpArr );
		// check if the blocked ip file exists
		if( fileExists( expandPath( application.blockedIpDir ) & 'blocked_ips.json' ) ) {
			// it does, delete the existing file
			fileDelete( expandPath( application.blockedIpDir ) & 'blocked_ips.json' );
		}
		// write the JSON to disk
		fileWrite( expandPath( application.blockedIpDir ) & 'blocked_ips.json', blockedIpJson, 'UTF-8' );

	}

	/**
	* @displayname	readBlockedIPFileFromDisk
	* @description	I read the blocked ip json from disk and convert it into an array
	* @return		array
	*/
	public array function readBlockedIPFileFromDisk() {

		var blockedIpJson = '';

		// check if the blocked ip file exists
		if( fileExists( expandPath( application.blockedIpDir ) & 'blocked_ips.json' ) ) {
			// it does, read in the JSON
			blockedIpJson = fileRead( expandPath( application.blockedIpDir ) & 'blocked_ips.json', 'UTF-8' );
			// and return an array of the JSON data
			return deserializeJSON( blockedIpJson );
		}

		// file does not exist, return an empty array
		return arrayNew(1);

	}

	/**
	* @displayname	importBlockedIPFileFromUrl
	* @description	I make an http call to a remote blocked_ips.json file and add them to our local blocked ip file
	* @param		importUrl {String} required - I am the FQDN URL to the blocked_ips.json file on the remote server (ex: https://domain.com/blocked/blocked_ips.json)
	* @return		void
	*/
	public void function importBlockedIPFileFromUrl( required string importUrl ) {

		var httpService = new http(); 
		var blockedIpArr = '';
		var blockedIp = '';

		// try to perform the import
		try {

			// set up the http attributes
			httpService.setMethod( 'GET' ); 
			httpService.setCharset( 'UTF-8' ); 
			httpService.setUrl( arguments.importUrl );

			// convert the returned JSON into an array
			blockedIpArr = deserializeJSON( httpService.send().getPrefix().fileContent );

			// loop through the array
			for( blockedIp in blockedIpArr ) {
				// and add each ip from the remote JSON file to our local array
				addBlockedIP( blockedIp.ipAddress, blockedIp.reason );
			}

		// catch any errors (e.g. bad URL, network issues, etc.)
		} catch( any e ) {
			// and fail gracefully (you may wish to log here as well)
		}

	}

	/* IP WATCHING 

		This section of the security service provides functions to
		help manage watching of potential hackers/bots by IP address.

		Functions include:
			checking if an IP is on the watched IP list
			adding and removing IP's from the watched IP list
			increasing the total times an ip has been flagged for potential abuse
			reading and writing the watched IP list to disk
			importing watched ip lists from other hosts via http
	
	*/

	/**
	* @displayname	getWatchedIp
	* @description	I parse the watched ip array and determine if the passed ip is being watched
	* @param		ipAddress {String} required - I am the ip address to check
	* @return 		struct
	*/
	public struct function getWatchedIp( required string ipAddress ) {

		// get watched IP's from the cache
		var watchedIpArr = cacheGet( uberHash( 'watchedIpArr', 'MD5', 57 ) );
		var watchedIp = '';
		var returnStruct = structNew();

		// set defaults for watched return struct
		returnStruct.isWatched = false;
		returnStruct.totalCount = 0;

		// check if the cached version of the watched IP array exists
		if( isNull( watchedIpArr ) ) {
			// it doesn't, read in the watched ip file
			watchedIpArr = readWatchedIpFileFromDisk();
			// and save the watched ip array to the cache
			cachePut( uberHash( 'watchedIpArr', 'MD5', 57 ), watchedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );
		}

		// loop through the watched ip array
		for( watchedIp in watchedIpArr ) {
			// and check if this ip address exists in the array
			if( watchedIp.ipAddress eq arguments.ipAddress ) {
				// it does, so it is watched, set return struct details
				returnStruct.isWatched = true;
				returnStruct.totalCount = watchedIp.totalCount;
			}
		}

		// and return the return struct
		return returnStruct;
	}

	/**
	* @displayname	addWatchedIp
	* @description	I add an ip address to the watched ip array
	* @param		ipAddress {String} required - I am the ip address to add
	* @param		reason {String} - I am the reason why this IP is being watched
	* @return		void
	*/
	public void function addWatchedIp( required string ipAddress, string reason = '' ) {

		// get watched IP's from the cache
		var watchedIpArr = cacheGet( uberHash( 'watchedIpArr', 'MD5', 57 ) );
		var watchedIp = '';
		var ipRecord = structNew();
		var found = false;

		// check if the cached version of the watched IP array exists
		if( isNull( watchedIPs ) ) {
			// it doesn't, read in the watched ip file
			watchedIpArr = readWatchedIpFileFromDisk();
		}

		// loop through the watched ip array
		for( watchedIp in watchedIpArr ) {
			// check if this ip address exists in the watched ip list
			if( watchedIp.ipAddress eq arguments.ipAddress ) {
				// it does, set found to true
				found = true;
			}
		}

		// check if the ip address was already found in the array
		if( !found ) {

			// it wasn't found, create a json friendly struct
			ipRecord[ 'ipAddress' ] = arguments.ipAddress;
			ipRecord[ 'timestamp' ] = now();
			ipRecord[ 'reason' ] = arguments.reason;
			ipRecord[ 'totalCount' ] = 1;

			// and add it to the array
			watchedIpArr.append( ipRecord );

			// log hack attempt
			writeLog( text = 'ip: ' & arguments.ipAddress & ' reason: ' & arguments.reason & ' timestamp: ' & now() & ' count: 1', type = 'warning', file = 'abuse' );

			// remove the existing cached watched ip array
			cacheRemove( uberHash( 'watchedIpArr', 'MD5', 57 ) );

			// and save the watched ip array to the cache
			cachePut( uberHash( 'watchedIpArr', 'MD5', 57 ), watchedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );

			// save the watched ip's as a json file
			saveWatchedIpFileToDisk( watchedIpArr );

		}

	}

	/**
	* @displayname	increaseWatchedIpCount
	* @description	I increase the total times an ip has been flagged for potential abuse
	* @param		ipAddress {String} required - I am the ip address to add
	* @param		reason {String} - I am the reason why this IP is being watched
	* @return		void
	*/
	public void function increaseWatchedIpCount( required string ipAddress, string reason = '' ) {
		
		// get watched IP's from the cache
		var watchedIpArr = cacheGet( uberHash( 'watchedIpArr', 'MD5', 57 ) );
		var watchedIp = '';
		var count = 0;

		// check if the cached version of the watched IP array exists
		if( isNull( watchedIPs ) ) {
			// it doesn't, read in the watched ip file
			watchedIpArr = readWatchedIpFileFromDisk();
		}

		// loop through the watched ip array
		for( watchedIp in watchedIpArr ) {
			// check if this ip address exists in the watched ip list
			if( watchedIp.ipAddress eq arguments.ipAddress ) {
				// it does, increase the counter of this record
				watchedIp.totalCount++;
				count = watchedIp.totalCount;
			}
		}

		// log hack attempt
		writeLog( text = 'ip: ' & arguments.ipAddress & ' reason: ' & arguments.reason & ' timestamp: ' & now() & ' count: ' & count, type = 'warning', file = 'abuse' );

		// remove the existing cached watched ip array
		cacheRemove( uberHash( 'watchedIpArr', 'MD5', 57 ) );

		// and save the watched ip array to the cache
		cachePut( uberHash( 'watchedIpArr', 'MD5', 57 ), watchedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );

		// save the watched ip's as a json file
		saveWatchedIpFileToDisk( watchedIpArr );
			
	}

	/**
	* @displayname	removeWatchedIp
	* @description	I remove an ip address from the watched ip array
	* @param		ipAddress {String} required - I am the ip address to remove
	* @return		void
	*/
	public void function removeWatchedIp( required string ipAddress ) {

		// get watched IP's from the cache
		var watchedIpArr = cacheGet( uberHash( 'watchedIpArr', 'MD5', 57 ) );
		var watchedIp = '';
		var ix = 0;
		var found = false;

		// check if the cached version of the watched IP array exists
		if( isNull( watchedIPs ) ) {
			// it doesn't, read in the watched ip file
			watchedIpArr = readWatchedIpFileFromDisk();
		}

		// loop through the watched ip array
		for( watchedIp in watchedIpArr ) {
			// increase the array index
			ix++;
			// check if this ip address exists in the watched ip list
			if( watchedIp.ipAddress eq arguments.ipAddress ) {
				// it does, remove the element from the array
				watchedIpArr.deleteAt( ix );
				// and set found to true
				found = true;
			}
		}

		// check if the ip address was found
		if( found ) {

			// remove the existing cached watched ip array
			cacheRemove( uberHash( 'watchedIpArr', 'MD5', 57 ) );

			// and save the watched ip array to the cache
			cachePut( uberHash( 'watchedIpArr', 'MD5', 57 ), watchedIpArr, createTimeSpan( 30, 0, 0, 0 ), createTimeSpan( 15, 0, 0, 0 ) );

			// save the watched ip's as a json file
			saveWatchedIpFileToDisk( watchedIpArr );

		}
	}

	/**
	* @displayname	saveWatchedIpFileToDiskToDisk
	* @description	I convert the watched ip array into json and save it to disk
	* @param		watchedIpArr {Array} required - I am the watched ip array to save
	* @return		void
	*/
	public void function saveWatchedIpFileToDisk( required array watchedIpArr ) {

		// convert the array to json
		var watchedIpJson = serializeJSON( arguments.watchedIpArr );
		// check if the watched ip file exists
		if( fileExists( expandPath( application.blockedIpDir ) & 'watched_ips.json' ) ) {
			// it does, delete the existing file
			fileDelete( expandPath( application.blockedIpDir ) & 'watched_ips.json' );
		}
		// write the JSON to disk
		fileWrite( expandPath( application.blockedIpDir ) & 'watched_ips.json', watchedIpJson, 'UTF-8' );

	}

	/**
	* @displayname	readWatchedIpFileFromDisk
	* @description	I read the watched ip json from disk and convert it into an array
	* @return		array
	*/
	public array function readWatchedIpFileFromDisk() {

		var watchedIpJson = '';

		// check if the watched ip file exists
		if( fileExists( expandPath( application.blockedIpDir ) & 'watched_ips.json' ) ) {
			// it does, read in the JSON
			watchedIpJson = fileRead( expandPath( application.blockedIpDir ) & 'watched_ips.json', 'UTF-8' );
			// and return an array of the JSON data
			return deserializeJSON( watchedIpJson );
		}

		// file does not exist, return an empty array
		return arrayNew(1);

	}

	/**
	* @displayname	importWatchedIpFileFromUrl
	* @description	I make an http call to a remote watched_ips.json file and add them to our local watched ip file
	* @param		importUrl {String} required - I am the FQDN URL to the watched_ips.json file on the remote server (ex: https://domain.com/blocked/watched_ips.json)
	* @return		void
	*/
	public void function importWatchedIpFileFromUrl( required string importUrl ) {

		var httpService = new http(); 
		var watchedIpArr = '';
		var watchedIp = '';

		// try to perform the import
		try {

			// set up the http attributes
			httpService.setMethod( 'GET' ); 
			httpService.setCharset( 'UTF-8' ); 
			httpService.setUrl( arguments.importUrl );

			// convert the returned JSON into an array
			watchedIpArr = deserializeJSON( httpService.send().getPrefix().fileContent );

			// loop through the array
			for( watchedIp in watchedIpArr ) {
				// and add each ip from the remote JSON file to our local array
				addWatchedIp( watchedIp.ipAddress, watchedIp.reason );
			}

		// catch any errors (e.g. bad URL, network issues, etc.)
		} catch( any e ) {
			// and fail gracefully (you may wish to log here as well)
		}

	}

	/* SQL INJECTION 

		This section of the security service provides functions to
		help detect SQL injection attempts and throw errors if found.

		Functions include:
			checking if a query string contains SQL injection attempts

		Notes: 
			This code is by no means exhaustive and may trigger false
			positives if you are not obfuscating and encrypting your
			URL parameters and values

			Errors are caught by the home.main.error function and
			will cause the offending IP address to be added to the
			blocked IP list. 
	
	*/

	/**
	* @displayname	checkSqlInjectionAttempt
	* @description	I check a passed in query string to ensure it does not contain SQL injection attempts
	* @param		queryString {String} required - I am the query string to parse for SQL injection attempts
	* @return		void
	*/
	public void function checkSqlInjectionAttempt( required string queryString ) {

		var msg = '';

		// decode the query string
		arguments.queryString = urlDecode( arguments.queryString );

		// encode the query string for JSON storage
		msg = encodeForJavaScript( arguments.queryString );

		// check for passing of hex string (0xHEXNUMBER) in query string
		if( reFindNoCase( '0[X][0-9A-F]+', arguments.queryString ) ) {
			// hex string found, throw an error to be caught
			throw( type = 'SQLInjection.Hex', message = '#msg# contains hexadecimal characters');
		}

		// check for passing of chr([]), char([]) or concat([]) in query string
		if( listFindNoCase( 'chr(,char(,concat(', arguments.queryString ) ) {
			// value found, throw an error to be caught
			throw( type = 'SQLInjection.Char', message = '#msg# contains SQL string attack characters');
		}

		// check for passing semi-colon followed by any common SQL command in query string
		if( reFindNoCase( ';.*(select|insert|update|delete|drop|alter|create)', arguments.queryString ) ) {
			// found semi-colon followed by a common SQL command, throw an error to be caught
			throw( type = 'SQLInjection.Command', message = '#msg# contains SQL commands');
		}

		// check for passing of comments in query string
		if( findNoCase( '/*', arguments.queryString ) or findNoCase( '*/', arguments.queryString ) ) {
			// found a comment throw an error to be caught
			throw( type = 'SQLInjection.Comment', message = '#msg# contains comment characters');
		}

		// check for ' and' in query string
		if( findNoCase( ' and', arguments.queryString ) ) {
			// found ' and', throw an error to be caught
			throw( type = 'SQLInjection.And', message = '#msg# contains [ and]');
		}

		// check for ' or' in query string
		if( findNoCase( ' or', arguments.queryString ) ) {
			// found ' or', throw an error to be caught
			throw( type = 'SQLInjection.Or', message = '#msg# contains [ or]');
		}

		// check for ' union' in query string
		if( findNoCase( ' union', arguments.queryString ) ) {
			// found ' union', throw an error to be caught
			throw( type = 'SQLInjection.Union', message = '#msg# contains [ union]');
		}

		// check for apostrophe in query string
		if( findNoCase( "'", arguments.queryString ) ) {
			// found apostrophe, throw an error to be caught
			throw( type = 'SQLInjection.Apostrophe', message = '#msg# contains apostrophe character');
		}

	}

	/**
	* @displayname	generateDummyCookieValue
	* @description	I generate a random value for dummy cookies
	* @param		encoding {String} default: BASE64 - I am the encoding to use for the encryption
	* @return		string
	*/
	public string function generateDummyCookieValue( string encoding = 'BASE64' ) {

		// return a random encrypted value to use for dummy cookies
		return urlEncodedFormat( encrypt( lcase( hash( createUUID() & now(), 'SHA-512', 'UTF-8', 1000 ) ), generateSecretKey('AES'), 'AES/CTR/PKCS5Padding', arguments.encoding ) );
	}

	/**
	* @displayname getEnvironment
	* @description I return the environment within which this code is executing
	*/	
	public function getEnvironment( boolean clearCache = false ) {

		// get the environment from cache
		var environment = cacheGet( 'deployed_environment_cache' );

		// check if the cached value is empty or if we're purposefully clearing the cache
		if( isNull( environment ) or arguments.clearCache ) {

			// we are, switch on hostname of the server (e.g. www, sa, tfa, etc.)
			switch( listFirst( CGI.SERVER_NAME, '.' ) ) {

				// check if the hostname contains 'sa' or 'tfa' (our demo sites) or 'www'
				// use any other method of determining if this is the production server 
				// you need (e.g. checking the IP address of the server, for example )
				case 'sa': 
				case 'tfa':
				case 'www':
					// it does, this is a production server, set the environment to 'prod'
					environment = 'prod';
				break;
				
				// otherwise, check if the hostname contains 'test'
				// you can put any other environments using any other methods
				// you need in this if/else block
				case 'test':
					// it does, this is a test server, set the environment to 'test'
					environment = 'test';
				break;
			
				// otherwise
				default:
					// assume this is a development server, set the environment to 'dev'
					environment = 'dev';
				break;
			}

			// check if we're clearing the cache 
			if( arguments.clearCache ) {
				// we are, remove the old cached value
				cacheRemove( 'deployed_environment_cache' );
			}

			// put the new cached environment value into the cache
			cachePut( 'deployed_environment_cache', environment, createTimeSpan( 1, 0, 0, 0 ), createTimeSpan( 0, 12, 0, 0 ) );

		}

		// return the environment value
		return environment;
		
	}

	/**
	* @displayname getPasswordArray
	* @description I return an array of the top 100,000 hacked passwords (cached from a file)
	* @return	   array
	*/	
	public array function getPasswordArray() {

		// get the hacked password array from cache
		var pwdArr = cacheGet( 'top_100000_hacked_passwd' );
		// set the default delimiter for the file to LF only
		var delim = chr(10);
		var pwdFile = '';

		// check if the hacked password array is null (doesn't exist in cache)
		if( isNull( pwdArr ) ) {
			// it is, read in the password file
			pwdFile = fileRead( application.passwordFilePath );
			// check if the lines are terminated with a CR-LF
			if( findNoCase( chr(13) & chr(10), pwdFile ) ) {
				// they are, change the delimiter to CR-LF
				delim = chr(13) & chr(10);
			// otherwise, check if the lines are terminated with a LF only
			} else if( findNoCase( chr(13), pwdFile ) ) {
				// they are, change the delimited to CR only
				delim = chr(13);
			}
			// convert the file to an array of passwords
			pwdArr = listToArray( pwdFile, delim );
			// store the array in the cache for TTL 90 days and ITL 45 days
			cachePut( 'top_100000_hacked_passwd', pwdArr, createTimeSpan( 90, 0, 0, 0 ), createTimeSpan( 45, 0, 0, 0 ) );
		}

		// return the password array
		return pwdArr;

	}

	/**
	* @displayname isPasswordHacked
	* @description I return true if the passed in password is found in the hacked password array, false otherwise
	*/
	public boolean function isPasswordHacked( required string password ) {
		// get the password array
		var pwdArr = getPasswordArray();
		// check if the passed in password is found in the array
		if( pwdArr.find( arguments.password ) ) {
			// it is, return true
			return true;
		}
		// it wasn't found, return false;
		return false;
	}


	/**
	* @displayname	generateInitializationVector
	* @description	I generate an initialization vector (IV) from random integers
	* @param		encoding {String} required - I am the encoding to use for the initialization vector
	* @return		string
	*/
	public string function generateInitializationVector( required string encoding, string algorithm = 'AES', numeric keyLength = 128 ) {
		
		// set the default number of bits for the IV (16 for AES)
		var bitLength = 16;
		// set up a var to store our integer array
		var integerArr = [];
		// set up a var to hold our IV byte
		var iv = '';

		// check if we're using the BLOWFISH algorithm
		if( findNoCase( 'BLOWFISH', arguments.algorithm ) ) {
			// we are, set the number of bits for the IV to 8
			bitLength = 8;
		}

		// check if the key length is 256
		if( arguments.keyLength eq 256 ) {
			// it is, double the bitLength
			bitLength += bitLength;
		}

		// loop from 1 to the bit length
		for( var ix = 1; ix <= bitLength; ix++ ) {
			// append a random integer to our array
			integerArr.append( randRange( -128, 127, 'SHA1PRNG' ) );
		}

		// cast the integer array to a Java byte
		iv = javaCast( "byte[]", integerArr );

		// return the iv byte encoded with the requested encoding
		return binaryEncode( iv, arguments.encoding );

	}

}