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
	property encryptionKey2;
	property encryptionAlgorithm2;
	property encryptionEncoding2;
	property encryptionKey3;
	property encryptionAlgorithm3;
	property encryptionEncoding3;
	property hmacKey;
	property hmacAlgorithm;
	property hmacEncoding;

	/**
	* @displayname init
	* @description I am the constructor method for SecurityService
	* @param 	{String} encryptionKey1 I am the encryption key used for pass number 1
	* @param 	{String} encryptionAlgorithm1 I am the encryption algorithm used for pass number 1
	* @param 	{String} encryptionEncoding1 I am the encryption encoding used for pass number 1
	* @param 	{String} encryptionKey2 I am the encryption key used for pass number 2
	* @param 	{String} encryptionAlgorithm2 I am the encryption algorithm used for pass number 2
	* @param 	{String} encryptionEncoding2 I am the encryption encoding used for pass number 2
	* @param 	{String} encryptionKey3 I am the encryption key used for pass number 3
	* @param 	{String} encryptionAlgorithm3 I am the encryption algorithm used for pass number 3
	* @param 	{String} encryptionEncoding3 I am the encryption encoding used for pass number 3
	* @param 	{String} hmacKey I am the key used for hmac hashing
	* @param 	{String} hmacAlgorithm I am the hashing algorithm used for hmac hashing
	* @param 	{String} hmacEncoding I am the encoding used for hmac hashing
	* @param 	{Boolean} generateHmacKey I am a flag to indicate if the service should generate an hmac key from an xor of the existing encryption keys (true), or use the provided hmacKey (false)
	* @return 	this
	*/	
	public function init( 
		string encryptionKey1 = '',
		string encryptionAlgorithm1 = '',
		string encryptionEncoding1 = '',
		string encryptionKey2 = '',
		string encryptionAlgorithm2 = '',
		string encryptionEncoding2 = '',
		string encryptionKey3 = '',
		string encryptionAlgorithm3 = '',
		string encryptionEncoding3 = '',
		string hmacKey = '',
		string hmacAlgorithm = '',
		string hmacEncoding = ''
		) {

		variables.encryptionKey1 = arguments.encryptionKey1;
		variables.encryptionAlgorithm1 = arguments.encryptionAlgorithm1;
		variables.encryptionEncoding1 = arguments.encryptionEncoding1;
		variables.encryptionKey2 = arguments.encryptionKey2;
		variables.encryptionAlgorithm2 = arguments.encryptionAlgorithm2;
		variables.encryptionEncoding2 = arguments.encryptionEncoding2;
		variables.encryptionKey3 = arguments.encryptionKey3;
		variables.encryptionAlgorithm3 = arguments.encryptionAlgorithm3;
		variables.encryptionEncoding3 = arguments.encryptionEncoding3;
		variables.hmacKey = arguments.hmacKey;
		variables.hmacAlgorithm = arguments.hmacAlgorithm;
		variables.hmacEncoding = arguments.hmacEncoding;

		return this;
	}


	// DATA ENCRYPTION //

	/**
	* @displayname dataEnc
	* @description I encrypt passed in values based on scope
	* @return      String
	*/
	public string function dataEnc( required string value, string mode = 'db' ) {
		
		var onePass = '';
		var twoPass = '';
		var lastPass = '';
		
		// check if the passed value has length //
		if( len( arguments.value ) ) {
		
			// it does, check if the mode of the encryption is 'db' //
			if( findNoCase( 'db', arguments.mode ) ) {
			
				// using database encryption, encrypt with the first set of keys and algorithm //
				onepass = encrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1 );
				// and again with the second set of keys and algorithm //
				twopass = encrypt( onepass, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2 );
				// and again with the third set of keys and algorithm //
				lastPass = encrypt( twopass, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3 );
				
			// otherwise, check if the mode of the encryption is 'repeatable' //
			} else if( findNoCase( 'repeatable', arguments.mode ) ) {
				
				// using database encryption, encrypt with the first set of keys and algorithm //
				onepass = encrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1 );
				// and again with the second set of keys and algorithm //
				twopass = encrypt( onepass, variables.encryptionKey2,  listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2 );
				// and again with the third set of keys and algorithm //
				lastPass = encrypt( twopass, variables.encryptionKey3,  listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3);
			
			// otherwise, check if the mode of the encryption is 'url' //
			} else if( findNoCase( 'url', arguments.mode ) ) {
				
				// using url encryption, check if useing BASE64 encoding on the URL key //
				if( findNoCase( 'BASE64', variables.encryptionEncoding1 ) ) {
				
					// encrypt with the first set of keys and repeatable algorithm //
					lastPass = encrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1);
					// using BASE64 encoding, URL encode the value //
					lastPass = URLEncodedFormat( lastPass );
				
				// otherwise //
				} else {
				
					// not BASE64 encoded, encrypt with the first set of keys and algorithm //
					lastPass = encrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1 );
				
				// end checking if useing BASE64 encoding on the URL key //	
				}	
				
			// otherwise, check if the mode of the encryption is 'form' //
			} else if( findNoCase( 'form', arguments.mode ) ) {
			
				// using form encryption, encrypt with the second set of keys and algorithm //
				lastPass = encrypt( arguments.value, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2 );
				
			// otherwise, check if the mode of the encryption is 'cookie' //
			} else if( findNoCase( 'cookie', arguments.mode ) ) {
			
				// using cookie encryption, encrypt with the first set of keys and algorithm //
				lastPass = encrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3 );
			
			// end checking if the mode of the encryption is 'db', 'url', 'form' or 'cookie' //	
			}
		
		// end checking if the passed value has length //
		}
		
		// return the encrypted value (or null if passed value has no length) //
		return lastPass;
	}

	// DATA DECRYPTION //

	/**
	* @displayname dataDec
	* @description I decrypt passed in values based on scope
	* @return      String
	*/
	public string function dataDec( required string value, string mode = 'db' ) {

		// var scope //
		var onePass = '';
		var twoPass = '';
		var lastPass = '';
		
		// check if the passed value has length //
		if( len( arguments.value ) ) {
		
			// it does, check if the mode of the encryption is 'db' //
			if( findNoCase( 'db', arguments.mode ) ) {
	
				// using database encryption, decrypt with the third set of keys and algorithm //
				var onePass = Decrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3 );
				// and again with the second set of keys and algorithm //
				var twoPass = Decrypt( onepass, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2 );
				// and again with the first set of keys and algorithm //
				var lastPass = Decrypt( twopass, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1 );
		
			// otherwise, check if the mode of the encryption is 'repeatable' //
			} else if( findNoCase( 'repeatable', arguments.mode ) ) {
	
				// using database encryption, decrypt with the third set of keys and algorithm //
				var onePass = Decrypt( arguments.value, variables.encryptionKey3, listFirst( variables.encryptionAlgorithm3, '/' ), variables.encryptionEncoding3 );
				// and again with the second set of keys and algorithm //
				var twoPass = Decrypt( onepass, variables.encryptionKey2, listFirst( variables.encryptionAlgorithm2, '/' ), variables.encryptionEncoding2 );
				// and again with the first set of keys and algorithm //
				var lastPass = Decrypt( twopass, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1 );
			
			// otherwise, check if the mode of the encryption is 'url' //
			} else if( findNoCase( 'url', arguments.mode ) ) {
				
				// using url encryption, check if useing BASE64 encoding on the URL key //
				if( findNoCase( 'BASE64', variables.encryptionEncoding1 ) ) {
				
					// using BASE64 encoding, URL decode the value //
					arguments.value = URLDecode( arguments.value );
					// replace spaces with + //
					arguments.value = Replace( arguments.value, chr(32), '+', 'ALL' );
					// decrypt with the first set of keys and repeatable algorithm //
					lastPass = Decrypt( arguments.value, variables.encryptionKey1, listFirst( variables.encryptionAlgorithm1, '/' ), variables.encryptionEncoding1 );
				
				// otherwise //
				} else {
				
					// not BASE64 encoded, decrypt with the first set of keys and algorithm //
					lastPass = Decrypt( arguments.value, variables.encryptionKey1, variables.encryptionAlgorithm1, variables.encryptionEncoding1 );
				
				// end checking if useing BASE64 encoding on the URL key //	
				}			
				
			// otherwise, check if the mode of the encryption is 'form' //
			} else if( findNoCase( 'form', arguments.mode ) ) {
			
				// using form encryption, decrypt with the second set of keys and algorithm //
				lastPass = Decrypt( arguments.value, variables.encryptionKey2, variables.encryptionAlgorithm2, variables.encryptionEncoding2 );
				
			// otherwise, check if the mode of the encryption is 'cookie' //
			} else if( findNoCase( 'cookie', arguments.mode ) ) {
			
				// using cookie encryption, decrypt with the first set of keys and algorithm //
				lastPass = Decrypt( arguments.value, variables.encryptionKey3, variables.encryptionAlgorithm3, variables.encryptionEncoding3 );
			
			// end checking if the mode of the encryption is 'db', 'url', 'form' or 'cookie' //	
			}
		
		// end checking if the passed value has length //
		}

		// return the decrypted value (or null if passed value has no length) //
		return lastPass;

	}

	/**
	* @displayname dataHmac
	* @description I hash and return passed in values based on HMAC
	* @return      String
	*/
	public string function dataHmac( required string input ) {

		return hmac( arguments.input, variables.hmacKey, variables.hmacAlgorithm, variables.hmacEncoding );

	}

	/**
	* @displayname uberHash
	* @description I hash and return passed in values based on method and iterations (ACF support)
	* @return      String
	*/
	public string function uberHash( required string input, string method = 'SHA-384', numeric iterations = 1000, string outcase = 'lower' ) {

		var output = hash( arguments.input, arguments.method, 'UTF-8', arguments.iterations );

		// check if we're returning lowercase
		if( findNoCase( 'lower', arguments.outcase ) ) {
			output = lCase( output );
		}

		// return the input hashed iterations 
		return output;

	}


	/**
	* @displayname getRandomPassword
	* @description I generate a random password of random length
	* @return      String
	*/
	public string function getRandomPassword() {

		var alpha = 'a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z';
		var upperAlpha = uCase( alpha );
		var numbers = '1,2,3,4,5,6,7,8,9,0';
		var special = '!,@,##,$,%,^,&,*';
		var length = randRange( 10, 16 );
		var password = '';
		var ix = 0;
		var pattern = '';
		var char = '';

		for( ix = 1; ix <= length; ix++ ) {
			pattern = randRange( 1, 4 );
			if( pattern EQ 1 ) {
				char = listGetAt( alpha, randRange( 1, listLen( alpha ) ) );
			} else if( pattern EQ 2 ) {
				char = listGetAt( upperAlpha, randRange( 1, listLen( upperAlpha ) ) );
			} else if( pattern EQ 3 ) {				
				char = listGetAt( numbers, randRange( 1, listLen( numbers ) ) );
			} else {
				char = listGetAt( special, randRange( 1, listLen( special ) ) );
			}
			password = password & char;
		}

		return password;

	}

	/**
	* @displayname checkUserSession
	* @description I retrieve the users session object from cache, and return it if it exists, else I return a blank session object
	* @return      Session
	*/
	public any function checkUserSession( required string sessionId ) {

		// get the session object from the cache
		var sessionObj = cacheGet( uberHash( arguments.sessionId, 'MD5', 3000 ) );

		// ensure it is still in the cache
		if( isNull( sessionObj ) ) {

			// it isn't, return an empty session object
			return createObject( 'component', 'model.beans.Session').init();

		// otherwise, ensure the session shouldn't have already expired (30 mins)
		} else if( dateDiff('n', sessionObj.getLastActionAt(), now() ) GTE application.timeoutMinutes ) {

			// it should have expired, return an empty session object
			return createObject( 'component', 'model.beans.Session').init();

		// otherwise, ensure that the hmac code matches for this session
		} else if( len( sessionObj.getHmacCode() ) and dataHmac( arguments.sessionId ) neq sessionObj.getHmacCode() ) {

			// it doesn't match, return an empty session object
			return createObject( 'component', 'model.beans.Session').init();

		// otherwise
		} else {

			// session is valid, return the session object
			return sessionObj;

		}

	}

	/**
	* @displayname createUserSession
	* @description I generate and resturn a session object based on passed in values
	* @return      Session
	*/
	public any function createUserSession( required numeric userId, required numeric role, required string firstName, required string lastName ) {

		var sessionObj = createObject( 'component', 'model.beans.Session').init(
			sessionId = getSessionId(),
			userId = arguments.userId,
			role = arguments.role,
			firstName = arguments.firstName,
			lastName = arguments.lastName,
			mfaCode = getMfaCode(),
			isAuthenticated = false,
			lastActionAt = now()
		);

		setUserSession( sessionObj );

		return sessionObj;

	}

	/**
	* @displayname setUserSession
	* @description I store a sessio0n object in the cache
	* @return      Void
	*/
	public void function setUserSession( required any sessionObj ) {

		cachePut( uberHash( arguments.sessionObj.getSessionId(), 'MD5', 3000 ), arguments.sessionObj, createTimeSpan( 0, 0, application.timeoutMinutes, 0), createTimeSpan( 0, 0, application.timeoutMinutes, 0 ) );

	}

	/**
	* @displayname clearUserSession
	* @description I remove a sessio0n object from the cache
	* @return      Void
	*/
	public void function clearUserSession( required any sessionObj ) {

		cacheRemove( uberHash( arguments.sessionObj.getSessionId(), 'MD5', 3000 ) );

	}

	/**
	* @displayname rotateUserSession
	* @description I update the session id of a session object 
	* @return      Session
	*/
	public any function rotateUserSession( required any sessionObj ) {

		arguments.sessionObj.setSessionId( getSessionId() );

		return arguments.sessionObj;

	}

    /**
    * @displayname updateUserSession
    * @description I update the last action at of a session object, remove the old session and save the new one 
    * @return      Session
    */
	public any function updateUserSession( required any sessionObj ) {

		clearUserSession( arguments.sessionObj );
		arguments.sessionObj.setLastActionAt( now() );
		arguments.sessionObj.setHmacCode( dataHmac( arguments.sessionObj.getSessionId() ) );
		setUserSession( arguments.sessionObj );

		return arguments.sessionObj;

	}

	/**
	* @displayname getSessionId
	* @description I generate a random hashed session id
	* @return      String
	*/
	public string function getSessionId() {

		var sessionId = uberHash( createUUID() & now(), 'SHA-384', 2000 );

		return sessionId;

	}

	/**
	* @displayname setSessionIdForCookie
	* @description I encrypt the session id of a session object for cookie storage
	* @return      String
	*/
	public string function setSessionIdForCookie( required string sessionId ) {

		var cookieId = dataEnc( arguments.sessionId, 'cookie' );

		return cookieId;

	}

	/**
	* @displayname getSessionIdFromCookie
	* @description I decrypt the session id of a session object from cookie storage
	* @return      String
	*/
	public string function getSessionIdFromCookie( required string cookieId ) {

		var sessionId = dataDec( arguments.cookieId, 'cookie' );

		return sessionId;

	}

	/**
	* @displayname getHeartbeat
	* @description I generate a random hash of random length for use in authentication (to prevent password disclosure)
	* @return      String
	*/
	public string function getHeartbeat() {

		var heartbeat = lCase( left( uberHash( now() & createUUID() & randRange( 1000, 9999 ), 'SHA-384', randRange( 1000, 3000 ) ), randRange( 32, 64 ) ) );

		return heartbeat;

	}

	/**
	* @displayname getMfaCode
	* @description I generate a random hashed two-factor authentication code of a random length
	* @return      String
	*/
	public string function getMfaCode() {

		var mfaCode = left( uberHash( createUUID() & now(), 'MD5', RandRange(1000,3000) ), randRange( 4, 8 ) );

		return mfaCode;

	}

}
