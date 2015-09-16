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
	public void function register( rc ) {}

    /**
    * @displayname process
    * @description I process registration requests and display the process view
    */ 
	public void function process( rc ) {

		var qGetUser = '';
		var fieldList = 'username,password,confirm,firstName,lastName';
		var ix = 0;

		// loop through fields
		for( ix = 1; ix <= listLen( fieldList ); ix++ ) {
			// ensure the username, password, confirm, firstName and lastName have been passed in
			if( !structKeyExists( rc, listGetAt( fieldList, ix ) ) OR !len( rc[ listGetAt( fieldList, ix ) ] ) ) {
				// missing something, redirect to registration page
				variables.fw.redirect( action = 'main.register', queryString = "msg=#urlEncodedFormat( 'You must provide a valid value for all fields to register.' )#" );
			}
		}

		// check if the password and confirmation are the same 
		if( compareNoCase( rc.password, rc.confirm ) NEQ 0 ) {
				// password mismatch, redirect to registration page
				variables.fw.redirect( action = 'main.register', queryString = "msg=#urlEncodedFormat( 'Your password and confirmation password do not match. Please try again.' )#" );			
		}

		// get the user from the database by encrypted username passed in
		qGetUser = userService.filter( username = application.securityService.dataEnc( rc.username, 'repeatable' ) );

		// check if there is a record for the passed username
		if( qGetUser.recordCount ) {
			// user exists, redirect to register page
			variables.fw.redirect( action = 'main.register', queryString = "msg=#urlEncodedFormat( 'A user account already exists for this email address. Please log in.' )#" );			
		}

		// get a user object to populate
		rc.userObj = userService.getUserById( 0 );

		// populate the user object encrypting and hashing as needed
		rc.userObj.setUsername( application.securityService.dataEnc( rc.username, 'repeatable' ) );
		rc.userObj.setPassword( application.securityService.dataEnc( hash( rc.password, 'SHA-384' ), 'db' ) );
		rc.userObj.setFirstName( application.securityService.dataEnc( encodeForHTML( rc.firstName ), 'db' ) );
		rc.userObj.setLastName( application.securityService.dataEnc( encodeForHTML( rc.lastName ), 'db' ) );
		rc.userObj.setRole( 0 );
		rc.userObj.setIsActive( 1 );

		// save the user object
		userService.saveUser( rc.userObj );

	}

    /**
    * @displayname reset
    * @description I present the reset view
    */ 
	public void function reset( rc ) {}

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
			variables.fw.redirect( action = 'main.reset', queryString = "msg=#urlEncodedFormat( '403: A user account could not be located for this email address. Please register for an account.' )#" );			
		}

		// get a user object to modify
		rc.userObj = userService.getUserById( qGetUser.userId );

		rc.userObj.setPassword( application.securityService.dataEnc( hash( randomPass, 'SHA-384' ), 'db' ) );

		// save the user object
		userService.saveUser( rc.userObj );

		// email the customer their new password
		//mailService.sendPasswordResetEmail( rc.userObj, randomPass );

		// user does not exist, redirect to reset page
		variables.fw.redirect( action = 'main.reset', queryString = "msg=#urlEncodedFormat( '200: An email has been sent with your new password. Please check your email and login with the new password provided.' )#" );	

	}
	
}
