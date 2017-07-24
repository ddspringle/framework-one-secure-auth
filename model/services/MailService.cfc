/**
*
* @file  model/services/MailService.cfc
* @author Denard Springle ( denard.springle@gmail.com )  
* @description I am the email service used to send the mfa code to the user
*
*/

component displayname="mailService" accessors="true"  {

	public function init(){

		variables.mailService = new mail();

		return this;
	}

	public void function sendMfaCode( required numeric phone, required string providerEmail, required string mfaCode ) {

		// clear the mail service of any previously used data
		variables.mailService.clear();

		variables.mailService.setFrom( 'twofactorauth@vsgcom.net' );
		variables.mailService.setTo( arguments.phone & arguments.providerEmail );
		variables.mailService.setSubject( 'Auth Code' );
		variables.mailService.setType( 'text' );
		variables.mailService.setBody( arguments.mfaCode );

		variables.mailService.send();

	}

}