# FW/1 Secure Authentication Example

This project is an example [fw/1](https://github.com/framework-one/fw1) application with secure single and two-factor (2FA) authentication and session management functions. This code was originally put together for the `ColdFusion: Code Security Best Practices` presentation by Denard Springle at [NCDevCon 2015](http://www.ncdevcon.com) and has since been transformed into a concise starting point for developers who need to create a secure application using the [fw/1](https://github.com/framework-one/fw1) CFML MVC framework.

This code has been expanded multiple times to include additional functionality not shown during the initial presentation. More details on how (and why) these security functions work and are important can be gleaned from reading the ColdFusion Code Security guides on the bottom half of [CFDocs](http://cfdocs.org/security) and from reviewing the SecurityService.cfc in /model/services/ which has been expanded with comments to help aid in understanding how and why security features have been implemented and should be easy to pick up and run with for anyone with a passing familiarity of CFML and [fw/1](https://github.com/framework-one/fw1).

## Features and Notes

* Based on basic example [fw/1](https://github.com/framework-one/fw1) application
* Uses subsystems for separation of concerns, securing only the `admin` subsystem
* Includes a SecurityService component that has encryption, decryption, hashing, password generation and session management code
* Includes a security controller for managing session and request scope session management within the `admin` subsystem
* Uses cookies and object cache for session management
* Includes HMAC protection for session cookies to help prevent tampering
* Rotates the session id on each request and utilizes form tokenization to help prevent CSRF
* Federates the login with a cookie and referrer requirement
* Protects the users password from disclosure with SHA-384 hashing during login
* Stores user data in encrypted format in the database
* Default CBC/PKCS5Padding defined for encryption algorithms
* Includes HTTP security headers designed to reduce attack surface
* Uses keyring stored on disk to load encryption keys instead of hard-coded in the `Application.cfc`
* Includes functions for reading, writing and generating a random keyring file
* Includes functions for checking for, adding, removing and importing blocked IP's
* Includes functions for checking for, adding, removing and importing watched IP's 
* Includes functions for managing watched/blocked IPs by catching common parameter tampering/sql injection attacks
* Includes optional `addDate` true/false parameter to uberHash function to append the current date to the input value on hash
* Includes 'dummy' cookies for the purpose of further obfuscating which cookie is used for session management
* Includes repeatable form encryption for ajax populated and javascript selected form fields
* Includes BaseBean with convenience functions for populating primary key data and CSRF fields in urls and forms (respectively)
* Includes page caching and flushing capabilities added for static views (for [NVCFUG Preso](https://www.meetup.com/nvcfug/events/236791823/)) - use url param `flushCache` to flush
* Includes fw1 environment control and check for the `prod` (production) environment before running IP watching or blocking routines
* Includes configurable block mode - one of abort or redirect. Abort simply aborts further processing for blocked IP's. Redirect works as it did before this release, redirecting to the `ipBlocked.html` file.
* Migrated to new `Application.cfc` FW/1 initialization model
* Improved HMAC key management to prevent development reloads from forcing the user to re-login (for non-production environments)
* **BREAKING CHANGE** The two factor (2FA) authentication code from our two-factor example has been rolled into this code as of 7/24/2017. You can turn on 2FA in the `Application.cfc` (off by default to maintain backwards compatibility). Code prior to this release has been moved to the `legacy` branch.
* **BREAKING CHANGE** As of 9/12/2017 the keyring master key now uses a PBKDF key on Lucee 5+ and ACF 11+ engines by default instead of legacy hashing to further enhance the security of the keyring. A new function `rekeyKeyRing()` has been added to the SecurityService to aid in rekeying your keyring for this change (and rekeying it in general) if upgrading from a previous release. You may alternatively uncomment a line in `Application.cfc` to force legacy master key usage. Please see additional notes in the `Application.cfc` for further details. Lucee 4.5 will continue to use the legacy hashing of the master key.
* **BREAKING CHANGE** The keyring path and the master key are now defined in their own variables in the application scope instead of being hard-coded in the initialization of the security service. These are now BASE64 encoded to aid in obfuscating the key and filename in case of code disclosure. If upgrading from a previous release you will need to BASE64 encode your master keyphrase and filename and replace the new default one in `Application.cfc`. Please see additional notes in the `Application.cfc` for further details.
* **BREAKING CHANGE** The dashboard controller has removed the `rc.product` and `rc.version` variables definitions and the dashboard view now uses the engine and engine version information derived from the application scope
* There is now an option to use a hacked password list to prevent the system from generating, or user from choosing, a password from the top 100,000 known passwords. This is turned off (`false`) by default in `Application.cfc` for backwards compatibility. To use this new function you should set `application.rejectHackedPasswords` to `true`.
* **BREAKING CHANGE** The `SecurityService.cfc` has been enhanced with additional functionality to randomly generate (when creating a new keyring) and use initialization vectors with all encryption and decryption. This will break existing code that is using a keyring without an initialization vector (will return an error about the length of the initialization vector).
* NEW! **BREAKING CHANGE** As of 6/26/2024, the `SecurityService.cfc` has been modified for compatibility with JDK17+ as it relates to the master key encryption and decryption block mode being utilized. Prior to these changes the master key encryption and decryption relied on the CTR block mode of encryption (BLOWFISH/CTR/PKCS5Padding). This has been modified to instead utilize CBC block mode (BLOWFISH/CBC/PKCS5Padding) for greater compatibility with JDK17+. This will break existing code that is using a keyring encrypted with the old CTR block mode. It is recommended to decrypt your existing keyring with the CTR block mode and then re-encrypt using the CBC block mode if you are upgrading from a previous version of this repository. The following code will help you accomplish this safely:

```
<cfscript>
	if( !structKeyExists( variables, 'rc' ) ) {
		variables.rc = {};
		structAppend( rc, url );
		structAppend( rc, form, true );
	}

	// set a keyring path
	rc.keyRingPath = expandPath( './keyrings/[ABCDEF0123456789].bin' );
	// set a keyring backup path
	rc.backupPath = rc.keyRingPath & '_BACKUP_' & dateTimeFormat( now(), 'yyyymmddhhnnss' );

	// validate the keyring file exists
	if( !fileExists( rc.keyRingPath ) ) {
		throw( rc.keyRingPath & ': keyring path does not exist!' );
	}

	// backup the existing keyring file
	fileCopy( rc.keyRingPath, rc.backupPath );

	// validate the backup file exists
	if( !fileExists( rc.backupPath ) ) {
		throw( rc.backupPath & ': backup path does not exist!' );
	}

	// load the CTR encrypted keyring from the file
	rc.keyring = charsetEncode( fileReadBinary( rc.keyRingPath ), 'utf-8' );

	// decrypt the keyring with the master key and BLOWFISH/CTR block mode
	rc.roundOne = decrypt( rc.keyring, rc.masterKey, 'BLOWFISH/CTR/PKCS5Padding', 'HEX' );
	rc.roundTwo = decrypt( roundOne, rc.masterKey, 'AES/CBC/PKCS5Padding', 'HEX' );

	// re-encrypt the keyring with the master key and BLOWFISH/CBC block mode
	rc.roundOne = encrypt( rc.roundTwo, rc.masterKey, 'AES/CBC/PKCS5Padding', 'HEX' );
	rc.roundTwo = encrypt( roundOne, variables.masterKey, 'BLOWFISH/CBC/PKCS5Padding', 'HEX' );

	// write the keyring back to disk
	fileWrite( rc.keyRingPath, charsetDecode( rc.roundTwo, 'utf-8' ) );
</cfscript>
```
* NEW! The scrypt JAR has been added to the repository and initialized for use (with 32MB/64MB RAM used for hashing). It has been added to the `uberHash()` method of `SecurityService.cfc` and can be utilized by passing the flag `useScrypt` as `true` (default is `false`). e.g. `application.securityService.uberHash( input = 'mY$7R0nGP@$$w0R6', useScrypt = true )`

* NEW! The scrypt JAR has been added to the repository and initialized for use (with 32MB/64MB RAM used for hashing). It has been added to the `uberHash()` method of `SecurityService.cfc` and can be utilized by passing the flag `useScrypt` as `true` (default is `false`). e.g. `application.securityService.uberHash( input = 'mY$7R0nGP@$$w0R6', useScrypt = true )`
* NEW! The missing link... a new function, `checkScrypt()` has been added to the `SecurityService.cfc` to check for values hased using `useScript=true` with `uberHash()`

## Compatibility

* Lucee 4.5+

* Adobe ColdFusion 2021+

## Installing

1. Drop the code into your favorite CFML engine's webroot OR install using [CommandBox](https://www.ortussolutions.com/products/commandbox) using the command `box install fw1-sa`
2. Create a database and generate the users and smsProviders database tables (MSSQL SQL and Excel data provided in the 'database' folder)
3. Create a datasource called `twofactorauth` for your database in your CFML engine's admin (or change in `Application.cfc`)
4. Configure an object cache, if one is not already defined (or, optionally, add it to `Application.cfc` if running Lucee 5.x+)
5. Configure a mail server in your CFML engine's admin
6. Move the `keyrings` folder to a location outside your webroot
7. Modify the default `developmentHmacKey` value in `Application.cfc` (use `generateSecretKey( 'HMACSHA512' )`)
8. Change the `keyRingPath` location to where you moved the `keyrings` folder to in `Application.cfc`
9. Change the hash iterations for the hashed keyring file name from the default value of `173` to some other integer number of iterations in `Application.cfc`
10. Provide a unique BASE64 encoded value for the application password in `Application.cfc` (instead of `c2VjdXJlX2F1dGhfbWFzdGVyX2tleQ==`)
11. Provide a unique BASE64 encoded value for the application salt in `Application.cfc` (instead of `UnRUcFBBS1hOQmgwem9XYg==`)
12. Provide a unique BASE64 encoded value for the keyring filename in `Application.cfc` (instead of `c2VjdXJlX2F1dGhfa2V5cmluZw==`)
13. Change the hash iterations for the hashed master key from the default value of `512` to some other integer number of iterations in `Application.cfc`
14. Change the starting location for the `mid()` function of the hashed master key to start at a position other than `38` in a range from `1` to `106`
15. Provide unique values for the `cookieName` and `dummyCookieOne`, `dummyCookieTwo` and `dummyCookieThree` values in `Application.cfc`
16. Modify remaining application variables in `Application.cfc` as needed (see notes in `Application.cfc`)
17. Browse to webroot to launch the application and generate a unique set of encryption keys in your keyring
18. Modify the `check if the keyring is a valid array of keys` statement in `Application.cfc` to prevent regeneration of a new keyring file after initial launch. See notes in `Application.cfc`.
19. Register an account, login and enjoy!

## Upgrading

**NOTE** If you are currently running a version of fw1-sa without the 2FA integration, then you'll need to complete the following steps before updating to the latest master branch:

_If **not using** 2FA_:

1. Preserve a copy of your existing `Application.cfc` (or `MyApplication.cfc` if included in your distribution) so you can copy values for keyring and other application variables as needed.
2. Modify your users table to include `providerId` and `phone` as additional fields before updating

_If **using** 2FA_:

1. Preserve a copy of your existing `Application.cfc` (or `MyApplication.cfc` if included in your distribution) so you can copy values for keyring and other application variables as needed.
2. Modify your users table as above 
3. Add the smsProviders table and import the included data
4. Assign sms provider id's and phone numbers to existing users *(this must be done before switching 2FA on else users will not be able to authenticate)*

## Bugs and Feature Requests

If you find any bugs or have a feature you'd like to see implemented in this code, please use the issues area here on GitHub to log them.

## Contributing

This project is actively being maintained and monitored by Denard Springle. If you would like to contribute to this example please feel free to fork, modify and send a pull request!

## Attribution

This project utilizes the free open source MVC CFML (ColdFusion) framework [Framework One (fw/1)](https://github.com/framework-one/fw1) by [Sean Corfield](https://twitter.com/seancorfield).

## License

The use and distribution terms for this software are covered by the Apache Software License 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
