# FW/1 Secure Authentication Example

This project is an example [fw/1](https://github.com/framework-one/fw1) application with secure authentication and session management functions as follows:

* Based on basic example [fw/1](https://github.com/framework-one/fw1) application
* Uses subsystems for separation of concerns, securing only the 'admin' subsystem
* Includes a SecurityService component that has encryption, decryption, hashing, password generation and session management code
* Includes a security controller for managing session and request scope session management within the 'admin' subsystem
* Uses cookies and object cache for session management
* Includes HMAC protection for session cookies to help prevent tampering
* Rotates the session id on each request and utilizes form tokenization to help prevent CSRF
* Federates the login with a cookie and referrer requirement
* Protects the users password from disclosure with SHA-384 hashing during login
* Stores user data in encrypted format in the database
* Default CBC/PKCS5Padding defined for encryption algorithms
* Includes HTTP security headers designed to reduce attack surface
* Uses keyring stored on disk to load encryption keys instead of hard-coded in the Application.cfc
* Includes functions for reading, writing and generating a random keyring file
* Includes functions for checking for, adding, removing and importing blocked IP's
* Includes functions for checking for, adding, removing and importing watched IP's 
* Managing watched/blocked IPs by catching common parameter tampering/sql injection attacks
* Added optional `addDate` true/false parameter to uberHash function to append the current date to the input value on hash
* Added 'dummy' cookies for the purpose of further obfuscating which cookie is used for session management
* Added repeatable form encryption for ajax populated and javascript selected form fields
* Added BaseBean with convenience functions for populating primary key data and CSRF fields in urls and forms (respectively)
* Added page caching and flushing capabilities added for static views (for [NVCFUG Preso](https://www.meetup.com/nvcfug/events/236791823/)) - use url param `flushCache` to flush
* Added fw1 environment control and check for the `prod` (production) environment before running IP watching or blocking routines
* Added configurable block mode - one of abort or redirect. Abort simply aborts further processing for blocked IP's. Redirect works as it did before this release, redirecting to the ipBlocked.html file.
* NEW! Migrated to new Application.cfc FW/1 initialization model
* NEW! **BREAKING CHANGE** The two factor authentication code from our two-factor example has been rolled into this code as of 7/24/2017. You can turn on 2FA in the Application.cfc (off by default to maintain backwards compatibility). Code prior to this release has been moved to the `legacy` branch.

This code was put together for the `ColdFusion: Code Security Best Practices` presentation by Denard Springle at [NCDevCon 2015](http://www.ncdevcon.com) and is a good basic starting point if you need to create a secure application using fw/1.

This code has since been expanded multiple times to include additional functionality not shown during the initial presentation. More details on how (and why) these security functions work and are important can be gleaned from reading the ColdFusion Security documents on [CFDocs](http://cfdocs.org/security) and from reviewing the SecurityService.cfc in /model/services/ which has been expanded for content.

## Compatibility

* Adobe ColdFusion 11+
* Lucee 4.5+

## Installing

1. Drop the code into your favorite CFML engine's webroot OR install using [CommandBox](https://www.ortussolutions.com/products/commandbox) using the command `box install fw1-sa`
2. Create a database and generate the users and smsProviders database tables (MSSQL SQL and Excel data provided in the 'database' folder)
3. Create a datasource for your database in your CFML engine's admin
4. Configure an object cache, if one is not already defined (Railo/Lucee)
5. Configure a mail server in your CFML engine's admin
6. Modify variables in Application.cfc as needed (see notes in Application.cfc)
7. Browse to webroot and enjoy!

## Upgrading

**NOTE** If you are running a version of fw1-sa without the 2FA integration already, then you'll need to complete the following steps before updating to the latest master branch:

_If **not** using 2FA_:

1. Modify your users table to include `providerId` and `phone` as additional fields before updating

_If **using** 2FA_:

1. Modify your users table as above 
2. Add the smsProviders table and import the included data
3. Assign sms provider id's and phone numbers to existing users *(this must be done before switching 2FA on else users will not be able to authenticate)*

## Demo

You can view single factor authentication using this code live at https://sa.vsgcom.net/

You can view two-factor authentication using this code [currently down] at https://tfa.vsgcom.net/

## Bugs and Feature Requests

If you find any bugs or have a feature you'd like to see implemented in this code, please use the issues area here on GitHub to log them.

## Contributing

This project is actively being maintained and monitored by Denard Springle. If you would like to contribute to this example please feel free to fork, modify and send a pull request!

## Attribution

This project utilizes the free open source MVC CFML (ColdFusion) framework  [Framework One (fw/1)](https://github.com/framework-one/fw1) by [Sean Corfield](https://twitter.com/seancorfield).

## License

The use and distribution terms for this software are covered by the Apache Software License 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
