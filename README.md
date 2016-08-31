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

This code was put together for the `ColdFusion: Code Security Best Practices` presentation by Denard Springle at [NCDevCon 2015](http://www.ncdevcon.com) and is a good basic starting point if you need to create a secure application using fw/1.

## Compatibility

* Adobe ColdFusion 10+
* Lucee 4.5+

## Installing

1. Drop the code into your favorite CFML engine's webroot OR install using [CommandBox](https://www.ortussolutions.com/products/commandbox) using the command `box install fw1-sa`
2. Create a database and generate the user database table (MSSQL SQL provided in the 'database' folder)
3. Create a datasource for your database in your CFML engine's admin
4. Configure an object cache, if one is not already defined (Railo/Lucee)
5. Modify encryption keys/algorithms/encoding in Application.cfc (use [generateSecretKey()](http://cfdocs.org/generatesecretkey) (or http://www.dvdmenubacks.com/key.cfm) to generate keys)
6. Modify cookieName and timeoutSession variables in Application.cfc
7. Browse to webroot and enjoy!

## Demo

**NOTE:** Demo servers are down temporarily [You can view this code live at https://sa.vsgcom.net/]

## Other implementations

* [Two-Factor Authentication Example](https://github.com/ddspringle/framework-one-two-factor-auth)

## Bugs and Feature Requests

If you find any bugs or have a feature you'd like to see implemented in this code, please use the issues area here on GitHub to log them.

## Contributing

This project is actively being maintained and monitored by Denard Springle. If you would like to contribute to this example please feel free to fork, modify and send a pull request!

## Attribution

This project utilizes the free open source MVC CFML (ColdFusion) framework  [Framework One (fw/1)](https://github.com/framework-one/fw1) by [Sean Corfield](https://twitter.com/seancorfield).

## License

The use and distribution terms for this software are covered by the Apache Software License 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
