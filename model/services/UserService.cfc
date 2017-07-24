/**** @file UserService.cfc* @author Denard Springle ( denard.springle@gmail.com )* @description I provide user related data access functions**/component displayname="UserService" accessors="true" {	public function init() {		return this;	}	// PUBLIC METHODS //	// CREATE //	/**	* @displayname	createNewUser	* @description	I insert a new user record into the users table in the database	* @param		user {Any} I am the User bean	* @return 		numeric	*/	public numeric function createNewUser( required any user ) {		var qPutUser = '';		var queryService = new query();		var sql = '';		try {			sql = 'INSERT INTO users ( providerId, username, password, firstName, lastName, phone, role, isActive ) VALUES ( :providerId, :username, :password, :firstName, :lastName, :phone, :role, :isActive )';			queryService.setSQL( sql );			queryService.addParam( name='providerId', value='#arguments.user.getProviderId()#', cfsqltype='cf_sql_integer' );			queryService.addParam( name='username', value='#arguments.user.getUsername()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name='password', value='#arguments.user.getPassword()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name='firstName', value='#arguments.user.getFirstName()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name='lastName', value='#arguments.user.getLastName()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name='phone', value='#arguments.user.getPhone()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name='role', value='#arguments.user.getRole()#', cfsqltype='cf_sql_integer' );			queryService.addParam( name='isActive', value='#arguments.user.getIsActive()#', cfsqltype='cf_sql_bit' );			qPutUser = queryService.execute();		// catch any errors //		} catch (any e) {			writeDump( e );			abort;		}		return qPutUser.getPrefix().IDENTITYCOL;	}	// RETRIEVE - BY ID //	/**	* @displayname	getUserByID	* @description	I return a User bean populated with the details of a specific user record	* @param		id {Numeric} I am the numeric auto-increment id of the user to search for	* @return 		any	*/	public any function getUserByID( required numeric id ) {		var qGetUser = '';		var queryService = new query();		var sql = '';		try {			sql = 'SELECT userId, username, password, firstName, lastName, role, isActive FROM users WHERE userId = :id';			queryService.setSQL( sql );			queryService.addParam( name = 'id', value = '#arguments.id#', cfsqltype = 'cf_sql_integer' );			qGetUser = queryService.execute().getResult();		// catch any errors //		} catch (any e) {			writeDump( e );			abort;		}		if( qGetUser.RecordCount ) {			return new model.beans.User(				userId		= qGetUser.userId,				providerId 	= qGetUser.providerId.				username	= qGetUser.username,				password	= qGetUser.password,				firstName	= qGetUser.firstName,				lastName	= qGetUser.lastName,				phone 		= qGetUser.phone,				role		= qGetUser.role,				isActive	= qGetUser.isActive			);		} else {			return new model.beans.User();		}	}	// UPDATE //	/**	* @displayname	updateUser	* @description	I update this user record in the users table of the database	* @param		user {Any} I am the User bean	* @return 		numeric	*/	public numeric function updateUser( required any user ) {		var qUpdUser = '';		var queryService = new query();		var sql = '';		try {			sql = 'UPDATE users SET username = :username, providerId = providerId, password = :password, firstName = :firstName, lastName = :lastName, phone = :phone, role = :role, isActive = :isActive WHERE userId = :userId';			queryService.setSQL( sql );			queryService.addParam( name = 'userId', value = '#arguments.user.getUserId()#', cfsqltype = 'cf_sql_integer' );			queryService.addParam( name = 'providerId', value='#arguments.user.getProviderId()#', cfsqltype='cf_sql_integer' );			queryService.addParam( name = 'username', value = '#arguments.user.getUsername()#', cfsqltype = 'cf_sql_varchar' );			queryService.addParam( name = 'password', value = '#arguments.user.getPassword()#', cfsqltype = 'cf_sql_varchar' );			queryService.addParam( name = 'firstName', value = '#arguments.user.getFirstName()#', cfsqltype = 'cf_sql_varchar' );			queryService.addParam( name = 'lastName', value = '#arguments.user.getLastName()#', cfsqltype = 'cf_sql_varchar' );			queryService.addParam( name = 'phone', value='#arguments.user.getPhone()#', cfsqltype='cf_sql_varchar' );			queryService.addParam( name = 'role', value = '#arguments.user.getRole()#', cfsqltype = 'cf_sql_integer' );			queryService.addParam( name = 'isActive', value = '#arguments.user.getIsActive()#', cfsqltype = 'cf_sql_bit' );			qUpdUser = queryService.execute().getResult();		// catch any errors //		} catch (any e) {			writeDump( e );			abort;		}		return arguments.user.getUserId();	}	// DELETE //	/**	* @displayname	deleteUserByID	* @description	I delete a user record from the users table in the database	* @param		id {Numeric} I am the numeric auto-increment id of the user to delete	* @return 		boolean	*/	public boolean function deleteUserByID( required numeric id ) {		var qDelUser = '';		var queryService = new query();		var sql = 'DELETE FROM users WHERE userId = :id';		try {			queryService.setSQL( sql );			queryService.addParam( name = 'id', value = '#arguments.id#', cfsqltype = 'cf_sql_integer' );			qDelUser = queryService.execute().getResult();		// catch any errors //		} catch (any e) {			writeDump( e );			abort;		}		return true;	}	// UTILITY METHODS //	// SAVE //	/**	* @displayname	saveUserByID	* @description	I save a user record in the users table in the database	* @param		user {Any} I am the User bean	* @return 		numeric	*/	public numeric function saveUser( required any user ) {		if( exists( arguments.user ) ) {			return updateUser( arguments.user );		} else {			return createNewUser( arguments.user );		}	}	// EXISTS //	/**	* @displayname	exists	* @description	I check if a user record exists in the users table in the database	* @param		user {Any} I am the User bean	* @return 		boolean	*/	public boolean function exists( required any user ) {		var qGetUser = '';		var queryService = new query();		var sql = 'SELECT userId FROM users WHERE userId = :userId';		queryService.setSQL( sql );		queryService.addParam( name = 'userId', value = '#arguments.user.getUserId()#', cfsqltype = 'cf_sql_integer' );		qGetUser = queryService.execute().getResult();		if( qGetUser.recordCount ) {			return true;		} else {			return false;		}	}	// FILTER //	/**	* @displayname	filter	* @description	I run a filtered query of all records within the users table in the database	* @param		returnColumns {String} I am the columns in the users table that should be returned in this query (default: all columns)	* @param		username {String} I am the value for username in the users table that should be returned in this query	* @param		password {String} I am the value for password in the users table that should be returned in this query	* @param		firstName {String} I am the value for firstName in the users table that should be returned in this query	* @param		lastName {String} I am the value for lastName in the users table that should be returned in this query	* @param		role {Numeric} I am the value for role in the users table that should be returned in this query	* @param		isActive {Boolean} I am the value for isActive in the users table that should be returned in this query	* @param		orderBy {String} I am the order to return records in the users table returned in this query	* @param		cache {Boolean} I am a flag (true/false) to determine if this query should be cached (default: false)	* @param		cacheTime {Any} I am the timespan the query should be cached for (default: 1 hour)	* @return 		query	*/	public query function filter(		string returnColumns = 'userId, providerId, username, password, firstName, lastName, phone, role, isActive', 		string providerId,		string username, 		string password, 		string firstName, 		string lastName,		string phone,		numeric role, 		boolean isActive, 		string orderBy,		boolean cache = false,		any cacheTime = createTimeSpan(0,1,0,0)	) {		var thisFilter = structNew();		if( isDefined( 'arguments.providerId' ) AND len( arguments.providerId ) ) {			thisFilter.rproviderId = arguments.providerId;		}		if( isDefined( 'arguments.username' ) AND len( arguments.username ) ) {			thisFilter.username = arguments.username;		}		if( isDefined( 'arguments.password' ) AND len( arguments.password ) ) {			thisFilter.password = arguments.password;		}		if( isDefined( 'arguments.firstName' ) AND len( arguments.firstName ) ) {			thisFilter.firstName = arguments.firstName;		}		if( isDefined( 'arguments.lastName' ) AND len( arguments.lastName ) ) {			thisFilter.lastName = arguments.lastName;		}		if( isDefined( 'arguments.phone' ) AND len( arguments.phone ) ) {			thisFilter.phone = arguments.phone;		}		if( isDefined( 'arguments.role' ) AND len( arguments.role ) ) {			thisFilter.role = arguments.role;		}		if( isDefined( 'arguments.isActive' ) AND len( arguments.isActive ) ) {			thisFilter.isActive = arguments.isActive;		}		if( isDefined( 'arguments.orderBy' ) AND len( arguments.orderBy ) ) {			thisFilter.order_by = arguments.orderBy;		}		if( isDefined( 'arguments.cache' ) AND len( arguments.cache ) ) {			thisFilter.cache = arguments.cache;		}		thisFilter.returnColumns = arguments.returnColumns;		if( !structIsEmpty( thisFilter ) AND structKeyExists( thisFilter, 'cache' ) AND thisFilter.cache ) {			return cacheFilteredUserRecords( thisFilter, arguments.cacheTime );		} else { 			return filterUserRecords( thisFilter );		}	}	// PRIVATE METHODS //	// QUERY - CACHE FILTERED USER RECORDS //	/**	* @displayname	cacheFilteredUserRecords	* @description	I run a query that will cache and return all user records. If a filter has been applied, I will refine results based on the filter	* @param		filter {Struct} I am the filter struct to apply to this query	* @param		cacheTime {Time} I am the time to cache this query (use createTimeSpan)	* @return 		query	*/	private query function cacheFilteredUserRecords( struct filter = {}, cacheTime = createTimeSpan( 0, 1, 0, 0 ) ) {		var cachedQueryName = hash( serializeJSON( arguments.filter ), 'MD5' );		var queryService = new query( datasource = variables.datasource, name = cachedQueryName, cachedWithin = arguments.cacheTime );		var sql = 'SELECT #arguments.filter.returnColumns# FROM users WHERE 1 = 1 ';		if( !structIsEmpty( arguments.filter ) ) {			// filter is applied //			if( structKeyExists( arguments.filter, 'providerId' ) ) {				sql = sql & 'AND providerId = :providerId ';				queryService.addParam( name = 'providerId', value = '#arguments.filter.providerId#', cfsqltype = 'cf_sql_integer' );			}			if( structKeyExists( arguments.filter, 'username' ) ) {				sql = sql & 'AND username = :username ';				queryService.addParam( name = 'username', value = '#arguments.filter.username#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'password' ) ) {				sql = sql & 'AND password = :password ';				queryService.addParam( name = 'password', value = '#arguments.filter.password#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'firstName' ) ) {				sql = sql & 'AND firstName = :firstName ';				queryService.addParam( name = 'firstName', value = '#arguments.filter.firstName#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'lastName' ) ) {				sql = sql & 'AND lastName = :lastName ';				queryService.addParam( name = 'lastName', value = '#arguments.filter.lastName#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'phone' ) ) {				sql = sql & 'AND phone = :phone ';				queryService.addParam( name = 'phone', value = '#arguments.filter.phone#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'role' ) ) {				sql = sql & 'AND role = :role ';				queryService.addParam( name = 'role', value = '#arguments.filter.role#', cfsqltype = 'cf_sql_integer' );			}			if( structKeyExists( arguments.filter, 'isActive' ) ) {				sql = sql & 'AND isActive = :isActive ';				queryService.addParam( name = 'isActive', value = '#arguments.filter.isActive#', cfsqltype = 'cf_sql_bit' );			}			if( structKeyExists( arguments.filter, 'order_by' ) ) {				sql = sql & 'ORDER BY #arguments.filter.order_by#';			}		}		return queryService.setSQL( sql ).execute().getResult();	}	// QUERY - FILTER USER RECORDS //	/**	* @displayname	filterUserRecords	* @description	I run a query that will return all user records. If a filter has been applied, I will refine results based on the filter	* @param		filter {Struct} I am the filter struct to apply to this query	* @return 		query	*/	private query function filterUserRecords( struct filter = {} ) {		var queryService = new query();		var sql = 'SELECT #arguments.filter.returnColumns# FROM users WHERE 1 = 1 ';		if( !structIsEmpty( arguments.filter ) ) {			// filter is applied //			if( structKeyExists( arguments.filter, 'providerId' ) ) {				sql = sql & 'AND providerId = :providerId ';				queryService.addParam( name = 'providerId', value = '#arguments.filter.providerId#', cfsqltype = 'cf_sql_integer' );			}			if( structKeyExists( arguments.filter, 'username' ) ) {				sql = sql & 'AND username = :username ';				queryService.addParam( name = 'username', value = '#arguments.filter.username#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'password' ) ) {				sql = sql & 'AND password = :password ';				queryService.addParam( name = 'password', value = '#arguments.filter.password#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'firstName' ) ) {				sql = sql & 'AND firstName = :firstName ';				queryService.addParam( name = 'firstName', value = '#arguments.filter.firstName#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'lastName' ) ) {				sql = sql & 'AND lastName = :lastName ';				queryService.addParam( name = 'lastName', value = '#arguments.filter.lastName#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'phone' ) ) {				sql = sql & 'AND phone = :phone ';				queryService.addParam( name = 'phone', value = '#arguments.filter.phone#', cfsqltype = 'cf_sql_varchar' );			}			if( structKeyExists( arguments.filter, 'role' ) ) {				sql = sql & 'AND role = :role ';				queryService.addParam( name = 'role', value = '#arguments.filter.role#', cfsqltype = 'cf_sql_integer' );			}			if( structKeyExists( arguments.filter, 'isActive' ) ) {				sql = sql & 'AND isActive = :isActive ';				queryService.addParam( name = 'isActive', value = '#arguments.filter.isActive#', cfsqltype = 'cf_sql_bit' );			}			if( structKeyExists( arguments.filter, 'order_by' ) ) {				sql = sql & 'ORDER BY #arguments.filter.order_by#';			}		}		return queryService.setSQL( sql ).execute().getResult();	}}