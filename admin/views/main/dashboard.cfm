<cfoutput>
	<div class="row">
		<div class="col-md-12"><h1>Secure Auth Example &raquo; Dashboard</h1></div>
	</div>
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-4">
			<h3>Welcome #session.sessionObj.getFirstName()# #session.sessionObj.getLastName()#!</h3>
			<h3>You have successfully logged into the Secure Auth Example Dashboard.</h3>
			<h3>Nothing to see here... this <strong>is</strong> just an example, after all :P</h3>
		</div>
		<div class="col-md-8">
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-12"><a href="#buildUrl( 'main.logout' )#" class="btn btn-warning">Sign Out</a>&nbsp;&nbsp;&nbsp;<a href="#buildUrl( 'home:main.default' )#" class="btn btn-info">Return To Home Page</a></div>
	</div>
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-12">Running #encodeForHtml( rc.product )# #encodeForHtml( rc.version )#</div>
	</div>
</cfoutput>