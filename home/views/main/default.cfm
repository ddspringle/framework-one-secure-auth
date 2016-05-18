<cfoutput>
	<div class="row">
		<div class="col-md-12"><h1>Secure Auth Example</h1></div>
	</div>
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-4">
			<div class="row">
				<div class="col-md-6">
					<a href="#buildUrl( 'main.register' )#" class="btn btn-block btn-lg btn-primary">Register</a>
				</div>
				<div class="col-md-6">
					<a href="#buildUrl( 'admin:main.default' )#" class="btn btn-success btn-lg btn-block">Login</a>
				</div>
			</div>
		</div>
		<div class="col-md-8">
		</div>
	</div>	
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-12"><p>This page was rendered on #encodeForHtml( rc.today )#.</p></div>
	</div>
</cfoutput>