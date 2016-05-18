	<div class="row">
		<div class="col-md-12"><h1>Secure Auth Example</h1></div>
	</div>
	<div class="row">
		<div class="col-md-12">&nbsp;</div>
	</div>
	<div class="row">
		<div class="col-md-4">
			<cfif rc.msg>
				<cfif !rc.msg eq 200>
					<div class="alert alert-danger alert-dismissable">
						<button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
						<i class="fa fa-exclamation-triangle"></i> <cfoutput>#encodeForHtml( rc.message )#</cfoutput>
					</div>
				<cfelse>
					<div class="alert alert-success alert-dismissable">
						<button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
						<i class="fa fa-info-circle"></i> <cfoutput>#encodeForHtml( rc.message )#</cfoutput>
					</div>
				</cfif>
			</cfif>
			<div class="panel panel-warning">
				<div class="panel-heading">
					<h3 class="panel-title">
						Reset your password
					</h3>
				</div>
				<div class="panel-body">
					<p>If you have forgotten your password, use this form to have a new system generated password emailed to you.</p>					
					<cfoutput><form role="form" action="#buildUrl( 'main.resetpass' )#" method="POST"></cfoutput>
						<div class="form-group">							 
							<label for="username">
								Email address
							</label>
							<input type="email" class="form-control" name="username" id="username" placeholder="someone@somewhere.com" required>
						</div>
						<button type="submit" class="btn btn-success">
							Reset Password
						</button>
						&nbsp;&nbsp;
						<cfoutput><a href="#buildUrl( 'main.default' )#" class="btn btn-danger">Cancel</a></cfoutput>
					</form>
				</div>
				<div class="panel-footer">
					Still having difficulties? Please contact your system administrator.
				</div>
			</div>
		</div>
		<div class="col-md-8">
		</div>
	</div>