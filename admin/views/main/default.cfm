<!DOCTYPE html>
<html lang="en">

<head>

	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="">
	<meta name="author" content="">

	<title><cfoutput>#encodeForHtml( rc.title )#</cfoutput></title>

	<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.4.0/css/font-awesome.min.css" rel="stylesheet">

	<link rel="shortcut icon" href="favicon.ico" type="image/x-icon" />

	<!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
	<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
	<!--[if lt IE 9]>
		<script src="https://oss.maxcdn.com/libs/html5shiv/3.7.0/html5shiv.js"></script>
		<script src="https://oss.maxcdn.com/libs/respond.js/1.4.2/respond.min.js"></script>
	<![endif]-->

<style type="text/css">

.panel-heading {
	padding: 5px 15px;
}

.panel-footer {
	padding: 1px 15px;
	color: #A0A0A0;
}

.profile-img {
	width: 50px;
	height: 100px;
	margin: 0 auto 10px;
	display: block;
	-moz-border-radius: 50%;
	-webkit-border-radius: 50%;
	border-radius: 50%;
}

</style>

</head>
 
<body>

	<div class="container" style="margin-top:40px">

		<cfif rc.msg>
			<div class="row">
				<div class="col-sm-6 col-md-4 col-md-offset-4">
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
				</div>
			</div>
			<!-- /.row -->                  
		</cfif>

		<div class="row">
			<div class="col-sm-6 col-md-4 col-md-offset-4">
				<div class="panel panel-default">
					<div class="panel-heading">
						<strong><cfoutput>#encodeForHtml( rc.title )#</cfoutput></strong>
					</div>
					<div class="panel-body">
						<form role="form" id="loginForm" action="<cfoutput>#buildURL( 'main.authenticate' )#</cfoutput>" method="POST" autocomplete="off">
							<cfoutput>
								<input type="hidden" id="heartbeat" name="heartbeat" value="#application.securityService.getHeartbeat()#">
								<input type="hidden" name="f#application.securityService.uberHash( 'token', 'SHA-512', 150 )#" value="#CSRFGenerateToken( forceNew = true )#">
							</cfoutput>
							<fieldset>
								<div class="row">
									<div class="center-block">
										<span class="profile-img"><i class="fa fa-user fa-5x"></i></span>
									</div>
								</div>
								<div class="row">
									<div class="col-sm-12 col-md-10  col-md-offset-1 ">
										<div class="form-group">
											<div class="input-group">
												<span class="input-group-addon">
													<i class="glyphicon glyphicon-user"></i>
												</span> 
												<input class="form-control" placeholder="Email Address" name="username" type="email" autocomplete="off" required autofocus>
											</div>
										</div>
										<div class="form-group">
											<div class="input-group">
												<span class="input-group-addon">
													<i class="glyphicon glyphicon-lock"></i>
												</span>
												<input class="form-control" placeholder="Password" name="password" id="password" type="password" value="" autocomplete="off" required>
											</div>
										</div>
										<div class="form-group">
											<input type="submit" id="btnLogin" class="btn btn-lg btn-primary btn-block" value="Sign in">
										</div>
									</div>
								</div>
							</fieldset>
						</form>
					</div>
					<div class="panel-footer ">
						<a href="<cfoutput>#buildURL( 'home:main.reset' )#</cfoutput>">Forgot your password?</a>
					</div>
				</div>
			</div>
		</div>
	</div>


	<script src="https://code.jquery.com/jquery-1.11.3.min.js"></script>
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha384.js"></script>

	<script type="text/javascript">

		$( document ).ready(function() {

			$( '#btnLogin').on( 'click', function( e ) {
				if( $('#password').val().length ) {

					e.preventDefault();

					var hp = $('#password').val();
					var hb = $('#heartbeat').val();

					hp = CryptoJS.SHA384( hp );
					hp = CryptoJS.SHA384( hp + hb );

					$('#password').val( hp ); 

					$('#loginForm').submit();

				}

			});

		});

	</script>

</body>
</html>