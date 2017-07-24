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

		<div class="row">
			<div class="col-sm-6 col-md-4 col-md-offset-4">
				<div class="panel panel-default">
					<div class="panel-heading">
						<strong><cfoutput>#encodeForHtml( rc.title )#</cfoutput></strong>
					</div>
					<div class="panel-body">
							<cfoutput>
								<form role="form" id="loginForm" action="#buildURL( 'main.authfactor' )#" method="POST" autocomplete="off">
								<input type="hidden" name="f#application.securityService.uberHash( 'token', 'SHA-512', 1700 )#" value="#CSRFGenerateToken( forceNew = true )#">
							</cfoutput>
								<div class="row">
									<div class="text-center">
										<p>Please enter your authorization code below.</p>
									</div>
								</div>
							<fieldset>
								<div class="row">
									<div class="col-sm-12 col-md-10  col-md-offset-1 ">
										<div class="form-group">
											<div class="input-group">
												<span class="input-group-addon">
													<i class="glyphicon glyphicon-earphone"></i>
												</span> 
												<input class="form-control" placeholder="Authorization Code" name="twofactor" type="password" autocomplete="off" required autofocus>
											</div>
										</div>
										<div class="form-group">
											<input type="submit" id="btnLogin" class="btn btn-lg btn-primary btn-block" value="Complete Sign in">
										</div>
									</div>
								</div>
							</fieldset>
						</form>
					</div>
					<div class="panel-footer ">
					</div>
				</div>
			</div>
		</div>
	</div>

	<script src="https://code.jquery.com/jquery-1.11.3.min.js"></script>
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>

</body>
</html>
