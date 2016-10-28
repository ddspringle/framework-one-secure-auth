// minimal Application.cfc to prevent fw/1 from triggering 
// during http calls to blocked_ips.json
component {
	this.name = hash( getBaseTemplatePath() );
}