Sensitive Information Disclosure via CodeIgniter Debug Mode

Vendor: BharatTaxi
Affected Asset: partners.bharattaxi.com
Report Date: 7 February 2026
Disclosure Method: Coordinated Disclosure via CERT-In
Reference: CERTIn-35766826
Status: Resolved


Summary

A misconfiguration was identified on the BharatTaxi partner portal where the CodeIgniter Debug Toolbar was enabled in a production environment. This developer debugging feature was publicly accessible and exposed internal application information.
The issue allowed unauthenticated users to access debugging panels by appending a query parameter to the URL.

https://partners.bharattaxi.com/?debugbar


Impact

The exposed debug interface revealed sensitive development information including:
- Internal server file paths
- Application configuration details
- SQL query logs
- Routing and request data
- Environment information



Steps to Reproduce
1) Open the following URL in a browser:
https://partners.bharattaxi.com/?debugbar

2) A Debug icon appears at the bottom of the page.

3) Expanding the panel reveals multiple debugging modules including:
- Database queries
- Application logs
- Environment data
- Framework internals


Evidence

Example debug toolbar loader:
- debugbar_loader
- debugbar_dynamic_script
- debugbar_dynamic_style
- toolbarContainer

This confirms that the CodeIgniter Debug Toolbar was active in the production environment.


Root Cause

**The issue occurred because the application was running with debugging features enabled.
The CI_ENVIRONMENT variable was not set to production, allowing the debug toolbar to be exposed.**


Responsible Disclosure Timeline
Date	
- 7 Feb 2026	Vulnerability reported to CERT-In
- 9 Feb 2026	CERT-In acknowledged report
- Feb 2026	CERT-In coordinated disclosure with vendor
- Mar 2026	Debug endpoint disabled
