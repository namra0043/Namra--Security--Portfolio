# Case Study: Directory Listing Exposure (VIT — anonymised)

Type: Information Disclosure  
Status:Reported (2025-09-04)  
Disclosure Window: Public summary only until vendor confirms fix

# Summary
On 2025-09-04, I discovered a web directory listing that exposed downloadable files without authentication. This report is a public, sanitised summary (no sensitive data included).

# Scope & Preconditions
- Target: VIT internal site   
- Access level: Unauthenticated (public internet)  
- Testing rules: Manual, read-only verification; no automated scans; no data exfiltration.

# Methodology

1. Visited the suspected path: `https://[redacted]/uploads/`.  
2. Observed that directory listing returned a file list.  
3. Downloaded a non-sensitive sample to verify access (kept offline).  
4. Confirmed behavior on both HTTP and HTTPS.

# Evidence (sanitised)
- Redacted screenshot stored.

# Impact
An attacker could download publicly available files. Severity depends on file contents; if sensitive documents exist, this may lead to information disclosure. 
Estimated severity: *Medium*.

# Remediation guidance
1. Disable directory listing.
2. Move sensitive files out of web-root or require authentication to access them.  
3. Add an index page to the directory to prevent listing.  
4. Periodically scan for exposed directories and fix permissions.

# Timeline (public excerpt)
- *2025-09-04:* Initial report submitted.   
- (Updating when vendor acknowledges)

*Researcher: * NAMRA PANCHAL
