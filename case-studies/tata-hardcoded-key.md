🔐 Case Study: Information Disclosure via Hardcoded AES Key in Client-Side Application (**Tata Play reported via responsible disclosure program)**

Overview

During security testing of a large Indian consumer-facing media platform, a critical information disclosure issue was identified involving improper client-side cryptographic implementation.
Sensitive user data (mobile numbers) was encrypted but transmitted to the client along with a hardcoded AES-128 key embedded in public JavaScript, allowing decryption of protected information.
The vulnerability was responsibly reported through the organization’s bug bounty program and later classified as a duplicate.


Vulnerability Classification

- Hardcoded Cryptographic Key in Client Code
- Client-Side Decryption of Sensitive Data
- Exposure of Personally Identifiable Information (PII)

CWE: CWE-321 — Use of Hard-coded Cryptographic Key
OWASP Top 10: A02 — Cryptographic Failures


Discovery Methodology

The issue was identified through manual analysis without automated exploitation.
- Inspection of client-side JavaScript bundles
- Analysis of authentication and OTP workflows
- Review of browser storage (localStorage)
- Static analysis of encryption logic


Technical Details (Sanitized)

- User mobile numbers were encrypted and stored inside a JWT token on the client
- The application masked the number in the UI but retained full encrypted data in storage
- A static AES-128 key was embedded within a publicly accessible JavaScript file
- The key could be extracted by inspecting the source code
- Encrypted data could then be decrypted locally without server interaction


Proof-of-Concept Summary

- Extract the hardcoded encryption key from public JavaScript
- Capture the encrypted mobile number from browser storage
- Decrypt the value using AES-128-ECB with the extracted key
- Retrieve the full unmasked mobile number
- This demonstrated that UI masking provided no real protection.


Impact Assessment

**Severity: High**
- **Type: Information Disclosure**
- **Category: Cryptographic Failure**


Potential risks include:
- Large-scale privacy violations
- Mass harvesting of user contact data
- Circumvention of privacy masking controls
- Increased risk when combined with session theft or XSS
- Loss of user trust and regulatory exposure


Responsible Disclosure Outcome
- The vulnerability was reported with detailed reproduction steps
- The organization acknowledged the submission
- The report was closed as a duplicate of a previously reported issue
- No further testing was conducted after confirmation



Skills Demonstrated

- Web Application Security Testing
- Client-Side JavaScript Analysis
- JWT and Browser Storage Analysis
- PII Risk Assessment
- Responsible Disclosure Practices
