🔐 OTP Flooding Vulnerability – Responsible Disclosure

🤝 Responsible Disclosure Timeline

Date	         Event
Mar 2026	Vulnerability discovered
Mar 2026	Report submitted
Apr 2026	Response received (Acknowledge)

📌 Summary
This report describes an OTP (One-Time Password) abuse scenario identified in a logistics platform during security testing. The issue allows multiple OTP requests to be triggered in a short time window, leading to potential OTP flooding.


 🧩 Vulnerability Details

- Type: Improper Rate Limiting / OTP Abuse
- Category: OWASP API Security (Lack of Resources & Rate Limiting)
- Severity: Medium (User Impact-Based)



 🚨 Description

The OTP generation endpoint is exposed as part of the pre-login flow and does not require authentication (expected behavior). However, insufficient rate limiting allows an attacker to trigger multiple OTPs rapidly.

During testing, it was observed that:

- OTP endpoint accepts repeated requests without strong throttling
- Multiple OTPs (15+) can be triggered within seconds
- Incorrect error handling (HTTP 429 converted to 500)

🧪 Proof of Concept (PoC)

curl -X POST https://target.com/api/sendOTP \
-H "Content-Type: application/json" \
-d '{"mobile":"<base64_encoded_number>"}'


🔹 Steps to Reproduce

- Identify OTP endpoint
- Send multiple requests using curl or Burp Suite
- Observe multiple OTPs received on the same number
- Continue until rate limit threshold (~15 requests)
- After threshold, server returns incorrect 500 instead of 429


⚠️ Impact

OTP flooding → User inconvenience / spam
Possible denial-of-service-like scenario on user communication channel
Weak abuse protection for authentication mechanism

🔍 Root Cause

-- Static rate limiting 
-- No adaptive throttling mechanism
-- Missing CAPTCHA / bot protection
-- Improper error code handling

🛡️ Recommended Fixes
-- Implement adaptive rate limiting (per IP/device/user)
-- Add CAPTCHA after few attempts
-- Introduce cooldown period between OTP requests
-- Fix HTTP response codes (429 Too Many Requests)
-- Monitor abnormal OTP request patterns


👨‍💻 Author

Namra Panchal
Bug Bounty Hunter
