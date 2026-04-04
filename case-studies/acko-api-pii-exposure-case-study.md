# Unauthenticated API Exposure of User Phone Number (Case Study)

## 🏢 Target
Acko (Responsible Disclosure Program)

## 🧠 Vulnerability Type
CWE-200: Information Disclosure

## 📌 Summary
An unauthenticated API endpoint exposed sensitive user data (phone number and user_id) when accessed with a valid `request_id`.

## 🔍 Vulnerable Endpoint
GET /api/v1/kycrequests/{request_id}/login-details

## ⚠️ Issue
The endpoint did not require authentication or authorization.

Any valid `request_id` returned:
- User phone number
- Internal user_id

## 🧪 Proof of Concept

curl -s https://www.acko.com/api/v1/kycrequests/<request_id>/login-details


{
  "request_id": "...",
  "user": {
    "phone": "XXXXXXXXXX",
    "user_id": "..."
  }
}


🎯 Impact
Exposure of Personally Identifiable Information (PII)
Enables targeted phishing or spam attacks
No authentication required
📊 Status

Marked as Duplicate

📚 Key Learning
API endpoints must enforce authentication
Sensitive data should never be exposed without authorization
Even indirect identifiers (like request_id) can become attack vectors
🔐 Recommendation
Enforce authentication
Validate ownership of request_id
Restrict sensitive fields in responses
