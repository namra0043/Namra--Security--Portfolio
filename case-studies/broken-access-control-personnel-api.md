# Broken Access Control in Personnel API (CWE-285)

## 📌 Summary

A Broken Access Control vulnerability was identified in the `personnel-master-search` API, allowing authenticated users to retrieve **all personnel records within a tenant**, instead of only the requested user.

---

## 🎯 Impact

* Unauthorized access to personnel data
* Exposure of:

  * Personnel IDs
  * Names
  * Team associations
  * Metadata & profile details
* Horizontal privilege escalation
* Violation of tenant data isolation

---

## 🧪 Root Cause

The API failed to enforce authorization checks on the `personnelId` parameter.

Even when a specific personnelId was supplied, the backend ignored the filter and returned the **entire dataset (147 users)**.

---

## 🔁 Proof of Concept

### Request:

```bash
curl -X POST "https://platform-devo-5.locus-api-devo.com/v1/client/locus-pentest-1/personnel-master-search/compact" \
-H "Authorization: Bearer <REDACTED_TOKEN>" \
-H "Content-Type: application/json" \
-d '{"personnelId":"locus-pentest-1/personnel/BB1"}'
```

### Expected:

Return only data for:

```
BB1
```

### Actual:

Returned all personnel records:

```
BB9
BB85
BB100
... (147 users)
```

---

## ⚠️ Security Issue

* CWE-285: Improper Authorization
* OWASP Top 10: A01 – Broken Access Control

---

## 🧠 Key Takeaways

* Authorization must be enforced **server-side**, not trusted from client input
* Filtering parameters ≠ access control
* APIs should validate **ownership and scope of data access**

---

## 📊 Report Status

* Program: Locus Private Bug Bounty
* Severity: High (Not confirmed)
* Status: Duplicate

---

## 🚀 Learning Outcome

Even though marked duplicate, this finding reinforced:

* API authorization testing techniques
* Importance of parameter validation
* Real-world impact of simple logic flaws

---

## 🧑‍💻 Author

Namra Panchal
Bug Bounty Hunter | API Security Enthusiast
