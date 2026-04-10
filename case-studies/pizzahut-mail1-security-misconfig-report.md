# 🔐 Security Misconfiguration on Pizza Hut Asset (P5 - Informational)

## 📌 Overview

While testing a Pizza Hut India asset, I identified multiple **security misconfigurations** on:


mail1.pizzahut.co.in


Although the issues were valid and reproducible, they were classified as **Informational (P5)** due to limited real-world impact.


## 🚨 What’s the Issue?

The target system had several misconfigurations indicating a **poorly maintained / legacy server**:

* Expired SSL certificate
*  Hostname mismatch in SSL certificate
*  Directory listing enabled (`/cgi-bin/`)
*  Server information disclosure (Apache headers)

---

## 🎯 Why This Matters

Individually, these issues may look low-risk — but together they indicate:

* 🧱 Weak security posture
* 🕵️ Increased attack surface
* 🔍 Easier reconnaissance for attackers
* ⚠️ Potential entry point for deeper vulnerabilities

---

## 🧪 Proof of Concept

### 🔹 Check SSL Certificate


👉 Shows:

* Expired certificate (Feb 2025)
* Certificate issued for different subdomain

---

### 🔹 Directory Listing

👉 Result:

* Public access to `/cgi-bin/` directory
* Directory contents exposed

---

## 🧠 Root Cause

*  Improper server configuration
*  Lack of SSL certificate management
*  Directory listing not disabled
*  Legacy system left exposed

---

## ⚠️ Security Classification

* **VRT:** Server Security Misconfiguration
* **Severity:** P5 (Informational)

---

## 📊 Report Status

* 🎯 Program: Yum! Brands Vulnerability Disclosure
* 📌 Status: Accepted (Informational)
* 💰 Reward: Not eligible

---

## 🧠 What I Learned

This report taught me an important bug bounty lesson:

* ✅ Finding issues is easy
* ❌ Proving impact is what matters

To move beyond P5:

* 🔗 Chain misconfigurations with real exploits
* 🔍 Look for sensitive data exposure
* 💥 Demonstrate actual attacker impact

---

## 💡 Final Thought

> Misconfigurations are just the beginning — impact is everything.

---

## 🧑‍💻 Author

**Namra Panchal**
Bug Bounty Hunter | Web Security Learner 🚀
