---
title: Cross-Site Scripting (XSS) Lab
tags: [Web, XSS, JavaScript]
description: A walkthrough of reflected XSS exploitation with payload crafting and CSP bypass.
date: 2025-11-09
---

## Overview
This lab explores reflected Cross-Site Scripting (XSS) vulnerabilities. XSS allows attackers to inject client-side scripts into web pages viewed by other users. This can lead to session hijacking, defacement, or redirection to malicious sites.

### Understanding Reflected XSS
Reflected XSS occurs when a malicious script is reflected off of a web application to the user's browser. The script is not stored on the web server; it's just echoed back in the response.

```javascript
// Example of a vulnerable input handling
const userInput = new URLSearchParams(window.location.search).get('q');
document.getElementById('search-results').innerHTML = `You searched for: ${userInput}`;