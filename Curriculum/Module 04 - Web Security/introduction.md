# Web Security

This module focuses on offensive web security, covering the identification and exploitation of vulnerabilities in web applications and APIs. Students will learn about the OWASP Top 10 Web Application Security Risks and the OWASP API Security Top 10:2023, browser security mechanisms, and client-side, server-side, and API attack vectors. The module emphasizes practical exploitation techniques, defense strategies, and industry-standard security tools.

## Learning Objectives

By the end of this module, students will be able to:

- Understand HTTP/HTTPS protocol fundamentals and their security implications
- Identify and exploit common web application security vulnerabilities
- Recognize and bypass browser security features (SOP, CORS, CSP)
- Perform client-side attacks including XSS, CSRF, and clickjacking
- Execute server-side attacks including SQL injection, SSRF, and command injection
- Test and exploit API vulnerabilities (REST, GraphQL, JWT, OAuth 2.0)
- Understand OWASP Top 10 (Web Apps) and API Security Top 10:2023
- Understand the root causes and business impact of web security breaches
- Apply defense-in-depth strategies to prevent web vulnerabilities
- Use professional penetration testing tools (Burp Suite, SQLmap, OWASP ZAP, Postman)
- Conduct comprehensive web application and API security assessments

## Module Structure

### 1. Introduction to Web Security

**Topics covered:**

- The World Wide Web architecture
- HTTP/HTTPS protocol fundamentals
- HTTP request and response structure
- HTTP methods, status codes, and headers
- Sessions, cookies, and state management
- TLS/SSL and transport security
- Security implications of web protocols

**Skills developed:**

- Reading and analyzing HTTP traffic
- Understanding web application architecture
- Recognizing security-relevant HTTP features

### 2. Browser Security Features

**Topics covered:**

- Same-Origin Policy (SOP)
- Cross-Origin Resource Sharing (CORS)
- Content Security Policy (CSP)
- Security headers (HSTS, X-Frame-Options, X-Content-Type-Options)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Subresource Integrity (SRI)
- CORS preflight requests and bypass techniques

**Skills developed:**

- Configuring security headers
- Bypassing security mechanisms
- Exploiting misconfigured CORS policies
- Testing CSP implementations

### 3. Client-Side Vulnerabilities

**Topics covered:**

- Cross-Site Scripting (XSS)
  - Reflected, Stored, and DOM-based XSS
  - XSS filter bypass techniques
  - Polyglot payloads
- Cross-Site Request Forgery (CSRF)
- Clickjacking and UI redressing
- Open Redirect vulnerabilities
- DOM Clobbering
- Prototype Pollution
- PostMessage vulnerabilities

**Skills developed:**

- Crafting XSS payloads
- Bypassing input filters and WAFs
- Building CSRF exploits
- Exploiting browser-based vulnerabilities
- Implementing client-side security controls

### 4. Server-Side Vulnerabilities

**Topics covered:**

- SQL Injection (Union, Blind, Time-based, Error-based, Out-of-band, NoSQL)
- Server-Side Request Forgery (SSRF)
- OS Command Injection
- Path Traversal and File Inclusion (LFI/RFI)
- XML External Entity (XXE) injection
- Server-Side Template Injection (SSTI)
- Insecure Deserialization
- Authentication and Authorization flaws (IDOR, privilege escalation)

**Skills developed:**

- Exploiting SQL injection across different database types
- Performing SSRF attacks and cloud metadata exploitation
- Executing remote code via multiple attack vectors
- Identifying and exploiting access control vulnerabilities
- Using automated tools (SQLmap, ysoserial, tplmap)

### 5. API Security

**Topics covered:**

- REST API security fundamentals
- GraphQL security and attack vectors
  - Introspection abuse
  - Batching attacks
  - Query depth and complexity DoS
- JWT (JSON Web Token) security
  - Algorithm confusion attacks
  - Weak secret keys
  - Missing expiration
- OAuth 2.0 and OpenID Connect
  - Authorization flows
  - Redirect URI manipulation
  - State parameter CSRF
- OWASP API Security Top 10:2023
- API authentication and authorization best practices
- Rate limiting and resource consumption
- API testing methodologies

**Skills developed:**

- Identifying and exploiting API vulnerabilities (BOLA, mass assignment, excessive data exposure)
- Testing GraphQL APIs for security issues
- Exploiting JWT weaknesses
- Testing OAuth 2.0 implementations
- Implementing secure API authentication and authorization
- Using API security testing tools (Postman, Burp Suite, custom scripts)
- Performing comprehensive API security assessments

## OWASP Top 10 Coverage

This module comprehensively covers vulnerabilities from the OWASP Top 10 Web Application Security Risks:

1. **A01:2021 - Broken Access Control**: Covered in Authentication & Authorization section
2. **A02:2021 - Cryptographic Failures**: Covered in HTTPS/TLS and Cookie Security sections
3. **A03:2021 - Injection**: Extensive coverage of SQL, Command, XXE, and SSTI
4. **A04:2021 - Insecure Design**: Design flaws discussed throughout module
5. **A05:2021 - Security Misconfiguration**: CSP, CORS, and security headers
6. **A06:2021 - Vulnerable and Outdated Components**: Referenced in context
7. **A07:2021 - Identification and Authentication Failures**: Dedicated section on auth flaws
8. **A08:2021 - Software and Data Integrity Failures**: Deserialization attacks
9. **A09:2021 - Security Logging and Monitoring Failures**: Detection techniques covered
10. **A10:2021 - Server-Side Request Forgery (SSRF)**: Comprehensive SSRF section

### OWASP API Security Top 10:2023

This module also covers the OWASP API Security Top 10:2023, which addresses API-specific vulnerabilities:

1. **API1:2023 - Broken Object Level Authorization (BOLA)**: Comprehensive coverage in API Security section
2. **API2:2023 - Broken Authentication**: JWT, OAuth 2.0, and authentication mechanisms
3. **API3:2023 - Broken Object Property Level Authorization**: Mass assignment and excessive data exposure
4. **API4:2023 - Unrestricted Resource Consumption**: Rate limiting and DoS protection
5. **API5:2023 - Broken Function Level Authorization**: Function-level access control flaws
6. **API6:2023 - Unrestricted Access to Sensitive Business Flows**: Business logic vulnerabilities
7. **API7:2023 - Server-Side Request Forgery (SSRF)**: Covered in Server-Side Vulnerabilities section
8. **API8:2023 - Security Misconfiguration**: CORS, security headers, and API configuration
9. **API9:2023 - Improper Inventory Management**: API documentation and endpoint management
10. **API10:2023 - Unsafe Consumption of APIs**: Third-party API integration security

## Tools and Technologies

Students will gain hands-on experience with industry-standard security tools:

**Interception Proxies:**

- Burp Suite Professional/Community
- OWASP ZAP

**Automated Scanners:**

- SQLmap (SQL injection)
- XSStrike (XSS detection)
- Commix (Command injection)
- XXEinjector (XXE exploitation)
- tplmap (Template injection)
- ysoserial (Java deserialization)

**API Security Tools:**

- Postman / Insomnia (API testing)
- jwt_tool (JWT security testing)
- GraphQL Armor (GraphQL protection)
- Arjun (API endpoint discovery)

**Testing Environments:**

- PortSwigger Web Security Academy
- DVWA (Damn Vulnerable Web Application)
- bWAPP (Buggy Web Application)
- crAPI (Completely Ridiculous API)
- VAmPI (Vulnerable API)
- DVGA (Damn Vulnerable GraphQL Application)
- HackTheBox / TryHackMe

**Development Tools:**

- Browser Developer Tools
- curl / wget
- Python requests library
- Postman / Insomnia

## Prerequisites

- Basic understanding of web development (HTML, CSS, JavaScript)
- Familiarity with HTTP and web browsers
- Basic command-line proficiency
- Programming fundamentals (any language)

## Assessment

Students will be evaluated through:

- Hands-on lab exercises for each vulnerability class
- Capture-the-flag (CTF) challenges
- Web application penetration testing project
- Written reports documenting findings and exploitation steps

## Resources

All lectures include:

- Real-world vulnerable code examples
- Step-by-step exploitation walkthroughs
- Prevention and mitigation strategies
- Links to practice labs and vulnerable applications
- References to official documentation and research papers

## Ethical Considerations

**Important**: All techniques taught in this module are for authorized security testing only. Students must:

- Only test applications they own or have explicit written permission to test
- Follow responsible disclosure practices
- Understand legal implications of unauthorized access
- Adhere to the ACM Code of Ethics and professional conduct standards

Unauthorized access to computer systems is illegal under laws including the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation worldwide.
