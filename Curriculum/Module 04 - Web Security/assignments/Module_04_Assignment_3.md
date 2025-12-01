# Assignment 3: API Security Assessment Project

## Objective

The purpose of this assignment is to develop comprehensive API security testing skills through a hands-on security assessment of a vulnerable API application. You will perform reconnaissance, identify vulnerabilities, exploit security flaws, and document your findings in a professional penetration testing report. This assignment simulates real-world API security assessments.

## Overview

You will conduct a security assessment of **crAPI (Completely Ridiculous API)** or **VAmPI (Vulnerable API)**, two intentionally vulnerable API applications designed for security testing practice. Your task is to identify and exploit vulnerabilities from the OWASP API Security Top 10:2023 and document your findings professionally.

## Instructions

### Phase 1: Environment Setup

#### Option A: crAPI (Recommended for comprehensive testing)

**Installation:**

```bash
# Using Docker Compose
git clone https://github.com/OWASP/crAPI
cd crAPI
docker-compose -f deploy/docker/docker-compose.yml up -d

# Access at http://localhost:8888
```

**About crAPI:**

- Full-featured vulnerable API and web application
- Covers multiple OWASP API Top 10 vulnerabilities
- Includes REST APIs and GraphQL
- More realistic and complex scenarios

#### Option B: VAmPI (Simpler, faster setup)

**Installation:**

```bash
# Using Docker
docker pull erev0s/vampi:latest
docker run -d -p 5000:5000 erev0s/vampi

# Access API at http://localhost:5000
# Documentation at http://localhost:5000/docs
```

**About VAmPI:**

- Lightweight vulnerable REST API
- Clear vulnerability examples
- Good for beginners
- Faster to complete

**Choose ONE application for your assessment.**

### Phase 2: Reconnaissance and API Discovery

Document the following information:

1. **API Endpoints Discovery**:
   - List all API endpoints discovered
   - HTTP methods supported for each endpoint
   - Authentication requirements
   - Parameter types and expected inputs

2. **API Documentation Analysis**:
   - Review available API documentation
   - Identify authenticated vs. unauthenticated endpoints
   - Note any security-relevant information disclosed

3. **Technology Stack Identification**:
   - Backend framework/language
   - Database type (if identifiable)
   - Authentication mechanism (JWT, session cookies, etc.)
   - Any third-party integrations

**Tools to Use:**

- Burp Suite (Proxy, Spider, Scanner)
- Postman or Insomnia (API testing)
- Browser Developer Tools
- curl or httpie (command-line testing)

### Phase 3: Vulnerability Testing

Test for the following vulnerability categories from OWASP API Security Top 10:2023:

#### 1. API1:2023 - Broken Object Level Authorization (BOLA/IDOR)

**What to test:**

- Can you access other users' resources by changing IDs?
- Are object-level access controls properly enforced?
- Can you enumerate user IDs or resource IDs?

**Testing methodology:**

1. Create two user accounts (User A and User B)
2. Obtain authentication tokens for both
3. Use User A's token to access User B's resources
4. Document any successful unauthorized access

**Example test:**

```bash
# User A's token trying to access User B's data
curl -H "Authorization: Bearer USER_A_TOKEN" \
     http://localhost:8888/api/users/USER_B_ID
```

#### 2. API2:2023 - Broken Authentication

**What to test:**

- Weak password policies
- Brute force protection (rate limiting)
- Session management issues
- JWT security (algorithm confusion, weak secrets)
- Token expiration and refresh mechanisms

**Testing methodology:**

1. Attempt multiple failed login attempts (test rate limiting)
2. Analyze JWT tokens for weaknesses
3. Test token reuse after logout
4. Check for predictable session identifiers

#### 3. API3:2023 - Broken Object Property Level Authorization

**What to test:**

- Mass assignment vulnerabilities
- Excessive data exposure in API responses
- Can users modify restricted fields?

**Testing methodology:**

1. Capture legitimate API requests
2. Add additional fields (e.g., `isAdmin: true`, `role: "admin"`)
3. Observe response for sensitive data exposure
4. Test field manipulation in update operations

**Example test:**

```bash
# Attempt to set admin flag via mass assignment
curl -X PUT http://localhost:5000/api/users/1 \
     -H "Content-Type: application/json" \
     -d '{"username": "attacker", "isAdmin": true, "balance": 999999}'
```

#### 4. API4:2023 - Unrestricted Resource Consumption

**What to test:**

- Rate limiting on sensitive endpoints
- Pagination limits
- Query complexity limits (GraphQL)
- Resource quotas

**Testing methodology:**

1. Send rapid requests to endpoints
2. Request large amounts of data without pagination
3. Test for timeout/throttling mechanisms

#### 5. API5:2023 - Broken Function Level Authorization

**What to test:**

- Can regular users access admin endpoints?
- Are privileged functions properly protected?
- Horizontal and vertical privilege escalation

**Testing methodology:**

1. Identify admin/privileged endpoints
2. Attempt access with regular user credentials
3. Test hidden or undocumented endpoints

#### 6. API7:2023 - Server-Side Request Forgery (SSRF)

**What to test:**

- URL parameters accepting external URLs
- Features that fetch remote resources
- Webhook implementations

**Testing methodology:**

1. Identify endpoints accepting URLs
2. Test with internal IPs (127.0.0.1, localhost, 192.168.x.x)
3. Test with cloud metadata endpoints (169.254.169.254)

#### 7. Additional Testing

- **SQL Injection**: Test input fields for SQL injection
- **XSS**: Test for reflected/stored XSS in API responses
- **CORS Misconfiguration**: Check CORS headers
- **Security Headers**: Verify presence of security headers
- **Error Handling**: Test for information disclosure in errors

### Phase 4: Exploitation and Proof of Concept

For each vulnerability found:

1. **Reproduce the vulnerability** reliably
2. **Document the exploitation process** step-by-step
3. **Capture evidence**:
   - Screenshots of successful exploits
   - HTTP request/response pairs
   - Video recordings (optional but recommended)
4. **Assess the impact**:
   - What data is exposed or compromised?
   - What actions can an attacker perform?
   - What is the business impact?

### Phase 5: Professional Report Writing

Compile your findings into a professional penetration testing report.

---

## Report Structure

### 1. Executive Summary (1-2 pages)

- Overview of the assessment
- Key findings summary
- Risk rating overview (Critical/High/Medium/Low count)
- Overall security posture assessment
- Prioritized recommendations

**Target Audience**: Non-technical stakeholders, management

### 2. Scope and Methodology (1 page)

- Application tested (crAPI or VAmPI)
- Testing dates and duration
- Testing methodology (OWASP API Top 10:2023)
- Tools used
- Limitations and constraints
- Rules of engagement

### 3. Technical Findings (Main section)

For each vulnerability discovered, include:

#### Finding Template

**Finding #X: [Vulnerability Name]**

- **Severity**: Critical / High / Medium / Low
- **OWASP Category**: API1:2023, API2:2023, etc.
- **CWE**: CWE number (e.g., CWE-284: Improper Access Control)
- **Affected Endpoint(s)**: List specific API endpoints
- **Description**: Clear explanation of the vulnerability
- **Proof of Concept**:
  - Step-by-step reproduction steps
  - HTTP requests and responses
  - Screenshots/evidence
- **Impact**: Detailed impact analysis
  - Confidentiality impact
  - Integrity impact
  - Availability impact
  - Business impact
- **Remediation**:
  - Specific fix recommendations
  - Secure code examples
  - References to best practices
- **CVSS Score**: Optional - calculate CVSS score

**Minimum Findings Required**: 5 vulnerabilities across different OWASP categories

### 4. Risk Assessment Matrix

Provide a summary table:

| Finding | Severity | OWASP Category | Impact | Remediation Priority |
|---------|----------|----------------|--------|---------------------|
| BOLA on /api/users | Critical | API1:2023 | High | Immediate |
| Missing Rate Limiting | High | API4:2023 | Medium | High |
| ... | ... | ... | ... | ... |

### 5. Recommendations (1-2 pages)

- **Immediate Actions**: Critical fixes needed now
- **Short-term Improvements**: High/medium priority fixes
- **Long-term Strategy**: Overall security improvements
- **Security Best Practices**: General recommendations for API security

### 6. Appendices

- **Appendix A**: Detailed HTTP requests and responses
- **Appendix B**: Tool outputs and logs
- **Appendix C**: References and resources
- **Appendix D**: Testing timeline

---

## Submission Requirements

### Deliverables

1. **Penetration Testing Report (PDF)**:
   - Professional formatting
   - Cover page with your name, date, title
   - Table of contents
   - All sections as outlined above
   - Properly formatted code and screenshots
   - 10-20 pages typical length

2. **Proof of Concept Files (ZIP)**:
   - Python scripts or curl commands used
   - Burp Suite project file (optional)
   - Screenshots and evidence
   - Any exploitation tools created

### Format Requirements

- **Document**: PDF format, professional appearance
- **Code**: Syntax highlighted, properly formatted
- **Screenshots**: Clear, annotated with explanations
- **File Naming**: `Module04_Assignment3_[YourName].pdf`
- **Submission**: Upload to Google Drive per course guidelines

---

## Evaluation Criteria

### Reconnaissance and Discovery (15 points)

- **Thoroughness** (8 points): Comprehensive API endpoint discovery
- **Documentation** (7 points): Clear documentation of API structure and technology stack

### Vulnerability Identification (35 points)

- **Quantity** (10 points): Number of unique vulnerabilities found (minimum 5)
- **Diversity** (10 points): Coverage across different OWASP categories
- **Accuracy** (10 points): Correct identification and classification
- **Severity Assessment** (5 points): Appropriate risk ratings

### Exploitation and Proof of Concept (25 points)

- **Reproducibility** (10 points): Clear, reproducible steps
- **Evidence Quality** (10 points): Screenshots, requests/responses, clear documentation
- **Technical Depth** (5 points): Understanding of exploitation techniques

### Report Quality (20 points)

- **Executive Summary** (5 points): Clear, concise, actionable for management
- **Technical Writing** (7 points): Clear explanations, proper terminology
- **Remediation Recommendations** (5 points): Specific, actionable fixes
- **Professionalism** (3 points): Formatting, grammar, organization

### Bonus Points (5 points)

- **Advanced Exploitation** (up to 3 points): Creative or advanced attack techniques
- **Automated Tools** (up to 2 points): Custom scripts for testing
- **Video Demonstration** (up to 2 points): Video proof of concept

### Total: 100 points (+ up to 7 bonus)

---

## Severity Rating Guidelines

Use the following criteria to assess severity:

### Critical

- Remote code execution
- Complete authentication bypass
- Access to all user data
- Admin account takeover

### High

- Access to sensitive data of multiple users
- Privilege escalation
- Significant BOLA allowing unauthorized data access
- No rate limiting on authentication

### Medium

- Limited information disclosure
- CSRF on important functions
- Weak password policy
- Missing security headers

### Low

- Information disclosure (non-sensitive)
- Verbose error messages
- Minor CORS issues
- Missing security recommendations

---

## Tips for Success

1. **Start Early**: API testing takes time; don't wait until the deadline
2. **Be Systematic**: Test methodically, document everything as you go
3. **Think Like an Attacker**: Try unexpected inputs and edge cases
4. **Document Everything**: Take screenshots immediately when you find vulnerabilities
5. **Professional Tone**: Write as if reporting to a real client
6. **Prioritize Findings**: Focus on high-impact vulnerabilities first
7. **Test Thoroughly**: Don't stop at the first vulnerability; explore comprehensively
8. **Ask Questions**: If stuck, ask during office hours (but don't share findings publicly)

---

## Tools Reference

### Essential Tools

- **Burp Suite Community/Pro**: <https://portswigger.net/burp>
- **Postman**: <https://www.postman.com/>
- **curl**: Command-line HTTP client (built-in on most systems)
- **jq**: JSON processor for command line

### Optional Tools

- **OWASP ZAP**: <https://www.zaproxy.org/>
- **jwt_tool**: <https://github.com/ticarpi/jwt_tool>
- **Arjun**: API endpoint discovery
- **SQLmap**: SQL injection testing

### Documentation Resources

- **crAPI Challenges**: <https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md>
- **VAmPI Documentation**: Check `/docs` endpoint
- **OWASP API Security Top 10**: <https://owasp.org/API-Security/>

---

## Academic Integrity

- **You must perform your own testing and write your own report**
- You may use automated tools (Burp Suite, SQLmap, etc.)
- You may consult documentation and resources
- **Do not share findings or collaborate on testing**
- **Do not share reports or exploit code with other students**
- Cite any resources or tools used

**This is individual work. Collaboration constitutes plagiarism and will result in academic penalties.**

---

## Important Notes

1. **Test Only Assigned Applications**: Only test crAPI or VAmPI (locally hosted)
2. **Do Not Test Production Systems**: Never test unauthorized applications
3. **Local Environment Only**: All testing must be on your local machine
4. **Ethical Conduct**: This is for educational purposes only
5. **No Real Attacks**: Do not use these techniques on unauthorized systems

**Reminder**: Unauthorized security testing is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---

## Deadline

Refer to the course schedule for the specific deadline. Late submissions will be penalized according to the course policy.

---

## Questions?

If you have questions:

1. Check the application's documentation (GitHub README, `/docs` endpoint)
2. Review Module 04 lecture materials on API security
3. Attend office hours or lab sessions
4. Post general questions (not vulnerabilities or solutions) on the course forum

Good luck with your API security assessment!
