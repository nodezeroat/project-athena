# Module 18 - Assignment 1: Android App Static Analysis

## Objective

Perform a comprehensive static security assessment of an Android application using decompilation tools and manual code review.

## Prerequisites

- jadx installed (`brew install jadx` or from GitHub releases)
- apktool installed (`brew install apktool`)
- Android Studio with emulator (optional, for running the app)
- MobSF running locally (optional, for automated scanning)

## Target Application

Use one of the following intentionally vulnerable applications:

- **DIVA (Damn Insecure and Vulnerable App)**: <https://github.com/payatu/diva-android>
- **InsecureBankv2**: <https://github.com/dineshshetty/Android-InsecureBankv2>
- **OWASP MSTG Apps**: <https://mas.owasp.org/MASTG/apps/>

## Tasks

### Part 1: APK Extraction and Decompilation (20 points)

1. Obtain the target APK (download or pull from device/emulator)
2. Decompile the APK using jadx and apktool
3. Document the package structure (main packages, key classes)
4. List all third-party libraries identified in the decompiled code

### Part 2: Manifest Analysis (20 points)

Analyze the `AndroidManifest.xml` and document:

1. All permissions requested - classify each as normal, dangerous, or signature
2. All exported components (Activities, Services, Receivers, Content Providers)
3. Security-relevant flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`)
4. Intent filters that could be triggered by external apps
5. Network security configuration (if present)

### Part 3: Data Storage Analysis (20 points)

Search the decompiled source code for:

1. SharedPreferences usage - are sensitive values stored in plaintext?
2. SQLite database usage - is encryption used (e.g., SQLCipher)?
3. External storage usage - is sensitive data written to shared storage?
4. Logging of sensitive data (`Log.d`, `Log.i`, `Log.e` with sensitive content)
5. Hardcoded credentials, API keys, or secrets in source code

### Part 4: Network Security Analysis (15 points)

Examine the network-related code for:

1. HTTP (cleartext) endpoints
2. Certificate validation implementation (custom TrustManagers)
3. Certificate pinning implementation
4. Sensitive data in URL parameters
5. API authentication mechanism

### Part 5: Vulnerability Report (25 points)

Write a professional security assessment report including:

1. **Executive Summary**: Brief overview of findings and overall risk assessment
2. **Findings Table**: List all vulnerabilities with severity (Critical/High/Medium/Low/Info)
3. **Detailed Findings**: For each vulnerability:
   - Description
   - Affected MASVS requirement
   - Location in code (file and line number)
   - Evidence (code snippet or screenshot)
   - Impact
   - Remediation recommendation
4. **Conclusion**: Summary and prioritized remediation roadmap

## Deliverables

- Vulnerability report (PDF or Markdown)
- Screenshots of key findings
- Any scripts used during analysis

## Grading Rubric

| **Criteria** | **Points** |
| --- | --- |
| APK structure documentation | 20 |
| Manifest analysis completeness | 20 |
| Data storage findings | 20 |
| Network security analysis | 15 |
| Report quality and professionalism | 25 |
| **Total** | **100** |
