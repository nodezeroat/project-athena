# Module 18 - Assignment 2: Dynamic Instrumentation with Frida

## Objective

Use Frida to perform dynamic analysis on an Android application. You will hook into running app functions, bypass security mechanisms, intercept sensitive data, and demonstrate runtime manipulation techniques.

## Prerequisites

- Python 3 with `frida-tools` and `objection` installed
- Android emulator (rooted) or rooted physical device
- frida-server running on the target device
- Burp Suite (Community Edition) for traffic interception
- Target app installed on the device
- Completion of Assignment 1 (static analysis) recommended

## Setup Verification

Before starting, verify your environment:

```bash
# Host machine
frida --version
objection version

# Device connection
frida-ps -U              # Should list device processes
frida-ps -Uai            # Should list installed apps
```

## Target Application

Use the same intentionally vulnerable app from Assignment 1, or one of:

- **DIVA (Damn Insecure and Vulnerable App)**
- **InsecureBankv2**
- **OWASP UnCrackable-Level1**: <https://mas.owasp.org/MASTG/apps/>

## Tasks

### Part 1: Reconnaissance with Frida and objection (15 points)

1. Connect to the target app using objection:

   ```bash
   objection -g <package_name> explore
   ```

2. Document the following:
   - App environment paths (`env` command)
   - List of Activities, Services, and Receivers
   - Contents of SharedPreferences
   - Contents of any SQLite databases
   - Any Keystore entries

3. Use Frida to enumerate loaded classes matching the app's package:

   ```javascript
   Java.perform(function() {
       Java.enumerateLoadedClasses({
           onMatch: function(className) {
               if (className.includes("<package>")) {
                   console.log(className);
               }
           },
           onComplete: function() {}
       });
   });
   ```

### Part 2: SSL Pinning Bypass and Traffic Interception (20 points)

1. Configure Burp Suite as a proxy for the device
2. Attempt to intercept HTTPS traffic (document any failures due to pinning)
3. Write a Frida script to bypass SSL certificate pinning
4. Successfully intercept and document at least 3 API requests/responses
5. Identify any sensitive data transmitted in the API calls

### Part 3: Authentication Bypass (20 points)

1. Identify the authentication-related classes and methods through static analysis
2. Write a Frida script that hooks the login/authentication method
3. Log the credentials as they are processed
4. Modify the return value to bypass authentication (e.g., force `isAuthenticated()` to return `true`)
5. Document the before/after behavior with screenshots

### Part 4: Security Mechanism Bypass (20 points)

Choose at least TWO of the following and write Frida scripts to bypass them:

#### Option A: Root Detection Bypass

- Identify root detection methods in the app
- Write a Frida script to bypass all root checks
- Verify the app runs normally on a rooted device after bypass

#### Option B: Encryption Interception

- Identify encryption methods used by the app
- Hook `javax.crypto.Cipher` or equivalent to log:
  - Algorithm used
  - Encryption key (hex encoded)
  - Plaintext input
  - Ciphertext output
- Document at least one encryption operation

#### Option C: Runtime Data Modification

- Find a class that holds user session or profile data
- Use `Java.choose()` to find live instances on the heap
- Modify runtime values (e.g., change user role, balance, or permissions)
- Document the impact of the modification

#### Option D: Anti-Debugging Bypass

- Identify anti-debugging mechanisms
- Write a Frida script to bypass debug detection
- Verify the app no longer detects the instrumentation

### Part 5: Comprehensive Frida Script (25 points)

Create a single, well-documented Frida script (`assessment.js`) that combines multiple hooks:

Requirements:

1. The script must include at least 4 different hooks
2. Each hook must have a clear comment explaining its purpose
3. The script must use `console.log` with clear prefixed tags (e.g., `[SSL]`, `[AUTH]`, `[CRYPTO]`)
4. The script must handle errors gracefully (try/catch for optional hooks)
5. The script must work when loaded with:

   ```bash
   frida -U -f <package_name> -l assessment.js --no-pause
   ```

6. Include a Python wrapper script that automates the Frida session and saves output to a log file

## Deliverables

1. **Report** (PDF or Markdown) documenting:
   - Each task performed with methodology and results
   - Screenshots showing successful hooks and bypasses
   - Frida console output for each task
2. **Frida scripts**:
   - Individual scripts for each task (Part 2, 3, 4)
   - Combined `assessment.js` script (Part 5)
   - Python automation script (Part 5)
3. **Captured data**:
   - Intercepted API traffic (Burp Suite export or screenshots)
   - Logged credentials and encryption keys

## Grading Rubric

| **Criteria** | **Points** |
| --- | --- |
| Reconnaissance and enumeration | 15 |
| SSL pinning bypass and traffic analysis | 20 |
| Authentication bypass | 20 |
| Security mechanism bypasses (2 of 4) | 20 |
| Comprehensive script quality and documentation | 25 |
| **Total** | **100** |

## Bonus Challenges (+15 points)

- **+5 points**: Bypass Frida detection if the app implements it
- **+5 points**: Hook native (JNI) functions in addition to Java methods
- **+5 points**: Create a Frida script that automatically dumps all SharedPreferences, databases, and Keychain/Keystore entries on app launch

## Important Notes

- This assignment is for **educational purposes** in an authorized testing environment only
- Only test on applications you have explicit permission to analyze
- Never use these techniques on production applications without written authorization
- Document your methodology thoroughly - the process is as important as the result
