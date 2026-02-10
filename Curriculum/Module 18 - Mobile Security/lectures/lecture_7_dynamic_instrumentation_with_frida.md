# Dynamic Instrumentation with Frida

Frida is the most powerful and widely used dynamic instrumentation toolkit for mobile security testing. It allows you to inject JavaScript into running processes to hook functions, modify behavior, bypass security controls, and inspect runtime data - all without modifying the application binary. This lecture provides a comprehensive guide to using Frida for both Android and iOS security assessment.

## What is Dynamic Instrumentation?

Dynamic instrumentation is the process of modifying a program's behavior at runtime without altering its binary on disk. Unlike static analysis (examining code without execution) or patching (modifying the binary), dynamic instrumentation works by injecting code into a running process.

**Comparison of Approaches:**

| **Technique** | **Modifies Binary?** | **Requires Repackaging?** | **Runtime Interaction?** |
| --- | --- | --- | --- |
| Static Analysis | No | No | No |
| Smali Patching | Yes | Yes | No |
| Dynamic Instrumentation | No | No | Yes (live) |
| Debugging (JDWP/LLDB) | No | Sometimes | Yes (breakpoints) |

**Advantages of Dynamic Instrumentation:**

- No need to modify or resign the app
- Interact with the app in real-time
- Inspect encrypted data after decryption
- Bypass security checks without understanding the full implementation
- Works on both Android and iOS with the same JavaScript API

## Frida Architecture

### Components

```text
┌──────────────────────────────────────────────────────┐
│                    Host Machine                      │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ frida CLI    │  │ frida-tools  │  │ Python API │  │
│  │ (REPL)       │  │ (frida-ps,   │  │ (scripting)│  │
│  │              │  │ frida-trace) │  │            │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                 │                 │        │
│         └────────┬────────┴────────┬────────┘        │
│                  │   Frida Core    │                 │
│                  │   (GumJS)       │                 │
│                  └────────┬────────┘                 │
│                           │ USB / Network            │
└───────────────────────────┼──────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────┐
│                    Target Device                     │
│                           │                          │
│                  ┌────────┴────────┐                 │
│                  │  frida-server   │                 │
│                  │  (root daemon)  │                 │
│                  └────────┬────────┘                 │
│                           │                          │
│              ┌────────────┼────────────┐             │
│              ▼            ▼            ▼             │
│         ┌────────┐  ┌────────┐  ┌────────┐           │
│         │ App A  │  │ App B  │  │ App C  │           │
│         │ (agent │  │        │  │ (agent │           │
│         │  .js)  │  │        │  │  .js)  │           │
│         └────────┘  └────────┘  └────────┘           │
└──────────────────────────────────────────────────────┘
```

### How Frida Works

1. **frida-server** runs as root on the target device
2. Host connects to frida-server via USB or network
3. When you target a process, Frida injects its **agent** (a shared library) into the process
4. The agent creates a JavaScript runtime (V8/QuickJS) inside the target process
5. Your JavaScript code runs within the target process's memory space
6. Frida's core engine (**Gum**) provides the hooking primitives

### Injection Modes

| **Mode** | **Command Flag** | **Description** |
| --- | --- | --- |
| Attach | (default) | Attach to a running process |
| Spawn | `-f` | Start the app and pause before execution begins |
| Embedded | N/A | Agent bundled into the app (gadget mode) |

**Spawn mode is preferred** for security testing because it allows you to hook functions before the app's initialization code runs (important for bypassing early security checks).

## Setup and Installation

### Host Machine Setup

```bash
# Install Frida tools via pip
pip install frida-tools

# Verify installation
frida --version
# 16.x.x

# List available commands
frida --help
frida-ps --help
frida-trace --help
```

### Android Setup

```bash
# 1. Determine device architecture
adb shell getprop ro.product.cpu.abi
# arm64-v8a (most modern devices)

# 2. Download matching frida-server from GitHub releases
# https://github.com/frida/frida/releases
# Download: frida-server-16.x.x-android-arm64.xz

# 3. Extract and push to device
xz -d frida-server-16.x.x-android-arm64.xz
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# 4. Start frida-server (requires root)
adb shell su -c "/data/local/tmp/frida-server &"

# 5. Verify connection
frida-ps -U
# Lists all running processes on the USB-connected device
```

### iOS Setup (Jailbroken Device)

```bash
# 1. Add Frida repository in Cydia/Sileo
# Repository: https://build.frida.re

# 2. Install "Frida" package from the repository
# This installs frida-server as a daemon

# 3. Verify connection
frida-ps -U
# Lists all running processes
```

### iOS Setup (Non-Jailbroken - Frida Gadget)

For non-jailbroken devices, embed Frida as a dynamic library:

```bash
# 1. Download Frida gadget
# frida-gadget-16.x.x-ios-universal.dylib.xz

# 2. Inject into the IPA using insert_dylib or optool
optool install -c load -p "@executable_path/FridaGadget.dylib" \
    -t Payload/AppName.app/AppName

# 3. Copy FridaGadget.dylib into the app bundle
cp FridaGadget.dylib Payload/AppName.app/

# 4. Resign and install
# Requires valid Apple Developer certificate
```

## Frida CLI Basics

### Essential Commands

```bash
# List running processes on USB device
frida-ps -U

# List installed applications
frida-ps -Ua    # Running apps
frida-ps -Uai   # All installed apps (includes package names)

# Attach to a running app
frida -U "App Name"
frida -U com.example.app          # By package name
frida -U -p 1234                  # By PID

# Spawn and attach (preferred for security testing)
frida -U -f com.example.app       # Spawns app paused
# Type %resume in the REPL to continue execution

# Load a script file
frida -U -f com.example.app -l hook_script.js

# Load script and auto-resume
frida -U -f com.example.app -l hook_script.js --no-pause
```

### Frida REPL (Interactive Mode)

```javascript
// Once attached, you're in a JavaScript REPL

// List loaded modules (libraries)
Process.enumerateModules()

// Find a specific module
Module.findBaseAddress("libnative.so")

// Search memory for a string
Memory.scan(Module.findBaseAddress("libnative.so"), 0x10000,
    "41 50 49 5f 4b 45 59", {  // "API_KEY" in hex
        onMatch: function(address, size) {
            console.log("Found at:", address);
        },
        onComplete: function() { console.log("Scan complete"); }
    });
```

## Frida JavaScript API

### The Interceptor API

The Interceptor is the primary API for hooking functions:

```javascript
// Hook a function by address
Interceptor.attach(targetAddress, {
    // Called BEFORE the original function
    onEnter: function(args) {
        console.log("Function called!");
        console.log("Arg 0:", args[0]);
        console.log("Arg 1:", args[1]);

        // Modify arguments
        args[0] = ptr("0x1234");
    },

    // Called AFTER the original function returns
    onLeave: function(retval) {
        console.log("Return value:", retval);

        // Modify return value
        retval.replace(ptr("0x1"));
    }
});
```

### Hooking Java Methods (Android)

```javascript
// The Java bridge - access to all Java classes
Java.perform(function() {

    // Find and hook a Java class
    var LoginActivity = Java.use("com.example.app.LoginActivity");

    // Hook an instance method
    LoginActivity.validatePassword.implementation = function(password) {
        console.log("[*] validatePassword called with: " + password);

        // Call the original method
        var result = this.validatePassword(password);
        console.log("[*] Original result: " + result);

        // Override return value
        return true;
    };

    // Hook a static method
    var CryptoUtils = Java.use("com.example.app.utils.CryptoUtils");
    CryptoUtils.encrypt.implementation = function(plaintext, key) {
        console.log("[*] encrypt() called");
        console.log("[*]   plaintext: " + plaintext);
        console.log("[*]   key: " + key);

        var result = this.encrypt(plaintext, key);
        console.log("[*]   ciphertext: " + result);
        return result;
    };

    // Hook constructor
    LoginActivity.$init.implementation = function() {
        console.log("[*] LoginActivity created");
        this.$init();
    };
});
```

### Hooking Overloaded Methods

```javascript
Java.perform(function() {
    var MyClass = Java.use("com.example.app.MyClass");

    // When a method has multiple overloads, specify parameter types
    MyClass.process.overload("java.lang.String").implementation = function(str) {
        console.log("[*] process(String) called: " + str);
        return this.process(str);
    };

    MyClass.process.overload("java.lang.String", "int").implementation = function(str, num) {
        console.log("[*] process(String, int) called: " + str + ", " + num);
        return this.process(str, num);
    };

    MyClass.process.overload("[B").implementation = function(bytes) {
        console.log("[*] process(byte[]) called");
        // Convert byte array to hex string
        var hexStr = "";
        for (var i = 0; i < bytes.length; i++) {
            hexStr += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("[*]   hex: " + hexStr);
        return this.process(bytes);
    };
});
```

### Hooking Objective-C Methods (iOS)

```javascript
// Objective-C runtime access
if (ObjC.available) {

    // Hook an instance method
    var LoginVC = ObjC.classes.LoginViewController;

    Interceptor.attach(LoginVC["- validateCredentials"].implementation, {
        onEnter: function(args) {
            // args[0] = self, args[1] = _cmd (selector)
            console.log("[*] validateCredentials called");
            console.log("[*] self: " + ObjC.Object(args[0]));
        },
        onLeave: function(retval) {
            console.log("[*] Result: " + retval);
            // Force return true
            retval.replace(ptr(0x1));
        }
    });

    // Hook a class method
    Interceptor.attach(ObjC.classes.NSURLSession["+ sharedSession"].implementation, {
        onEnter: function(args) {
            console.log("[*] NSURLSession.sharedSession called");
        }
    });

    // Resolve a method by selector
    var isJailbroken = LoginVC["- isJailbroken"];
    Interceptor.attach(isJailbroken.implementation, {
        onLeave: function(retval) {
            console.log("[*] isJailbroken returned: " + retval);
            retval.replace(ptr(0x0));  // Return NO
            console.log("[*] Replaced with: false");
        }
    });
}
```

### Working with Data Types

```javascript
Java.perform(function() {

    // Reading String arguments
    var StringClass = Java.use("java.lang.String");

    // Creating Java objects from JavaScript
    var javaString = StringClass.$new("Hello from Frida!");

    // Working with byte arrays
    var bytes = Java.array("byte", [0x48, 0x65, 0x6c, 0x6c, 0x6f]);

    // Converting byte[] to String
    var str = StringClass.$new(bytes, "UTF-8");
    console.log("String: " + str);

    // Accessing enums
    var MyEnum = Java.use("com.example.app.MyEnum");
    console.log("Enum value: " + MyEnum.VALUE_A.value);

    // Working with arrays
    var ArrayList = Java.use("java.util.ArrayList");
    var list = ArrayList.$new();
    list.add("item1");
    list.add("item2");
    console.log("List size: " + list.size());

    // Casting objects
    Java.cast(someObject, Java.use("com.example.TargetType"));
});
```

### Enumerating Classes and Methods

```javascript
Java.perform(function() {

    // List all loaded classes matching a pattern
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("com.example.app")) {
                console.log("[*] Class: " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });

    // List all methods of a class
    var targetClass = Java.use("com.example.app.SecurityManager");
    var methods = targetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log("[*] Method: " + method.getName());
    });

    // List all fields of a class
    var fields = targetClass.class.getDeclaredFields();
    fields.forEach(function(field) {
        console.log("[*] Field: " + field.getName() + " : " + field.getType());
    });
});
```

### Finding and Manipulating Live Objects

```javascript
Java.perform(function() {

    // Find all instances of a class in the heap
    Java.choose("com.example.app.UserSession", {
        onMatch: function(instance) {
            console.log("[*] Found UserSession instance");
            console.log("[*]   Token: " + instance.getToken());
            console.log("[*]   UserId: " + instance.getUserId());
            console.log("[*]   IsAdmin: " + instance.isAdmin());

            // Modify the live object
            instance.setAdmin(true);
            console.log("[*]   IsAdmin (modified): " + instance.isAdmin());
        },
        onComplete: function() {
            console.log("[*] Heap search complete");
        }
    });
});
```

## Practical: SSL Pinning Bypass

SSL/Certificate pinning bypass is one of the most common uses of Frida in mobile security testing.

### Android SSL Pinning Bypass

#### Method 1: Hook TrustManager (Generic)

```javascript
Java.perform(function() {

    // Bypass custom TrustManager implementations
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // Create a TrustManager that trusts everything
    var TrustManager = Java.registerClass({
        name: "com.frida.TrustAllManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) { },
            checkServerTrusted: function(chain, authType) { },
            getAcceptedIssuers: function() { return []; }
        }
    });

    // Replace the default SSLContext
    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, TrustManagers, null);

    console.log("[*] Custom TrustManager installed");
});
```

#### Method 2: Hook OkHttp CertificatePinner

```javascript
Java.perform(function() {
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCertificates) {
            console.log("[*] OkHttp pinning bypassed for: " + hostname);
            // Do nothing - skip the pin check
        };
    } catch(e) {
        console.log("[-] OkHttp not found: " + e);
    }
});
```

#### Method 3: Hook Network Security Config

```javascript
Java.perform(function() {
    try {
        // Android 7+ network security config
        var NetworkSecurityTrustManager = Java.use(
            "android.security.net.config.NetworkSecurityTrustManager"
        );
        NetworkSecurityTrustManager.checkServerTrusted.implementation =
            function(chain, authType, engine) {
            console.log("[*] NetworkSecurityConfig pinning bypassed");
        };
    } catch(e) {
        console.log("[-] NetworkSecurityTrustManager not found");
    }
});
```

### iOS SSL Pinning Bypass

```javascript
if (ObjC.available) {
    // Method 1: Hook NSURLSession delegate
    var resolver = new ApiResolver("objc");

    resolver.enumerateMatches(
        "-[* URLSession:didReceiveChallenge:completionHandler:]", {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    // args[4] = completionHandler block
                    var dominated = new ObjC.Block(args[4]);
                    // Call completion with UseCredential disposition
                    var dominated_impl = dominated.implementation;
                    dominated.implementation = function(disposition, credential) {
                        dominated_impl(0, credential); // 0 = UseCredential
                    };
                }
            });
        },
        onComplete: function() {}
    });

    // Method 2: Hook SecTrustEvaluateWithError
    var SecTrustEvaluateWithError = Module.findExportByName(
        "Security", "SecTrustEvaluateWithError"
    );
    if (SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onLeave: function(retval) {
                retval.replace(ptr(0x1)); // Return true (trusted)
                console.log("[*] SecTrustEvaluateWithError bypassed");
            }
        });
    }

    console.log("[*] iOS SSL pinning bypass active");
}
```

## Practical: Root/Jailbreak Detection Bypass

### Android Root Detection Bypass

```javascript
Java.perform(function() {

    // Method 1: Hook common root detection methods
    var RootDetection = Java.use("com.example.app.security.RootDetection");
    RootDetection.isDeviceRooted.implementation = function() {
        console.log("[*] Root detection bypassed");
        return false;
    };

    // Method 2: Hook file existence checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = [
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su",
            "/su/bin/su", "/system/app/Magisk"
        ];

        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log("[*] Hiding root file: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // Method 3: Hook Runtime.exec (su command check)
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Blocked command: " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };

    // Method 4: Hook SafetyNet / Play Integrity
    try {
        var SafetyNet = Java.use(
            "com.google.android.gms.safetynet.SafetyNetClient"
        );
        SafetyNet.attest.implementation = function(nonce, apiKey) {
            console.log("[*] SafetyNet attestation intercepted");
            return this.attest(nonce, apiKey);
        };
    } catch(e) {
        console.log("[-] SafetyNet not found");
    }
});
```

### iOS Jailbreak Detection Bypass

```javascript
if (ObjC.available) {

    // Hook FileManager.fileExistsAtPath
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var jailbreakPaths = [
                "/Applications/Cydia.app",
                "/Applications/Sileo.app",
                "/usr/sbin/sshd",
                "/usr/bin/ssh",
                "/etc/apt",
                "/var/jb",
                "/var/lib/cydia",
                "/usr/lib/TweakInject"
            ];

            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                    console.log("[*] Hiding jailbreak file: " + this.path);
                    retval.replace(ptr(0x0));
                    return;
                }
            }
        }
    });

    // Hook canOpenURL (cydia:// check)
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf("cydia") !== -1 ||
                this.url.indexOf("sileo") !== -1) {
                console.log("[*] Hiding URL scheme: " + this.url);
                retval.replace(ptr(0x0));
            }
        }
    });

    // Hook fork() - jailbreak detection via sandbox check
    var fork_ptr = Module.findExportByName(null, "fork");
    if (fork_ptr) {
        Interceptor.attach(fork_ptr, {
            onLeave: function(retval) {
                retval.replace(ptr(-1)); // Return -1 (fork failed)
                console.log("[*] fork() blocked for jailbreak detection");
            }
        });
    }
}
```

## Practical: Intercepting Encryption

```javascript
Java.perform(function() {

    // Hook javax.crypto.Cipher
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[*] Cipher.getInstance: " + algo);
        return this.getInstance(algo);
    };

    Cipher.init.overload("int", "java.security.Key").implementation = function(mode, key) {
        var modeStr = (mode === 1) ? "ENCRYPT" : "DECRYPT";
        console.log("[*] Cipher.init mode=" + modeStr);

        // Extract the key bytes
        var keyBytes = key.getEncoded();
        console.log("[*]   Key: " + bytesToHex(keyBytes));

        return this.init(mode, key);
    };

    Cipher.doFinal.overload("[B").implementation = function(data) {
        console.log("[*] Cipher.doFinal");
        console.log("[*]   Input (" + data.length + " bytes): " + bytesToHex(data));

        var result = this.doFinal(data);
        console.log("[*]   Output (" + result.length + " bytes): " + bytesToHex(result));

        return result;
    };
});

// Helper function
function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

## Practical: Bypassing Anti-Debugging

```javascript
Java.perform(function() {

    // Hook Debug.isDebuggerConnected
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[*] isDebuggerConnected bypassed");
        return false;
    };

    // Hook TracerPid check via /proc/self/status
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line && line.indexOf("TracerPid") !== -1) {
            console.log("[*] TracerPid check intercepted");
            return "TracerPid:\t0";
        }
        return line;
    };
});
```

## frida-trace: Quick Function Tracing

`frida-trace` automatically generates hook scripts for matching functions:

```bash
# Trace all methods in a class (Android)
frida-trace -U -f com.example.app -j "com.example.app.security.*!*"

# Trace specific method
frida-trace -U -f com.example.app -j "com.example.app.LoginActivity!validatePassword"

# Trace native functions
frida-trace -U -f com.example.app -i "open"        # libc open()
frida-trace -U -f com.example.app -i "SSL_*"       # All SSL functions
frida-trace -U -f com.example.app -i "*encrypt*"   # All encrypt-related

# Trace Objective-C methods (iOS)
frida-trace -U -f com.example.app -m "-[LoginVC validateCredentials]"
frida-trace -U -f com.example.app -m "-[* isJailbroken]"
frida-trace -U -f com.example.app -m "+[NSURL *]"

# Generated handlers are in __handlers__/ directory
# Edit them to customize behavior
```

## objection: Frida-Powered Exploration

objection is a runtime exploration toolkit built on Frida:

```bash
# Install
pip install objection

# Connect to running app
objection -g com.example.app explore

# Spawn and connect
objection -g com.example.app explore --startup-command "android sslpinning disable"
```

### Common objection Commands

```bash
# Environment info
> env                              # App paths and directories

# SSL Pinning bypass
> android sslpinning disable       # Android
> ios sslpinning disable           # iOS

# Root/Jailbreak bypass
> android root disable             # Android
> ios jailbreak disable            # iOS

# File system exploration
> ls /data/data/com.example.app/
> file download /path/to/file local_file

# Keychain/Keystore
> ios keychain dump                 # iOS Keychain contents
> android keystore list             # Android KeyStore entries

# Database access
> sqlite connect /path/to/database.db
> .tables
> SELECT * FROM users;

# SharedPreferences
> android hooking list activities
> android hooking list services
> android hooking list receivers

# Hooking
> android hooking watch class com.example.app.SecurityManager
> android hooking watch method com.example.app.SecurityManager.isRooted --dump-args --dump-return

# Search for classes
> android hooking search classes password
> android hooking search methods encrypt

# Memory exploration
> memory list modules
> memory search "API_KEY" --string
```

## Writing Complete Frida Scripts

### Script Template

```javascript
// script.js - Complete Frida script template

// Wait for Java VM to be ready (Android)
Java.perform(function() {
    console.log("[*] Frida script loaded");
    console.log("[*] Process: " + Process.id);

    // ===== SSL Pinning Bypass =====
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, certs) {
            console.log("[SSL] Pinning bypassed for: " + hostname);
        };
    } catch(e) {}

    // ===== Root Detection Bypass =====
    try {
        var RootCheck = Java.use("com.example.app.RootChecker");
        RootCheck.isRooted.implementation = function() {
            console.log("[ROOT] Detection bypassed");
            return false;
        };
    } catch(e) {}

    // ===== Intercept API Calls =====
    try {
        var ApiClient = Java.use("com.example.app.network.ApiClient");
        ApiClient.makeRequest.implementation = function(endpoint, params) {
            console.log("[API] Request to: " + endpoint);
            console.log("[API] Params: " + params);
            var response = this.makeRequest(endpoint, params);
            console.log("[API] Response: " + response);
            return response;
        };
    } catch(e) {}

    // ===== Monitor SharedPreferences =====
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (key.toLowerCase().indexOf("token") !== -1 ||
            key.toLowerCase().indexOf("password") !== -1 ||
            key.toLowerCase().indexOf("key") !== -1) {
            console.log("[PREFS] " + key + " = " + value);
        }
        return value;
    };

    console.log("[*] All hooks installed");
});
```

### Running the Script

```bash
# Spawn app with script
frida -U -f com.example.app -l script.js --no-pause

# Output:
# [*] Frida script loaded
# [*] Process: 12345
# [*] All hooks installed
# [SSL] Pinning bypassed for: api.example.com
# [ROOT] Detection bypassed
# [API] Request to: /api/v1/user/profile
# [API] Params: {"user_id": 42}
# [PREFS] auth_token = eyJhbGciOiJIUzI1NiJ9...
```

### Python Script (Automation)

```python
#!/usr/bin/env python3
"""Automated Frida instrumentation script."""

import frida
import sys

PACKAGE = "com.example.app"

JS_CODE = """
Java.perform(function() {
    var Activity = Java.use("com.example.app.LoginActivity");
    Activity.authenticate.implementation = function(user, pass) {
        send({type: "credentials", user: user, pass: pass});
        return this.authenticate(user, pass);
    };
});
"""

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "credentials":
            print(f"[!] Captured: {payload['user']}:{payload['pass']}")
    elif message["type"] == "error":
        print(f"[ERROR] {message['stack']}")

def main():
    device = frida.get_usb_device()
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)

    script = session.create_script(JS_CODE)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print(f"[*] Attached to {PACKAGE} (PID: {pid})")
    print("[*] Press Ctrl+C to exit")

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        session.detach()
        print("\n[*] Detached")

if __name__ == "__main__":
    main()
```

## Advanced Techniques

### Hooking Native Functions

```javascript
// Hook a native function by name
var openPtr = Module.findExportByName("libc.so", "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("[*] open(" + this.path + ")");
    },
    onLeave: function(retval) {
        console.log("[*]   fd = " + retval);
    }
});

// Hook a function in a specific library
var base = Module.findBaseAddress("libnative.so");
var targetFunc = base.add(0x1234);  // Offset from IDA/Ghidra

Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("[*] Native function called");
        console.log("[*]   arg0: " + args[0]);
        console.log("[*]   arg0 as string: " + args[0].readUtf8String());
        // Read memory
        console.log("[*]   hex dump: " + hexdump(args[1], {length: 64}));
    }
});
```

### Replacing Function Implementations

```javascript
// Completely replace a native function
var targetAddr = Module.findExportByName("libnative.so", "verify_license");

Interceptor.replace(targetAddr, new NativeCallback(function(arg0, arg1) {
    console.log("[*] verify_license() → returning 1 (valid)");
    return 1;
}, "int", ["pointer", "int"]));
```

### Memory Reading and Writing

```javascript
// Read memory at an address
var addr = ptr("0x12345678");
console.log(addr.readU32());           // Read 32-bit unsigned int
console.log(addr.readUtf8String());    // Read null-terminated string
console.log(addr.readByteArray(16));   // Read 16 bytes

// Write memory
addr.writeU32(0x41414141);
addr.writeUtf8String("modified");

// Hex dump
console.log(hexdump(addr, {
    offset: 0,
    length: 128,
    header: true,
    ansi: true
}));

// Allocate memory and write data
var buf = Memory.alloc(256);
buf.writeUtf8String("Frida was here");
```

## Frida Detection and Evasion

Some apps attempt to detect Frida:

### Common Detection Methods

1. **Port scanning**: Check for frida-server's default port (27042)
2. **Named pipes**: Check for frida-related named pipes in `/proc/self/fd/`
3. **Library detection**: Check for `frida-agent` in loaded modules
4. **Thread detection**: Look for Frida's characteristic thread names
5. **Memory scanning**: Search for Frida strings in process memory

### Anti-Detection Techniques

```bash
# Change frida-server port
/data/local/tmp/frida-server -l 0.0.0.0:1337

# Connect on custom port
frida -H 192.168.1.100:1337 com.example.app

# Rename frida-server binary
cp frida-server hluda-server
./hluda-server &
```

```javascript
// Hook detection methods
Java.perform(function() {
    // Hide frida-server port
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
        if (port === 27042) {
            console.log("[*] Blocked connection to Frida port");
            throw Java.use("java.io.IOException").$new("Connection refused");
        }
        return this.$init(host, port);
    };
});
```

## Key Takeaways

- Frida is the most versatile tool for mobile dynamic analysis, working on both Android and iOS
- The `Java.perform()` bridge provides full access to the Java/Kotlin runtime on Android
- The `ObjC.classes` bridge provides access to the Objective-C runtime on iOS
- SSL pinning bypass is essential for traffic interception during testing
- Root/jailbreak detection can be systematically bypassed by hooking detection functions
- Frida allows intercepting encryption operations to see plaintext data
- Combine static analysis (to identify targets) with dynamic instrumentation (to modify behavior)
- objection provides a convenient command-line interface for common Frida tasks
- Python scripts enable automated and reproducible instrumentation workflows
- Frida spawn mode (`-f`) ensures hooks are active before the app's initialization code runs

## Resources

- Frida Official Documentation: <https://frida.re/docs/>
- Frida JavaScript API Reference: <https://frida.re/docs/javascript-api/>
- Frida CodeShare (Community Scripts): <https://codeshare.frida.re/>
- objection: <https://github.com/sensepost/objection>
- OWASP MASTG - Dynamic Analysis: <https://mas.owasp.org/MASTG/techniques/>
- Frida Handbook: <https://learnfrida.info/>
- Awesome Frida: <https://github.com/dweinstein/awesome-frida>
- Android SSL Pinning Bypass Scripts: <https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/>
