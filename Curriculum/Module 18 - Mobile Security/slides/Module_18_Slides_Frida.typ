#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Dynamic Instrumentation with Frida],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "What is Dynamic Instrumentation?")

#slide(title: "Dynamic Instrumentation")[
  Modifying program behavior *at runtime* without altering the binary.

  #table(
    columns: (auto, auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Technique*], [*Modifies Binary?*], [*Repackaging?*], [*Live?*],
    [Static Analysis], [No], [No], [No],
    [Smali Patching], [Yes], [Yes], [No],
    [Dynamic Instrumentation], [No], [No], [Yes],
    [Debugging (JDWP)], [No], [Sometimes], [Yes],
  )

  *Advantages:*
  - No need to modify or resign the app
  - Real-time interaction with the running app
  - Inspect encrypted data after decryption
  - Same JavaScript API for Android and iOS
]

#section-slide(title: "Frida Architecture")

#slide(title: "How Frida Works")[
  ```text
  Host Machine              Target Device
  ┌──────────────┐          ┌──────────────┐
  │ frida CLI    │   USB/   │ frida-server │
  │ Python API   │ ◄──────► │ (root)       │
  │ frida-tools  │ Network  │              │
  └──────────────┘          │   ┌──────┐   │
                            │   │ App  │   │
                            │   │(agent│   │
                            │   │ .js) │   │
                            │   └──────┘   │
                            └──────────────┘
  ```

  1. frida-server runs as root on device
  2. Host connects via USB or network
  3. Frida injects agent (shared library) into target process
  4. Agent creates JavaScript runtime inside the process
  5. Your JS code runs within the target's memory space
]

#slide(title: "Injection Modes")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Mode*], [*Flag*], [*Description*],
    [Attach], [(default)], [Connect to running process],
    [Spawn], [`-f`], [Start app paused, hook before init],
    [Gadget], [N/A], [Agent embedded in app binary],
  )

  *Spawn mode (`-f`) is preferred* for security testing:
  - Hooks active before app initialization code runs
  - Essential for bypassing early security checks
  - Anti-tamper, root detection, pinning setup
]

#section-slide(title: "Setup")

#slide(title: "Installation")[
  *Host Machine:*
  ```bash
  pip install frida-tools
  frida --version
  ```

  *Android Device (rooted):*
  ```bash
  adb shell getprop ro.product.cpu.abi  # arm64-v8a
  # Download matching frida-server from GitHub
  adb push frida-server /data/local/tmp/
  adb shell chmod 755 /data/local/tmp/frida-server
  adb shell su -c "/data/local/tmp/frida-server &"
  ```

  *iOS Device (jailbroken):*
  - Add repo: `https://build.frida.re`
  - Install "Frida" package from Cydia/Sileo
]

#slide(title: "Essential CLI Commands")[
  ```bash
  # List processes on device
  frida-ps -U          # Running processes
  frida-ps -Uai        # All installed apps

  # Attach to running app
  frida -U com.example.app

  # Spawn and attach (preferred)
  frida -U -f com.example.app

  # Load a script file
  frida -U -f com.example.app -l script.js

  # Auto-resume after spawning
  frida -U -f com.example.app -l script.js \
    --no-pause
  ```

  In REPL: `%resume` to continue app execution
]

#section-slide(title: "Frida JavaScript API")

#slide(title: "The Interceptor API")[
  Core API for hooking functions:

  ```javascript
  Interceptor.attach(targetAddress, {
    // Called BEFORE the original function
    onEnter: function(args) {
      console.log("Arg 0:", args[0]);
      // Modify arguments
      args[0] = ptr("0x1234");
    },
    // Called AFTER the function returns
    onLeave: function(retval) {
      console.log("Return:", retval);
      // Modify return value
      retval.replace(ptr("0x1"));
    }
  });
  ```
]

#slide(title: "Hooking Java Methods (Android)")[
  ```javascript
  Java.perform(function() {
    var LoginActivity = Java.use(
      "com.example.app.LoginActivity"
    );

    LoginActivity.validatePassword
      .implementation = function(password) {
      console.log("[*] Password: " + password);

      // Call original method
      var result = this.validatePassword(password);
      console.log("[*] Result: " + result);

      // Override: always return true
      return true;
    };
  });
  ```
]

#slide(title: "Hooking Overloaded Methods")[
  When a method has multiple signatures:

  ```javascript
  Java.perform(function() {
    var MyClass = Java.use("com.example.MyClass");

    // Specify parameter types
    MyClass.process
      .overload("java.lang.String")
      .implementation = function(str) {
        console.log("process(String): " + str);
        return this.process(str);
      };

    MyClass.process
      .overload("java.lang.String", "int")
      .implementation = function(str, num) {
        console.log("process(String,int)");
        return this.process(str, num);
      };
  });
  ```
]

#slide(title: "Hooking Objective-C Methods (iOS)")[
  ```javascript
  if (ObjC.available) {
    var LoginVC = ObjC.classes.LoginViewController;

    Interceptor.attach(
      LoginVC["- isJailbroken"].implementation, {
      onLeave: function(retval) {
        console.log("[*] isJailbroken: " + retval);
        retval.replace(ptr(0x0)); // Return NO
        console.log("[*] Bypassed!");
      }
    });

    Interceptor.attach(
      LoginVC["- validateCredentials"].implementation,
      {
      onEnter: function(args) {
        // args[0]=self, args[1]=_cmd
        console.log("[*] Validate called");
      }
    });
  }
  ```
]

#section-slide(title: "Practical: SSL Pinning Bypass")

#slide(title: "Android SSL Pinning Bypass")[
  *Hook OkHttp CertificatePinner:*

  ```javascript
  Java.perform(function() {
    var CertificatePinner = Java.use(
      "okhttp3.CertificatePinner"
    );
    CertificatePinner.check
      .overload("java.lang.String",
                "java.util.List")
      .implementation = function(hostname, certs) {
        console.log("[SSL] Bypassed: " + hostname);
        // Skip the pin check entirely
      };
  });
  ```

  Also hook: `X509TrustManager`, `NetworkSecurityTrustManager`
]

#slide(title: "iOS SSL Pinning Bypass")[
  ```javascript
  if (ObjC.available) {
    // Hook SecTrustEvaluateWithError
    var func = Module.findExportByName(
      "Security", "SecTrustEvaluateWithError"
    );
    if (func) {
      Interceptor.attach(func, {
        onLeave: function(retval) {
          retval.replace(ptr(0x1)); // trusted
          console.log("[SSL] Bypassed");
        }
      });
    }
  }
  ```

  *Easiest method:*
  ```bash
  objection -g com.app explore
  > ios sslpinning disable
  ```
]

#section-slide(title: "Practical: Root/Jailbreak Bypass")

#slide(title: "Android Root Detection Bypass")[
  ```javascript
  Java.perform(function() {
    // Hook detection method directly
    var RootDetect = Java.use(
      "com.example.security.RootDetection"
    );
    RootDetect.isDeviceRooted
      .implementation = function() {
        console.log("[ROOT] Bypassed");
        return false;
      };

    // Hook file existence checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
      var path = this.getAbsolutePath();
      if (path.indexOf("su") !== -1 ||
          path.indexOf("Superuser") !== -1) {
        return false; // Hide root files
      }
      return this.exists();
    };
  });
  ```
]

#slide(title: "iOS Jailbreak Detection Bypass")[
  ```javascript
  if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(
      NSFileManager["- fileExistsAtPath:"]
        .implementation, {
      onEnter: function(args) {
        this.path = ObjC.Object(args[2]).toString();
      },
      onLeave: function(retval) {
        if (this.path.indexOf("Cydia") !== -1 ||
            this.path.indexOf("ssh") !== -1 ||
            this.path.indexOf("jb") !== -1) {
          retval.replace(ptr(0x0)); // Not found
        }
      }
    });
  }
  ```
]

#section-slide(title: "Practical: Intercepting Encryption")

#slide(title: "Hooking javax.crypto.Cipher")[
  ```javascript
  Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.doFinal.overload("[B")
      .implementation = function(data) {
      console.log("[CRYPTO] Input: "
        + bytesToHex(data));

      var result = this.doFinal(data);
      console.log("[CRYPTO] Output: "
        + bytesToHex(result));

      return result;
    };
  });

  function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += ("0" + (bytes[i] & 0xFF)
        .toString(16)).slice(-2);
    }
    return hex;
  }
  ```
]

#section-slide(title: "Exploring with objection")

#slide(title: "objection: Frida-Powered Toolkit")[
  ```bash
  pip install objection

  # Connect to app
  objection -g com.example.app explore

  # Common commands:
  > env                       # App paths
  > android sslpinning disable
  > ios sslpinning disable
  > android root disable
  > ios jailbreak disable
  > ios keychain dump
  > android keystore list

  # Hooking
  > android hooking watch class \
    com.example.SecurityManager
  > android hooking search classes password
  > memory search "API_KEY" --string
  ```
]

#section-slide(title: "Advanced Techniques")

#slide(title: "Finding Live Objects on the Heap")[
  ```javascript
  Java.perform(function() {
    Java.choose("com.example.UserSession", {
      onMatch: function(instance) {
        console.log("[*] Found session:");
        console.log("  Token: "
          + instance.getToken());
        console.log("  Admin: "
          + instance.isAdmin());

        // Modify the live object!
        instance.setAdmin(true);
      },
      onComplete: function() {
        console.log("[*] Heap search done");
      }
    });
  });
  ```

  `Java.choose()` finds all instances of a class in memory.
]

#slide(title: "Hooking Native Functions")[
  ```javascript
  // Hook libc open()
  var openPtr = Module.findExportByName(
    "libc.so", "open"
  );
  Interceptor.attach(openPtr, {
    onEnter: function(args) {
      console.log("open("
        + args[0].readUtf8String() + ")");
    }
  });

  // Hook function in native library by offset
  var base = Module.findBaseAddress("libnative.so");
  var func = base.add(0x1234); // From Ghidra/IDA

  Interceptor.attach(func, {
    onEnter: function(args) {
      console.log(hexdump(args[0], {length: 64}));
    }
  });
  ```
]

#slide(title: "frida-trace: Quick Tracing")[
  ```bash
  # Trace all methods in a Java class
  frida-trace -U -f com.app \
    -j "com.app.security.*!*"

  # Trace specific method
  frida-trace -U -f com.app \
    -j "com.app.LoginActivity!validatePassword"

  # Trace native functions
  frida-trace -U -f com.app -i "SSL_*"
  frida-trace -U -f com.app -i "*encrypt*"

  # Trace Objective-C methods
  frida-trace -U -f com.app \
    -m "-[* isJailbroken]"
  ```

  Auto-generates handlers in `__handlers__/` for customization.
]

#section-slide(title: "Complete Script Example")

#slide(title: "Combined Assessment Script")[
  ```javascript
  Java.perform(function() {
    // === SSL Pinning Bypass ===
    try {
      var Pinner = Java.use(
        "okhttp3.CertificatePinner");
      Pinner.check.overload(
        "java.lang.String","java.util.List")
        .implementation = function(h, c) {
          console.log("[SSL] Bypass: " + h);
        };
    } catch(e) {}

    // === Root Detection Bypass ===
    try {
      var Root = Java.use("com.app.RootChecker");
      Root.isRooted.implementation = function() {
        console.log("[ROOT] Bypassed");
        return false;
      };
    } catch(e) {}
    console.log("[*] All hooks installed");
  });
  ```
]

#slide(title: "Python Automation")[
  ```python
  import frida, sys

  PACKAGE = "com.example.app"
  JS_CODE = open("assessment.js").read()

  def on_message(message, data):
      if message["type"] == "send":
          print(f"[!] {message['payload']}")

  device = frida.get_usb_device()
  pid = device.spawn([PACKAGE])
  session = device.attach(pid)
  script = session.create_script(JS_CODE)
  script.on("message", on_message)
  script.load()
  device.resume(pid)

  print(f"[*] Attached to {PACKAGE}")
  sys.stdin.read()
  ```

  Enables automated, reproducible instrumentation.
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - Frida is the most versatile tool for mobile dynamic analysis
  - `Java.perform()` gives full access to the Java/Kotlin runtime
  - `ObjC.classes` gives access to the Objective-C runtime
  - SSL pinning bypass is essential for traffic interception
  - Root/jailbreak detection is systematically bypassable
  - Frida can intercept encryption to see plaintext data
  - Combine static analysis (identify targets) with Frida (modify behavior)
  - objection provides convenient CLI for common tasks
  - Spawn mode (`-f`) ensures hooks are active before app init
  - Python scripts enable automated workflows
]

#slide(title: "Resources")[
  *Official:*
  - Frida Documentation: frida.re/docs/
  - Frida JavaScript API: frida.re/docs/javascript-api/
  - Frida CodeShare: codeshare.frida.re/

  *Tools:*
  - objection: github.com/sensepost/objection
  - frida-tools: pip install frida-tools

  *Learning:*
  - OWASP MASTG - Dynamic Analysis
  - Frida Handbook: learnfrida.info
  - Awesome Frida: github.com/dweinstein/awesome-frida
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Dynamic Instrumentation with Frida],
  subtitle: [Module 18 - Mobile Security],
)
