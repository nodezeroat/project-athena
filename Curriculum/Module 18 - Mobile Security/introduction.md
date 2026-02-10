# Mobile Security

This module covers the fundamentals of mobile security, including common attack vectors for both Android and iOS devices. Students will learn about the architecture of mobile platforms, how to assess the security of mobile apps using static and dynamic analysis, techniques for reverse engineering mobile apps, and hands-on dynamic instrumentation using Frida.

## Learning Objectives

- Understand the architecture of Android and iOS platforms and their security implications
- Identify and exploit common attack vectors for mobile devices and applications
- Assess the security of mobile apps using both automated tools and manual techniques
- Reverse engineer Android and iOS apps to identify vulnerabilities
- Use Frida for dynamic instrumentation to hook functions, bypass security controls, and inspect runtime behavior
- Intercept and analyze mobile app network traffic, including bypassing certificate pinning

## Topics Covered

1. [Introduction to Mobile Security](lectures/lecture_1_introduction.md) - Threat landscape, OWASP Mobile Top 10, testing methodology
2. [Mobile Device Architecture](lectures/lecture_2_mobile_device_architecture.md) - Android and iOS platform internals, IPC, app packaging
3. [Android Security](lectures/lecture_3_android_security.md) - Sandboxing, permissions, data storage, ADB, common vulnerabilities
4. [iOS Security](lectures/lecture_4_ios_security.md) - Code signing, sandboxing, data protection, Keychain, jailbreaking
5. [Mobile App Security Assessment](lectures/lecture_5_mobile_app_security_assessment.md) - MASVS/MASTG, MobSF, traffic interception, testing checklist
6. [Reverse Engineering Mobile Apps](lectures/lecture_6_reverse_engineering_mobile_apps.md) - APK/IPA decompilation, smali, Ghidra, obfuscation
7. [Dynamic Instrumentation with Frida](lectures/lecture_7_dynamic_instrumentation_with_frida.md) - Frida architecture, JavaScript API, hooking, SSL pinning bypass, root detection bypass, encryption interception

## Slides

1. [Introduction to Mobile Security](slides/Module_18_Slides_Introduction.typ)
2. [Mobile Device Architecture](slides/Module_18_Slides_Mobile_Architecture.typ)
3. [Android Security](slides/Module_18_Slides_Android_Security.typ)
4. [iOS Security](slides/Module_18_Slides_iOS_Security.typ)
5. [Mobile App Security Assessment](slides/Module_18_Slides_App_Assessment.typ)
6. [Reverse Engineering Mobile Apps](slides/Module_18_Slides_Reverse_Engineering.typ)
7. [Dynamic Instrumentation with Frida](slides/Module_18_Slides_Frida.typ)

## Assignments

1. [Android App Static Analysis](assignments/Module_18_Assignment_1.md) - Decompile and assess an Android app's security posture
2. [Dynamic Instrumentation with Frida](assignments/Module_18_Assignment_2.md) - Use Frida to hook functions, bypass security controls, and intercept data at runtime

## Prerequisites

- Basic understanding of web security (HTTP, APIs, authentication)
- Familiarity with Linux command line
- Basic programming knowledge (JavaScript, Python)
- Recommended: Completion of Module 04 (Web Security)

By the end of this module, students should be able to perform a comprehensive mobile application security assessment covering static analysis, dynamic analysis, reverse engineering, and runtime manipulation using industry-standard tools.
