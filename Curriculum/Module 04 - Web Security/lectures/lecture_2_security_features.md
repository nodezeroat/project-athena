# Security Features of the Browser

The Browser implements some security features to mitigate a lot of different vulnerabilities. This section gives a short overview about some of the most used features.

## Same-Origin Policy (SOP)

The Same Origin Policy (SOP) is a security mechanism implemented in web browsers to prevent potentially malicious interactions between web pages from different origins. It plays a crucial role in ensuring the privacy and security of web application data.

### What Defines an Origin?

An origin is determined by the combination of:

- **Protocol Scheme**: The communication protocol (e.g., `http`, `https`).
- **Host Name**: The domain name or IP address (e.g., `example.com`).
- **Port Number**: The communication port (e.g., `80` for HTTP, `443` for HTTPS).

Two URLs have the **same origin** only if all three of these components are identical.

For example, consider the following URL:

```
http://normal-website.com/example/example.html
```

This uses the scheme http, the domain `normal-website.com`, and the port number `80`. The following table shows how the same-origin policy will be applied if content at the above URL tries to access other origins:

| **URL accessed**                        | **Access permitted?**              |
| --------------------------------------- | ---------------------------------- |
| <http://normal-website.com/example/>      | Yes: same scheme, domain, and port |
| <http://normal-website.com/example2/>     | Yes: same scheme, domain, and port |
| <https://normal-website.com/example/>     | No: different scheme and port      |
| <http://en.normal-website.com/example/>   | No: different domain               |
| <http://www.normal-website.com/example/>  | No: different domain               |
| <http://normal-website.com:8080/example/> | No: different port\*               |

> \*Internet Explorer will allow this access because IE does not take account of the port number when applying the same-origin policy.

### Policy Details

- **Reading Responses**: Web content from one origin cannot read responses from another origin. This prevents malicious websites from accessing data they shouldn't.
- **Sending Requests**: While reading responses from different origins is restricted, sending requests is not. However, the response from such a request will be opaque to the initiating origin.
- **Cookies**: Cookies set by an origin are sent only to that particular origin. Other origins cannot access or modify these cookies.

### Exceptions & Workarounds: CORS

- **Cross-Origin Resource Sharing (CORS)**: It's a mechanism that allows restricted resources on a web page to be requested from another domain outside the domain from which the resource originated.
- With CORS, a server can specify who can access its assets and which HTTP request methods are allowed from external resources.
- CORS headers, when set up correctly, allow web pages to make cross-origin AJAX calls to fetch or send data, overcoming the SOP restrictions.

### Why is SOP Important?

- **Data Isolation**: SOP ensures that potentially malicious web pages cannot read or modify data from other websites, protecting user data.
- **Avoiding Cross-Site Request Forgery (CSRF)**: By ensuring that only the issuing origin can read cookies, SOP helps mitigate CSRF attacks where malicious sites trick users into performing unwanted actions on another site where they're authenticated.

### How is the same-origin policy implemented?

The same-origin policy generally controls the access that JavaScript code has to content that is loaded cross-domain. Cross-origin loading of page resources is generally permitted. For example, the SOP allows embedding of images via the `<img>` tag, media via the `<video>` tag and JavaScript includes with the `<script>` tag. However, while these external resources can be loaded by the page, any JavaScript on the page won't be able to read the contents of these resources.

There are various exceptions to the same-origin policy:

- Some objects are writable but not readable cross-domain, such as the `location` object or the `location.href` property from iframes or new windows.

- Some objects are readable but not writable cross-domain, such as the `length` property of the `window` object (which stores the number of frames being used on the page) and the `closed` property.

- The `replace` function can generally be called cross-domain on the `location` object.

- You can call certain functions cross-domain. For example, you can call the functions `close`, `blur` and `focus` on a new window. The `postMessage` function can also be called on iframes and new windows in order to send messages from one domain to another.

Due to legacy requirements, the same-origin policy is more relaxed when dealing with cookies, so they are often accessible from all subdomains of a site even though each subdomain is technically a different origin. You can partially mitigate this risk using the `HttpOnly` cookie flag.

It's possible to relax same-origin policy using `document.domain`. This special property allows you to relax SOP for a specific domain, but only if it's part of your FQDN (fully qualified domain name). For example, you might have a domain `marketing.example.com` and you would like to read the contents of that domain on `example.com`. To do so, both domains need to set `document.domain` to `example.com`. Then SOP will allow access between the two domains despite their different origins. In the past it was possible to set `document.domain` to a TLD such as com, which allowed access between any domains on the same TLD, but now modern browsers prevent this.

## Content Secure Policy (CSP)

CSP is a browser security mechanism that aims to mitigate XSS and some other attacks. It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.

To enable CSP, a response needs to include an HTTP response header called `Content-Security-Policy` (Sometimes you may see mentions of the `X-Content-Security-Policy` header, but that's an older version and you don't need to specify it anymore.) with a value containing the policy. The policy itself consists of one or more directives, separated by semicolons.

Alternatively, the `<meta>` element can be used to configure a policy, for example:

```html
<meta
  http-equiv="Content-Security-Policy"
  content="default-src 'self'; img-src https://*; child-src 'none';" />
```

## Why CSP?

A primary goal of CSP is to mitigate and report XSS attacks. XSS attacks exploit the browser's trust in the content received from the server. Malicious scripts are executed by the victim's browser because the browser trusts the source of the content, even when it's not coming from where it seems to be coming from.

CSP makes it possible for server administrators to reduce or eliminate the vectors by which XSS can occur by specifying the domains that the browser should consider to be valid sources of executable scripts. A CSP compatible browser will then only execute scripts loaded in source files received from those allowed domains, ignoring all other scripts (including inline scripts and event-handling HTML attributes).

## Using CSP

Configuring Content Security Policy involves adding the `Content-Security-Policy` HTTP header to a web page and giving it values to control what resources the user agent is allowed to load for that page. For example, a page that uploads and displays images could allow images from anywhere, but restrict a form action to a specific endpoint. A properly designed Content Security Policy helps protect a page against a cross-site scripting attack.

A policy can be defined using the `Content-Secure-Policy` HTTP Header like this:

```
Content-Security-Policy: policy
```

### Writing a policy

A policy is made up of directives that set rules for various resource types. It's essential to have a `default-src` directive as a general fallback. To prevent inline scripts and the use of `eval()`, a `default-src` or `script-src` directive is required. Similarly, to limit inline styles, either a `default-src` or `style-src` directive is needed. Directives cater to diverse resource types like fonts, frames, images, media, scripts, and more.

For examples and more information see: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#examples_common_use_cases>

## Resources

- <https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy>
- <https://portswigger.net/web-security/cors/same-origin-policy>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
- <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
