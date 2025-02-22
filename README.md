# NMAP Custom Script for HTTP Header Vulnerability Scanning

## Introduction
This guide provides a detailed walkthrough on using a custom NMAP script to scan for HTTP header vulnerabilities. The script ranks detected vulnerabilities based on custom-defined metrics to aid security assessments.

For demonstration, a vulnerable Nginx web application will be set up, allowing users to analyze real-time scanning results.

---
## Prerequisite Tools
Ensure the following tools are installed:
- **NMAP** – Required for executing the custom NSE script.
- **Docker** – Used to build and manage the vulnerable test environment.
- **Make** – Simplifies command execution.

---
## Custom Metrics for Vulnerability Ranking
The vulnerabilities are categorized based on:
1. **Severity** – The criticality of the issue.
2. **CVSS Score** – A standardized rating to measure risk.
3. **Impact** – The potential consequences of an exploit.

---
## Use Case
The target for this scanning process is a web application running on Nginx. The goal is to detect security misconfigurations in HTTP headers and rank them by severity, CVSS score, and impact.

### **Common HTTP Security Vulnerabilities**
```
1. HSTS (HTTP Strict Transport Security)
   Severity: High
   CVSS: ~6.5–7.5
   Impact: MITM attacks, downgrade attacks

2. Content-Security-Policy (CSP)
   Severity: High
   CVSS: ~6.0–7.0
   Impact: XSS, data injection attacks

3. HPKP (HTTP Public Key Pins) [Deprecated]
   Severity: Medium-High
   CVSS: ~5.0–6.5
   Impact: MITM, rogue certificate attacks

4. Set-Cookie (Secure & HttpOnly Missing)
   Severity: Medium
   CVSS: ~5.0–6.0
   Impact: Session hijacking, CSRF

5. X-Frame-Options
   Severity: Medium
   CVSS: ~4.5–5.5
   Impact: Clickjacking

6. X-XSS-Protection (Obsolete)
   Severity: Medium
   CVSS: ~4.0–5.0
   Impact: XSS attacks

7. X-Content-Type-Options
   Severity: Medium
   CVSS: ~4.0–5.0
   Impact: MIME sniffing attacks

8. Expect-CT (Obsolete)
   Severity: Low-Medium
   CVSS: ~3.5–4.5
   Impact: Prevents misissued certificates

9. X-Permitted-Cross-Domain-Policies
   Severity: Low
   CVSS: ~3.0–4.0
   Impact: Flash/Silverlight exploitation

10. Cache-Control & Pragma
   Severity: Low
   CVSS: ~3.0–3.5
   Impact: Sensitive data exposure via caching

11. Expires
   Severity: Low
   CVSS: ~2.5–3.5
   Impact: Caching-related risks
```
---
## Installation
Prepare the script for execution:
```
# Make the script executable
chmod +x sec-headers-check.nse

# Run the script with NMAP
nmap --script /path/to/sec-headers-check.nse -p 80 <your-nginx-ip>
```

---
## How It Works / Testing
### **Testing on a Vulnerable Environment**
1. Set up the vulnerable Nginx environment:
   ```sh
   cd vulnerable-environment
   make up
   ```
2. Confirm Nginx is running by navigating to `http://localhost:8000`
3. Run the vulnerability scan:
   ```sh
   nmap --script ./sec-headers-check.nse -p 8000 localhost
   ```
4. Expected output:
   ```sh
   PORT     STATE SERVICE
   8000/tcp open  http-alt
    | High -- [CVSS 7.0] content-security-policy missing -- Vulnerable to XSS and data injection
    | Medium -- [CVSS 6.0] x-frame-options missing -- Clickjacking risk
    | Medium -- [CVSS 5.0] x-content-type-options missing -- MIME sniffing attack risk
    | Low -- [CVSS 2.5] expect-ct missing -- Weak certificate transparency enforcement
    | Low -- [CVSS 3.0] x-xss-protection missing -- Limited XSS protection
    |_Low -- [CVSS 2.0] cache-control missing -- Potential data leaks via cache
   ```

### **Testing on a Secure Environment**
1. Deploy a secure Nginx instance:
   ```sh
   docker run --name nginx-app -d -p 8085:80 nginx
   ```
2. Run a security scan:
   ```sh
   nmap --script ./sec-headers-check.nse -p 8085 localhost
   ```
3. Expected output:
   ```sh
   PORT     STATE  SERVICE
   8085/tcp closed unknown
   ```

This confirms that secure configurations prevent vulnerabilities.

---
## Debugging
For troubleshooting, use these commands:
1. Enable script tracing:
   ```sh
   nmap --script ./sec-headers-check.nse -p 8000 localhost --script-trace
   ```
2. Enable debug logs:
   ```sh
   nmap --script ./sec-headers-check.nse -p 8000 localhost -d
   ```
3. Test using a debugging script:
   ```sh
   nmap --script debug-script.nse -p 8000 localhost
   ```
   Expected output:
   ```sh
   PORT     STATE SERVICE
   8000/tcp open  http-alt
   |_debug-script: NSE script is running successfully!
   ```

---
## Conclusion
This guide outlines how to identify HTTP security vulnerabilities using a custom NMAP script. By setting up both vulnerable and secure environments, users can validate security controls and improve their web application's defense mechanisms.

