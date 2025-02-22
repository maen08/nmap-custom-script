# nmap-custom-script
NMAP custom script that prioritize the detected vulnerabilities based on defined metrics


## Prerequisite
- NMAP
- Docker
- Linux / Windows machine

  
## Custom metrics
- Severity
- Exploitability
- CVSS score

## How it works
- Once you run the script agains the target, first it will scan for a number of vulnerabilities (listed) and then it will give the output listed based on priority

```
# Run the script command


# Example of output results

```

## Use Case
- Scanning vulnerabilities in Nginx and output the findings based on severity, CVSS score and impact
- The following are sample isues to be checked:

```

1. **HSTS (HTTP Strict Transport Security)**  
   - **Severity:** High  
   - **CVSS:** ~6.5–7.5  
   - **Impact:** MITM attacks, downgrade attacks  

2. **Content-Security-Policy (CSP)**  
   - **Severity:** High  
   - **CVSS:** ~6.0–7.0  
   - **Impact:** XSS, data injection attacks  

3. **HPKP (HTTP Public Key Pins) [Deprecated]**  
   - **Severity:** Medium-High  
   - **CVSS:** ~5.0–6.5  
   - **Impact:** MITM, rogue certificate attacks  

4. **Set-Cookie (Secure & HttpOnly missing)**  
   - **Severity:** Medium  
   - **CVSS:** ~5.0–6.0  
   - **Impact:** Session hijacking, CSRF  

5. **X-Frame-Options**  
   - **Severity:** Medium  
   - **CVSS:** ~4.5–5.5  
   - **Impact:** Clickjacking  

6. **X-XSS-Protection (Obsolete but relevant for legacy systems)**  
   - **Severity:** Medium  
   - **CVSS:** ~4.0–5.0  
   - **Impact:** XSS attacks  

7. **X-Content-Type-Options**  
   - **Severity:** Medium  
   - **CVSS:** ~4.0–5.0  
   - **Impact:** MIME sniffing attacks  

8. **Expect-CT (Certificate Transparency, obsolete)**  
   - **Severity:** Low-Medium  
   - **CVSS:** ~3.5–4.5  
   - **Impact:** Prevents misissued certificates  

9. **X-Permitted-Cross-Domain-Policies**  
   - **Severity:** Low  
   - **CVSS:** ~3.0–4.0  
   - **Impact:** Flash/Silverlight exploitation  

10. **Cache-Control & Pragma**  
   - **Severity:** Low  
   - **CVSS:** ~3.0–3.5  
   - **Impact:** Sensitive data exposure via caching  

11. **Expires**  
   - **Severity:** Low  
   - **CVSS:** ~2.5–3.5  
   - **Impact:** Caching-related risks

```


## Testing
- Setup a vulnerable environment with docker so that we can scan for vulnerabilities
```
# Setup environment command

```

- Get the IP address of the vulnerable environment/machine
```
# Command
docker inspect name-here | grep IPAddrr

```

- Scan
```
# Command

```
