# nmap-custom-script
- NMAP custom script that scan for vulnerabilities and order them based on custome metrics
- For this case, our script will be scanning HTTP headers vulnerabilities (secure headers)
- We'll setup vulnerable webapp (Nginx) for demo in order to get the scanning results


## Prerequisite tools 
- nmap - for running our custom nse script
- Docker - for building our vulnerable environment
- make - for running commands easily

  
## Custom metrics (choosen)
- Severity
- CVSS score
- Impact


## Use Case
- Our target in this case is a web application which is represented by Nginx (for demo purpose)
- Scanning vulnerabilities in Nginx and output the findings based on severity, CVSS score and impact
- Examples of real HTTP security vulnerabilities are:

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

    4. Set-Cookie (Secure & HttpOnly missing)
        Severity: Medium
        CVSS: ~5.0–6.0
        Impact: Session hijacking, CSRF

    5. X-Frame-Options
        Severity: Medium
        CVSS: ~4.5–5.5
        Impact: Clickjacking

    6. X-XSS-Protection (Obsolete but relevant for legacy systems)
        Severity: Medium
        CVSS: ~4.0–5.0
        Impact: XSS attacks

    7. X-Content-Type-Options
        Severity: Medium
        CVSS: ~4.0–5.0
        Impact: MIME sniffing attacks

    8. Expect-CT (Certificate Transparency, obsolete)
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

## Installation
- Get the script ready to work

```
# make it executable
chmod +x sec-headers-check.nse

# run it
nmap --script /path/to/sec-headers-check.nse -p 80 <your-nginx-ip>

```

## How it works / Testing
1. On Vulnerable environment 
- Setup a vulnerable environment with docker so that we can scan for vulnerabilities


```
# Setup environment command
cd vulnerable-environment

# run it
make up
```

- Verify nginx is working fine by navigate to `http://localhost:8000`

- Scan

```
# Command
nmap --script ./sec-headers-check.nse  -p 8000 localhost

```

- Output of vulnerabilities ordered based on in `Severity rating`, `CVSS score` and `Described impact`:

```

Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 16:48 EAT
Nmap scan report for maen (192.168.1.137)
Host is up (0.000087s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt
| shc: High -- [CVSS 7.5] Strict-Transport-Security Missing -- Allows MITM and downgrade attacks
| High -- [CVSS 7.0] Content-Security-Policy Missing -- Vulnerable to XSS and data injection
| Medium -- [CVSS 6.0] X-Frame-Options Missing -- Clickjacking risk
| Medium -- [CVSS 5.0] X-Content-Type-Options Missing -- MIME sniffing attack risk
| Low -- [CVSS 2.0] X-Permitted-Cross-Domain-Policies Missing -- Flash/Silverlight policy risks
| Low -- [CVSS 2.5] Expect-CT Missing -- Weak certificate transparency enforcement
| Low -- [CVSS 3.0] X-XSS-Protection Missing -- Limited XSS protection
|_Low -- [CVSS 2.0] Cache-Control Missing -- Potential data leaks via cache

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds

```



2. On Secure environment
- Seting up another webapp with secure configurations of `nginx` then we wont get any vulnerability captured since it is secure.
- To do that just run `nginx` in a docker container without any configuration (by default Nginx have done great on their configurations)

```
# launch a docker container by running
docker run --name nginx-app -d -p 8085:80 nginx

# scan the secured app
nmap --script ./sec-headers-check.nse  -p 8085 localhost

```

- Output will look like this:

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 16:36 EAT
Nmap scan report for maen (192.168.1.137)
Host is up (0.000095s latency).

PORT     STATE  SERVICE
8085/tcp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds

```

- This shows that our custom script is working. Alternatively, you can fix the misconfiguration in the vulnerable environment and try to scan again
using the script if you'll get the results (you wont catch those issues)

## Debugging
- Run the script by checking the trace by adding the flag `--script-trace` in the end of your command.
- Running the script `debug-script.nse` on the target. You should get the output like this:

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 16:14 EAT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt
|_degub-script: NSE script is running successfully!

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds

```
