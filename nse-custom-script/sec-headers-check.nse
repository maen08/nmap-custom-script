local http = require "http"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Scans a web server for missing or misconfigured security headers and ranks them by severity.
]]

author = "Your Name"
license = "Same as Nmap"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https"
end

action = function(host, port)
    local report = {}
    local url = "http://" .. host.target .. ":" .. port.number .. "/"
    local response = http.get(url)

    if not response then
        return "Failed to connect to target."
    end

    local headers = response.header
    local issues = {}

    -- Define security checks
    local checks = {
        {
            name = "HSTS (Strict-Transport-Security) Missing",
            header = "strict-transport-security",
            cvss = 7.5,
            impact = "Allows MITM and downgrade attacks",
        },
        {
            name = "Content-Security-Policy (CSP) Missing",
            header = "content-security-policy",
            cvss = 7.0,
            impact = "Vulnerable to XSS and data injection",
        },
        {
            name = "X-Frame-Options Missing",
            header = "x-frame-options",
            cvss = 5.5,
            impact = "Clickjacking attack possible",
        },
        {
            name = "X-XSS-Protection Disabled",
            header = "x-xss-protection",
            cvss = 5.0,
            impact = "Browser XSS filter disabled",
            check = function(val) return val == "0" end
        },
        {
            name = "X-Content-Type-Options Missing",
            header = "x-content-type-options",
            cvss = 5.0,
            impact = "MIME type sniffing allowed",
        },
        {
            name = "Set-Cookie Missing Secure & HttpOnly",
            header = "set-cookie",
            cvss = 6.0,
            impact = "Session hijacking, CSRF risk",
            check = function(val)
                return not val:match("; secure") or not val:match("; httponly")
            end
        },
        {
            name = "Expect-CT Missing",
            header = "expect-ct",
            cvss = 4.5,
            impact = "No certificate transparency enforcement",
        },
        {
            name = "X-Permitted-Cross-Domain-Policies Missing",
            header = "x-permitted-cross-domain-policies",
            cvss = 4.0,
            impact = "Cross-domain Flash/Silverlight risks",
        },
        {
            name = "Cache-Control Missing",
            header = "cache-control",
            cvss = 3.5,
            impact = "Sensitive data might be cached",
        },
        {
            name = "Pragma Header Missing",
            header = "pragma",
            cvss = 3.5,
            impact = "Old browsers might cache sensitive responses",
        },
        {
            name = "Expires Header Missing",
            header = "expires",
            cvss = 3.0,
            impact = "No expiration date for cache control",
        }
    }

    -- Analyze headers
    for _, check in ipairs(checks) do
        local header_value = headers[check.header]

        if not header_value or (check.check and check.check(header_value)) then
            table.insert(issues, {
                severity = check.cvss,
                name = check.name,
                impact = check.impact
            })
        end
    end

    -- Sort issues by severity (high to low)
    table.sort(issues, function(a, b) return a.severity > b.severity end)

    -- Format output
    if #issues == 0 then
        return "No security header issues detected!"
    else
        for _, issue in ipairs(issues) do
            table.insert(report, string.format(
                "[CVSS %.1f] %s - %s", issue.severity, issue.name, issue.impact))
        end
        return table.concat(report, "\n")
    end
end
