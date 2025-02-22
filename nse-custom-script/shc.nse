local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Scans HTTP security headers and reports missing ones with severity levels.
]]

categories = {"safe"}

portrule = shortport.http

-- Function to convert a table to a string for better readability in logs
function tableToString(tbl)
    local str = ""
    for k, v in pairs(tbl) do
        str = str .. tostring(k) .. ": " .. tostring(v) .. "\n"
    end
    return str
end

action = function(host, port)
    local url = "http://" .. (host.targetname or host.ip) .. ":" .. port.number
    -- local url = "http://" .. host.targetname .. ":" .. port.number
    stdnse.debug(1, "Fetching headers from: %s", url)

    local response = http.get(host, port, "/")
    if not response then
        return "Error: No response received!"
    end

    local headers = response.header
    if not headers then
        return "Error: No headers received!"
    end

    -- Print the headers for debugging purposes
    stdnse.debug(1, "Headers received: %s", tableToString(headers))

    -- List of headers to check
    local security_headers = {
        ["Strict-Transport-Security"] = { severity = "High", cvss = "7.5", impact = "Allows MITM and downgrade attacks" },
        ["Content-Security-Policy"] = { severity = "High", cvss = "7.0", impact = "Vulnerable to XSS and data injection" },
        ["X-Frame-Options"] = { severity = "Medium", cvss = "6.0", impact = "Clickjacking risk" },
        ["X-XSS-Protection"] = { severity = "Low", cvss = "3.0", impact = "Limited XSS protection" },
        ["X-Content-Type-Options"] = { severity = "Medium", cvss = "5.0", impact = "MIME sniffing attack risk" },
        ["X-Permitted-Cross-Domain-Policies"] = { severity = "Low", cvss = "2.0", impact = "Flash/Silverlight policy risks" },
        ["Expect-CT"] = { severity = "Low", cvss = "2.5", impact = "Weak certificate transparency enforcement" },
        ["Cache-Control"] = { severity = "Low", cvss = "2.0", impact = "Potential data leaks via cache" }
    }

    -- Checking for missing security headers
    local results = {}
    for header, info in pairs(security_headers) do
        if not headers[header] then
            table.insert(results, string.format("%s -- [CVSS %s] %s Missing -- %s",
                info.severity, info.cvss, header, info.impact))
        end
    end

    -- Sort results by severity (High -> Low)
    table.sort(results, function(a, b)
        local severity_order = { High = 3, Medium = 2, Low = 1 }
        local sa = severity_order[string.match(a, "^(%a+)")]
        local sb = severity_order[string.match(b, "^(%a+)")]
        return sa > sb
    end)

    -- Return the results
    return table.concat(results, "\n")
end
