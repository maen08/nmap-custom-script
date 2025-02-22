local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Scans HTTP security headers and reports missing or misconfigured ones with severity levels.
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
        ["strict-transport-security"] = { 
            severity = "High", 
            cvss = "7.5", 
            impact = "Allows MITM and downgrade attacks", 
            check = function(val)
                return not val
            end 
        },
        ["content-security-policy"] = { 
            severity = "High", 
            cvss = "7.0", 
            impact = "Vulnerable to XSS and data injection", 
            check = function(val)
                return not val or val == ""
            end
        },
        ["x-frame-options"] = { 
            severity = "Medium", 
            cvss = "6.0", 
            impact = "Clickjacking risk", 
            check = function(val)
                return not val or val == ""
            end
        },
        ["x-xss-protection"] = { 
            severity = "Low", 
            cvss = "3.0", 
            impact = "Limited XSS protection", 
            check = function(val)
                return not val or val == "0" or val == ""
            end
        },
        ["x-content-type-options"] = { 
            severity = "Medium", 
            cvss = "5.0", 
            impact = "MIME sniffing attack risk", 
            check = function(val)
                return not val or val == ""
            end
        },
        ["expect-ct"] = { 
            severity = "Low", 
            cvss = "2.5", 
            impact = "Weak certificate transparency enforcement", 
            check = function(val)
                return not val or val == ""
            end
        },
        ["cache-control"] = { 
            severity = "Low", 
            cvss = "2.0", 
            impact = "Potential data leaks via cache", 
            check = function(val)
                return not val or val == ""
            end
        }
    }

    -- Results array to store header issues
    local results = {}

    -- Checking for missing or misconfigured headers
    for header, info in pairs(security_headers) do
        local header_value = headers[header]

        -- If the header is missing
        if not header_value then
            table.insert(results, string.format("%s -- [CVSS %s] %s missing -- %s",
                info.severity, info.cvss, header, info.impact))

        -- If header exists, check its value
        else
            -- Check for special cases like X-XSS-Protection
            if header == "X-XSS-Protection" then
                if header_value == "1" then
                    -- If the value is 1, no issue, skip printing
                    stdnse.debug(1, "X-XSS-Protection set to 1 (good).")
                elseif header_value == "0" then
                    -- Flag as improper value
                    table.insert(results, string.format("Low -- [CVSS 3.0] %s Set to 0 -- XSS protection disabled", header))
                else
                    -- Flag if the value is something unexpected
                    table.insert(results, string.format("Low -- [CVSS 3.0] %s Invalid value -- %s", header, header_value))
                end

            -- Check for Content-Security-Policy (CSP)
            elseif header == "Content-Security-Policy" then
                if header_value == "" then
                    -- If the value is empty, flag as missing
                    table.insert(results, string.format("High -- [CVSS 7.0] %s Empty -- Vulnerable to XSS and data injection", header))
                else
                    -- Otherwise, skip printing since it's configured
                    stdnse.debug(1, "%s is present with value: %s", header, header_value)
                end
            else
                -- For all other headers, check if they're empty or missing
                if info.check(header_value) then
                    table.insert(results, string.format("%s -- [CVSS %s] %s Incorrect or missing -- %s",
                        info.severity, info.cvss, header, info.impact))
                end
            end
        end
    end

    -- Sort results by severity (High -> Low)
    table.sort(results, function(a, b)
        local severity_order = { High = 3, Medium = 2, Low = 1 }
        local sa = severity_order[string.match(a, "^(%a+)")]
        local sb = severity_order[string.match(b, "^(%a+)")]
        return sa > sb
    end)

    -- Return the results or indicate that everything is secure
    if #results == 0 then
        return "All security headers are properly configured."
    else
        return table.concat(results, "\n")
    end
end
