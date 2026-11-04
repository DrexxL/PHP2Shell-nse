-- Copyright 2026 Drexx Laggui
-- SPDX-License-Identifier: Apache-2.0

local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local table     = require "table"
local url       = require "url"

description = [[
Checks web servers for signs of PHP2Shell (CVE-2026-109618, CVE-2026-109619),
two serious PHP bugs that were fixed on 21 October 2026.

WHAT IT DOES. It asks each web server for normal pages, the same way a web
browser would. It sends no attack and does not follow redirects. Then it
looks for the PHP version that the server reports about itself. The server
can report it in the X-Powered-By or Server header, or on a PHP information
page (phpinfo). The script compares that version with the first fixed
version for its branch: 8.2.35, 8.3.36, 8.4.27 or 8.5.12.

Example: a server that says "X-Powered-By: PHP/8.2.10" reports a version
older than 8.2.35, so the script shows BANNER BELOW FIX.

WHAT IT CANNOT DO. The version a server reports is a claim, not proof. It is
like a name tag: a proxy, a program or an administrator can change it, hide
it or fake it. It also cannot show fixes that a Linux distribution copied
into an older version (a "backport"). So this script never says a server is
safe or unsafe. Each result is about one web service, not the whole computer.
Confirm every result on the server itself with php2shell-hostcheck.sh.

RESULTS (one for each web service, always shown):
  BANNER BELOW FIX        The reported version is older than the fix. Some
                          distribution builds, such as Ubuntu's, show the
                          plain version number even after a backported fix,
                          so check this on the server.
  BANNER AT OR ABOVE FIX  The reported version is the fixed one or newer.
                          This is not proof that the server is fixed.
  CHECK FAILED            The script found nothing it can use. Possible
                          causes: no version shown, no response, different
                          versions on different pages, a distribution build,
                          or a branch outside PHP's warning.

Rules dated 2026-11-04. Both CVEs are in the CISA Known Exploited
Vulnerabilities catalog. A third bug, CVE-2026-115560, is not checked.
]]

---
-- @usage
-- nmap -sV -p 80,443,8080,8443 --script php2shell-detect.nse 10.0.0.0/24
-- nmap -sV -p 443 --script php2shell-detect.nse \
--      --script-args 'php2shell-detect.paths=/app/,/login.php,php2shell-detect.probe-info' intranet.example
--
-- Keep -sV. Without it, nmap can skip web servers on unusual ports.
--
-- @args php2shell-detect.paths Extra pages to check, separated by commas.
--       The script always checks "/". It checks every page you list. If
--       two pages report different versions, the result is CHECK FAILED.
-- @args php2shell-detect.probe-info Set this to also check /index.php,
--       /info.php and /phpinfo.php for a PHP information page.
-- @args php2shell-detect.vhost The website name to send. Use it when one
--       server hosts several websites. For HTTPS, scan by the website name
--       instead of the IP address, so nmap sends the name during the
--       secure connection setup (SNI) too.
--
-- The settings also work under the script's file name, so a renamed copy
-- still works.
--
-- @output
-- 80/tcp open  http
-- | php2shell-detect:
-- |   result: BANNER BELOW FIX
-- |   reason: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35. Some ...
-- |   action: Confirm on the host: identify the PHP binary and SAPI that ...
-- |   target: http://10.0.0.5:80  Host: 10.0.0.5  SNI: none
-- |   evidence:
-- |     GET / -> 200, x-powered-by: PHP/8.2.10
-- |   rules: PHP security releases of 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12); rule set dated 2026-11-04
-- |   checked_at: 2026-11-04T14:02:11Z
-- |   cves: CVE-2026-109618, CVE-2026-109619 (both in the CISA KEV catalog)
-- |   references:
-- |     https://www.cve.org/CVERecord?id=CVE-2026-109618
-- |     https://www.cve.org/CVERecord?id=CVE-2026-109619
-- |_    https://www.cisa.gov/known-exploited-vulnerabilities-catalog

author     = "Drexx Laggui"
license    = "Apache-2.0 -- https://www.apache.org/licenses/LICENSE-2.0"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local ARG_PREFIX = "php2shell-detect"
local RULES_DATE = "2026-11-04"

-- First fixed release on each branch named in the vendor advisory.
local FIXED = {
  ["8.2"] = "8.2.35",
  ["8.3"] = "8.3.36",
  ["8.4"] = "8.4.27",
  ["8.5"] = "8.5.12",
}

local AFFECTED = "BANNER BELOW FIX"
local ABOVE    = "BANNER AT OR ABOVE FIX"
local FAILED   = "CHECK FAILED"

local CONFIRM = "Confirm on the host: identify the PHP binary and SAPI that "
             .. "serve this site and check the package changelog for the CVE IDs."

local function get_arg(name)
  return stdnse.get_script_args(ARG_PREFIX .. "." .. name)
      or stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
end

-- Compare dotted numeric versions: -1 if a<b, 0 if equal, 1 if a>b.
local function vcmp(a, b)
  local function parts(v)
    local t = {}
    for n in v:gmatch("%d+") do t[#t + 1] = tonumber(n) end
    return t
  end
  local pa, pb = parts(a), parts(b)
  for i = 1, math.max(#pa, #pb) do
    local x, y = pa[i] or 0, pb[i] or 0
    if x < y then return -1 elseif x > y then return 1 end
  end
  return 0
end

-- A suffix such as RC1, alpha2, beta, -dev marks a pre-release, which
-- precedes the release with the same number.
local function is_prerelease(suffix)
  local s = (suffix or ""):lower()
  return s:match("^rc") or s:match("^alpha") or s:match("^beta")
      or s:match("^%-?dev") or false
end

-- Decide the result for one disclosed version string.
local function classify(v, suffix)
  local branch = v:match("^(%d+%.%d+)")
  local pre    = is_prerelease(suffix)
  local distro = (suffix ~= "" and not pre)
  local full   = v .. suffix

  if vcmp(branch, "8.2") < 0 then
    return FAILED,
      ("Disclosed PHP %s is on unsupported branch %s. The vendor advisory covers "
       .. "8.2 to 8.5 only; whether older branches are affected is disputed between "
       .. "sources."):format(full, branch),
      "Treat as unverified. Upgrade to a supported fixed release or isolate the service."
  end
  if vcmp(branch, "8.5") > 0 then
    return FAILED,
      ("Disclosed PHP %s is on branch %s, which is newer than the advisory's scope."):format(full, branch),
      "Check for a later advisory that covers this branch."
  end

  local fixed = FIXED[branch]
  local c     = vcmp(v, fixed)
  local below = (c < 0) or (c == 0 and pre)

  if below and distro then
    return FAILED,
      ("Disclosed PHP %s is a distribution build numbered below %s. Distributions "
       .. "backport fixes without changing the upstream number, so the banner cannot "
       .. "decide it."):format(full, fixed),
      CONFIRM
  end
  if below then
    local why = pre and
      ("Disclosed PHP %s is a pre-release of %s or earlier, which precedes the fix."):format(full, v) or
      ("Disclosed PHP %s precedes the fixed release %s. Some distribution builds "
       .. "show the bare upstream number even with the fix backported."):format(full, fixed)
    return AFFECTED, why, CONFIRM .. " Patch if the fix is absent."
  end
  return ABOVE,
    ("Disclosed PHP %s is at or after the fixed release %s. A banner can be set or "
     .. "stale, so this is not proof that the service is patched."):format(full, fixed),
    CONFIRM
end

-- Collect every PHP version string in one response.
local function extract(resp, path, evidence, versions, seen)
  local got    = (resp ~= nil and resp.status ~= nil)
  local status = got and resp.status or "no response"
  if got and seen.ssl == nil then seen.ssl = resp.ssl end
  local line   = ("GET %s -> %s"):format(path, tostring(status))
  if resp and resp.header and resp.header.location then
    line = line .. " (redirect to " .. resp.header.location .. ", not followed)"
  end
  local found = {}
  local partial_before = #seen.partial

  if resp and resp.header then
    for _, h in ipairs({"x-powered-by", "server"}) do
      local val = resp.header[h]
      if val then
        for v, suf in val:gmatch("PHP/(%d+%.%d+%.%d+)([%w~%.%+%-]*)") do
          found[#found + 1] = { v, suf, ("%s: %s"):format(h, val) }
        end
        if #found == 0 then
          local part = val:match("PHP/(%d+%.?%d*)")
          if part then
            seen.partial[#seen.partial + 1] = part
            evidence[#evidence + 1] = line .. (", %s: %s (partial version only)"):format(h, val)
          end
        end
      end
    end
  end

  -- Only the phpinfo() page heading counts; arbitrary page text does not.
  if resp and resp.status == 200 and resp.body then
    local v, suf = resp.body:match('<h1 class="p">PHP Version (%d+%.%d+%.%d+)([%w~%.%+%-]*)%s*</h1>')
    if v then found[#found + 1] = { v, suf, "phpinfo() heading: PHP Version " .. v .. suf } end
  end

  if #found == 0 and #seen.partial == partial_before then
    evidence[#evidence + 1] = line .. ", no PHP version disclosed"
  end
  for _, f in ipairs(found) do
    evidence[#evidence + 1] = line .. ", " .. f[3]
    local key = f[1] .. f[2]
    if not versions[key] then
      versions[key] = { v = f[1], suffix = f[2] }
      versions[#versions + 1] = key
    end
  end
  return got
end

-- The Host header nmap's http library sends (same rules as http.lua).
local function host_header_sent(host, port, vhost)
  if vhost then return vhost end
  local global = stdnse.get_script_args("http.host")
  if global then return global end
  -- url.ascii_hostname exists only from nmap 7.94; older releases use the
  -- plain host name, as their http library does.
  local name   = (rawget(url, "ascii_hostname") or stdnse.get_hostname)(host)
  local scheme = url.get_default_scheme(port)
  if scheme then
    local ssl_port = shortport.ssl(host, port)
    if (ssl_port and scheme == "https") or (not ssl_port and scheme == "http") then
      return name
    end
  end
  return name .. ":" .. port.number
end

action = function(host, port)
  local paths = {"/"}
  local extra = get_arg("paths")
  if extra then
    for p in extra:gmatch("[^,%s]+") do paths[#paths + 1] = p end
  end
  if get_arg("probe-info") then
    for _, p in ipairs({"/index.php", "/info.php", "/phpinfo.php"}) do
      paths[#paths + 1] = p
    end
  end

  local opts  = { redirect_ok = false }
  local vhost = get_arg("vhost")
  if vhost then opts.header = { Host = vhost } end

  local out = stdnse.output_table()

  local evidence, versions, any_response = {}, {}, false
  local seen = { partial = {} }
  for _, path in ipairs(paths) do
    if extract(http.get(host, port, path, opts), path, evidence, versions, seen) then
      any_response = true
    end
  end
  -- Report the transport actually used, not a guess from the port number.
  local scheme = (seen.ssl == true and "https") or (seen.ssl == false and "http") or nil

  if not any_response then
    out.result = FAILED
    out.reason = "No HTTP response was received on any requested path."
    out.action = "Verify the service manually or on the host."
  elseif #versions == 0 and #seen.partial > 0 then
    out.result = FAILED
    out.reason = "Only a partial PHP version was disclosed (" .. table.concat(seen.partial, ", ")
              .. "), which cannot be compared with a fixed release."
    out.action = "Authenticated host-side package and runtime inspection is required."
  elseif #versions == 0 then
    out.result = FAILED
    out.reason = "No PHP version was disclosed (expose_php may be Off, PHP may be absent, "
              .. "or a proxy may hide it). The active PHP runtime and package patch state "
              .. "were not verified."
    out.action = "Authenticated host-side package and runtime inspection is required."
  elseif #versions > 1 then
    out.result = FAILED
    out.reason = "Conflicting PHP versions were disclosed: " .. table.concat(versions, ", ")
              .. ". Different paths may be served by different back ends."
    out.action = "Inspect each back end on its host."
  else
    local only = versions[versions[1]]
    local result, reason, act = classify(only.v, only.suffix)
    out.result = result
    out.reason = reason
    out.action = act
  end

  if scheme then
    out.target = ("%s://%s:%d  Host: %s  SNI: %s"):format(
      scheme, host.ip, port.number, host_header_sent(host, port, vhost),
      (scheme == "https" and host.targetname) or "none")
  else
    out.target = ("%s:%d (no response, transport unknown)"):format(host.ip, port.number)
  end
  out.evidence   = evidence
  out.rules      = ("PHP security releases of 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12); "
                 .. "rule set dated %s"):format(RULES_DATE)
  out.checked_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
  out.cves       = "CVE-2026-109618, CVE-2026-109619 (both in the CISA KEV catalog)"
  out.references = {
    "https://www.cve.org/CVERecord?id=CVE-2026-109618",
    "https://www.cve.org/CVERecord?id=CVE-2026-109619",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  }
  return out
end
