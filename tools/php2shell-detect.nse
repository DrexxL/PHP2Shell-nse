local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local table     = require "table"

description = [[
Banner-triage check for PHP2Shell (CVE-2026-109618, CVE-2026-109619).

WHAT IT DOES. Sends ordinary HTTP GET requests (no exploit payload, redirects
not followed) to every configured path. It records each PHP version string
disclosed in the X-Powered-By or Server response header or in a phpinfo()
page heading, and compares it with the first fixed release on each branch
named in the PHP security advisory.

WHAT IT CANNOT DO. A version string in an HTTP response is a claim, not proof.
A proxy, application or administrator can set, strip or forge it, and it says
nothing about fixes a distribution has backported. The script therefore never
reports a service as "not vulnerable". Every result describes one HTTP
service, not the host, and needs host-side confirmation (runtime and package
inspection) before it goes into a compliance record.

RESULTS (one per HTTP service, always printed):
  BANNER BELOW FIX        The disclosed version precedes the fix. Some
                          distribution builds (for example Ubuntu's) report
                          the bare upstream number even when the fix has
                          been backported, so this too needs confirmation.
  BANNER AT OR ABOVE FIX  The disclosed version is at or after the fix.
                          This is not proof that the service is patched.
  CHECK FAILED            No usable evidence: no version disclosed, no
                          response, conflicting versions, a distribution
                          build, or a branch outside the vendor advisory.

Rules as of 2026-11-04: fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (PHP
security releases of 21 October 2026). Both CVEs are listed in the CISA Known
Exploited Vulnerabilities catalog.
]]

---
-- @usage
-- nmap -sV -p 80,443,8080,8443 --script php2shell-detect.nse 10.0.0.0/24
-- nmap -sV -p 443 --script php2shell-detect.nse \
--      --script-args 'php2shell-detect.paths=/app/,/login.php,php2shell-detect.probe-info' intranet.example
--
-- @args php2shell-detect.paths Comma-separated extra paths to request in
--       addition to "/". Every path is examined; differing versions make
--       the check fail.
-- @args php2shell-detect.probe-info If set, also requests /index.php,
--       /info.php and /phpinfo.php and reads any phpinfo() heading.
-- @args php2shell-detect.vhost Host header to send (name-based virtual
--       hosts). For TLS, scan by hostname so Nmap also sends it as SNI.
--
-- Arguments are also accepted under the script's file name, so a renamed
-- copy keeps working.
--
-- @output
-- 80/tcp open  http
-- | php2shell-detect:
-- |   result: BANNER BELOW FIX
-- |   reason: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35. Some ...
-- |   action: Confirm on the host (php -v, package changelog), then patch.
-- |   target: http://10.0.0.5:80  Host: 10.0.0.5  SNI: none
-- |   evidence:
-- |     GET / -> 200, x-powered-by: PHP/8.2.10
-- |   rules: PHP security releases of 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12); rule set dated 2026-11-04
-- |   checked_at: 2026-11-04T14:02:11Z
-- |   cves: CVE-2026-109618, CVE-2026-109619
-- |_  references: https://www.cve.org/CVERecord?id=CVE-2026-109618 ...

author     = "Local security team"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
local function extract(resp, path, evidence, versions)
  local status = resp and resp.status or "no response"
  local line   = ("GET %s -> %s"):format(path, tostring(status))
  if resp and resp.header and resp.header.location then
    line = line .. " (redirect to " .. resp.header.location .. ", not followed)"
  end
  local found = {}

  if resp and resp.header then
    for _, h in ipairs({"x-powered-by", "server"}) do
      local val = resp.header[h]
      if val then
        for v, suf in val:gmatch("PHP/(%d+%.%d+%.%d+)([%w~%.%+%-]*)") do
          found[#found + 1] = { v, suf, ("%s: %s"):format(h, val) }
        end
      end
    end
  end

  -- Only the phpinfo() page heading counts; arbitrary page text does not.
  if resp and resp.status == 200 and resp.body then
    local v, suf = resp.body:match('<h1 class="p">PHP Version (%d+%.%d+%.%d+)([%w~%.%+%-]*)%s*</h1>')
    if v then found[#found + 1] = { v, suf, "phpinfo() heading: PHP Version " .. v .. suf } end
  end

  if #found == 0 then
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
  return resp ~= nil
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

  local scheme = shortport.ssl(host, port) and "https" or "http"
  local out = stdnse.output_table()

  local evidence, versions, any_response = {}, {}, false
  for _, path in ipairs(paths) do
    if extract(http.get(host, port, path, opts), path, evidence, versions) then
      any_response = true
    end
  end

  if not any_response then
    out.result = FAILED
    out.reason = "No HTTP response was received on any requested path."
    out.action = "Verify the service manually or on the host."
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

  out.target = ("%s://%s:%d  Host: %s  SNI: %s"):format(
    scheme, host.ip, port.number, vhost or stdnse.get_hostname(host),
    (scheme == "https" and host.targetname) or "none")
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
