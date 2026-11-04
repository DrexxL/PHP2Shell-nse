local http      = require "http"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local vulns     = require "vulns"

description = [[
Passive, version-based check for PHP2Shell (CVE-2026-109618, CVE-2026-109619).

The script sends ordinary HTTP GET requests and reads the PHP version that the
server discloses, either in the X-Powered-By or Server response header or, if
asked, in a phpinfo() page. It compares that version with the first fixed
release on each branch (8.2.35, 8.3.36, 8.4.27, 8.5.12). Branches 5.4 to 8.1
are end of life and are reported as having no upstream fix.

It sends NO exploit payload and cannot crash the target. The trade-off is that
it can only see what the server chooses to disclose:
  * With expose_php = Off, no version is visible and the host is reported as
    UNKNOWN (with -v) rather than safe.
  * Distribution builds (Debian, Ubuntu, RHEL, and so on) often backport fixes
    without changing the version number. A distribution suffix such as
    "-1~deb12u1" is flagged so you can confirm against the package changelog
    on the host itself.
]]

---
-- @usage
-- nmap -p 80,443,8080,8443 --script php2shell-detect.nse 10.0.0.0/24
-- nmap -p 80 --script php2shell-detect.nse --script-args php2shell-detect.probe-info 10.0.0.5
-- nmap -p 80 --script php2shell-detect.nse --script-args vulns.showall -v 10.0.0.5
--
-- @args php2shell-detect.paths Comma-separated extra paths to request
--       (default: only "/"). Example: "/app/,/login.php"
-- @args php2shell-detect.probe-info If set, also requests /index.php,
--       /info.php and /phpinfo.php and parses any phpinfo() output found.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | php2shell-detect:
-- |   VULNERABLE:
-- |   PHP2Shell memory corruption RCE (CVE-2026-109618)
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2026-109618
-- |     Risk factor: High
-- |       Disclosed PHP version 8.2.10 is below the fixed release 8.2.35.
-- |       Evidence: x-powered-by header on /: PHP/8.2.10
-- ...

author     = "Local security team"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

-- First fixed release per supported branch.
local FIXED = {
  ["8.2"] = "8.2.35",
  ["8.3"] = "8.3.36",
  ["8.4"] = "8.4.27",
  ["8.5"] = "8.5.12",
}

-- Compare dotted versions numerically: -1 if a<b, 0 if equal, 1 if a>b.
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

-- Look for a PHP version in headers first, then in a phpinfo() body.
local function find_php_version(resp, path)
  if not resp then return nil end
  if resp.header then
    for _, h in ipairs({"x-powered-by", "server"}) do
      local val = resp.header[h]
      if val then
        local v, suffix = val:match("PHP/(%d+%.%d+%.%d+)([^%s,;]*)")
        if v then
          return { version = v, suffix = suffix,
                   source = ("%s header on %s: %s"):format(h, path, val) }
        end
      end
    end
  end
  if resp.status == 200 and resp.body then
    local v, suffix = resp.body:match("PHP Version (%d+%.%d+%.%d+)([%w~%.%+%-]*)")
    if v then
      return { version = v, suffix = suffix,
               source = "phpinfo() output at " .. path }
    end
  end
  return nil
end

-- Decide the state and an explanation for one disclosed version.
local function classify(ev)
  local v      = ev.version
  local branch = v:match("^(%d+%.%d+)")
  local distro = (ev.suffix and ev.suffix ~= "")
  local note   = distro and
    (" Version carries distribution suffix '%s': fixes may be backported, "
     .. "so confirm with the package changelog on the host."):format(ev.suffix) or ""

  if vcmp(v, "5.4") < 0 or vcmp(branch, "8.5") > 0 then
    return vulns.STATE.NOT_VULN,
      ("PHP %s is outside the reported affected range (5.4 to 8.5)."):format(v)
  end

  local fixed = FIXED[branch]
  if not fixed then
    return vulns.STATE.LIKELY_VULN,
      ("PHP %s is on end-of-life branch %s; no upstream fix exists. "
       .. "Upgrade to a fixed supported release or isolate the host.%s"):format(v, branch, note)
  end

  if vcmp(v, fixed) >= 0 then
    return vulns.STATE.NOT_VULN,
      ("PHP %s is at or above the fixed release %s."):format(v, fixed)
  end

  return vulns.STATE.LIKELY_VULN,
    ("Disclosed PHP version %s is below the fixed release %s.%s"):format(v, fixed, note)
end

action = function(host, port)
  local paths = {"/"}
  local extra = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if extra then
    for p in extra:gmatch("[^,%s]+") do paths[#paths + 1] = p end
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".probe-info") then
    for _, p in ipairs({"/index.php", "/info.php", "/phpinfo.php"}) do
      paths[#paths + 1] = p
    end
  end

  local ev
  for _, path in ipairs(paths) do
    ev = find_php_version(http.get(host, port, path), path)
    if ev then break end
  end

  if not ev then
    stdnse.debug1("No PHP version disclosed on %s:%d", host.ip, port.number)
    if nmap.verbosity() > 0 then
      return "UNKNOWN: no PHP version disclosed (expose_php may be Off, or no PHP). "
          .. "Absence of a banner is not evidence of safety; inspect the host locally."
    end
    return nil
  end

  local state, why = classify(ev)
  local extra_info = why .. "\nEvidence: " .. ev.source

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local common_desc = [[
PHP2Shell is a pair of critical remote-code-execution flaws in PHP, publicly
disclosed 17 October 2026 and reported as exploited in the wild. This finding
is based on the version the server discloses, not on exploitation.]]

  return report:make_output(
    { title = "PHP2Shell memory corruption RCE (CVE-2026-109618)",
      state = state, IDS = { CVE = "CVE-2026-109618" }, risk_factor = "High",
      description = common_desc, extra_info = extra_info },
    { title = "PHP2Shell stale request-state RCE (CVE-2026-109619)",
      state = state, IDS = { CVE = "CVE-2026-109619" }, risk_factor = "High",
      description = common_desc, extra_info = extra_info }
  )
end
