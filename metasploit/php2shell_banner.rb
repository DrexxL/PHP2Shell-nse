##
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# Metasploit port of php2shell-detect.nse: banner triage for PHP2Shell
# (CVE-2026-109618, CVE-2026-109619). It reads the PHP version a web server
# reports about itself and compares it with the fixed releases. It sends
# ordinary GET requests only: no exploit, no attack.
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  RULES_DATE = '2026-11-04'.freeze

  # First fixed release on each branch named in the PHP security advisory
  # (PHP security releases of 21 October 2026).
  FIXED = {
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12'
  }.freeze

  BELOW = 'BANNER BELOW FIX'.freeze
  ABOVE = 'BANNER AT OR ABOVE FIX'.freeze
  FAILED = 'CHECK FAILED'.freeze

  CONFIRM = 'Confirm on the host: identify the PHP binary and SAPI that serve this ' \
            'site and check the package changelog for the CVE IDs.'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PHP2Shell Banner Triage (CVE-2026-109618, CVE-2026-109619)',
        'Description' => %q{
          Reads the PHP version that each web server reports about itself (the
          X-Powered-By or Server header, or a phpinfo() page heading) and compares
          it with the first fixed release on its branch: 8.2.35, 8.3.36, 8.4.27 or
          8.5.12. It sends ordinary GET requests only, does not follow redirects,
          and sends no exploit.

          A reported version is a claim, not proof: a proxy, an application or an
          administrator can change, hide or fake it, and Linux distributions often
          backport fixes without changing the number. So this module never reports
          a host as vulnerable or safe. Results are BANNER BELOW FIX, BANNER AT OR
          ABOVE FIX or CHECK FAILED, and are stored as notes, not vulnerabilities.
          Confirm every result on the server with php2shell-hostcheck.sh.

          Rules dated 2026-11-04. Both CVEs are in the CISA Known Exploited
          Vulnerabilities catalog. CVE-2026-115560 is not checked.
        },
        'Author' => ['Drexx Laggui'],
        'License' => 'Apache License 2.0',
        'References' => [
          ['CVE', '2026-109618'],
          ['CVE', '2026-109619'],
          ['URL', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']
        ],
        'DisclosureDate' => '2026-10-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The first page to check', '/']),
        OptString.new('PATHS', [false, 'Extra pages to check, separated by commas (for example /app/,/login.php)', '']),
        OptBool.new('PROBE_INFO', [true, 'Also check /index.php, /info.php and /phpinfo.php for a phpinfo() page', false])
      ]
    )
  end

  # Compare dotted numeric versions: -1, 0 or 1.
  def vcmp(a, b)
    pa = a.scan(/\d+/).map(&:to_i)
    pb = b.scan(/\d+/).map(&:to_i)
    [pa.length, pb.length].max.times do |i|
      x = pa[i] || 0
      y = pb[i] || 0
      return -1 if x < y
      return 1 if x > y
    end
    0
  end

  # RC1, alpha2, beta, -dev: a pre-release precedes the release with the same number.
  def prerelease?(suffix)
    suffix.to_s.downcase.match?(/\A(rc|alpha|beta|-?dev)/)
  end

  # Decide the result for one reported version: [result, reason, action].
  def classify(ver, suffix)
    branch = ver[/\A\d+\.\d+/]
    pre = prerelease?(suffix)
    distro = !suffix.empty? && !pre
    full = ver + suffix

    if vcmp(branch, '8.2') < 0
      return [FAILED,
              "Disclosed PHP #{full} is on unsupported branch #{branch}. The vendor advisory covers " \
              '8.2 to 8.5 only; whether older branches are affected is disputed between sources.',
              'Treat as unverified. Upgrade to a supported fixed release or isolate the service.']
    end
    if vcmp(branch, '8.5') > 0
      return [FAILED,
              "Disclosed PHP #{full} is on branch #{branch}, which is newer than the advisory's scope.",
              'Check for a later advisory that covers this branch.']
    end

    fixed = FIXED[branch]
    c = vcmp(ver, fixed)
    below = c < 0 || (c == 0 && pre)

    if below && distro
      return [FAILED,
              "Disclosed PHP #{full} is a distribution build numbered below #{fixed}. Distributions " \
              'backport fixes without changing the upstream number, so the banner cannot decide it.',
              CONFIRM]
    end
    if below
      why = if pre
              "Disclosed PHP #{full} is a pre-release of #{ver} or earlier, which precedes the fix."
            else
              "Disclosed PHP #{full} precedes the fixed release #{fixed}. Some distribution builds " \
              'show the bare upstream number even with the fix backported.'
            end
      return [BELOW, why, "#{CONFIRM} Patch if the fix is absent."]
    end
    [ABOVE,
     "Disclosed PHP #{full} is at or after the fixed release #{fixed}. A banner can be set or " \
     'stale, so this is not proof that the service is patched.',
     CONFIRM]
  end

  def paths_to_check
    paths = [normalize_uri(target_uri.path)]
    datastore['PATHS'].to_s.split(/[,\s]+/).reject(&:empty?).each { |p| paths << normalize_uri(p) }
    paths.concat(['/index.php', '/info.php', '/phpinfo.php']) if datastore['PROBE_INFO']
    paths.uniq
  end

  # The Host header actually sent, read from the raw request when available.
  def host_header_sent(res)
    raw = res.respond_to?(:request) ? res.request.to_s : ''
    sent = raw[/^Host:\s*([^\r\n]+)/i, 1]
    sent || datastore['VHOST'] || rhost
  end

  def run_host(ip)
    evidence = []
    versions = {} # "8.2.10" + suffix => [version, suffix]
    partial = []
    any_response = false
    host_sent = nil

    paths_to_check.each do |path|
      res = send_request_cgi({ 'method' => 'GET', 'uri' => path }, 20)
      unless res
        evidence << "GET #{path} -> no response"
        next
      end
      any_response = true
      host_sent ||= host_header_sent(res)
      line = "GET #{path} -> #{res.code}"
      line << " (redirect to #{res.headers['Location']}, not followed)" if res.headers['Location']

      found = []
      partial_here = false
      %w[X-Powered-By Server].each do |h|
        val = res.headers[h]
        next unless val

        hits = val.scan(/PHP\/(\d+\.\d+\.\d+)([\w~.+-]*)/)
        hits.each { |v, s| found << [v, s, "#{h.downcase}: #{val}"] }
        next unless hits.empty? && (part = val[/PHP\/(\d+(?:\.\d+)?)(?![\d.])/, 1])

        partial << part
        partial_here = true
        evidence << "#{line}, #{h.downcase}: #{val} (partial version only)"
      end

      # Only the phpinfo() page heading counts; ordinary page text does not.
      if res.code == 200 && (m = res.body.to_s.match(%r{<h1 class="p">PHP Version (\d+\.\d+\.\d+)([\w~.+-]*)\s*</h1>}))
        found << [m[1], m[2], "phpinfo() heading: PHP Version #{m[1]}#{m[2]}"]
      end

      evidence << "#{line}, no PHP version disclosed" if found.empty? && !partial_here
      found.each do |v, s, src|
        evidence << "#{line}, #{src}"
        versions[v + s] ||= [v, s]
      end
    end

    if !any_response
      result = FAILED
      reason = 'No HTTP response was received on any requested path.'
      action = 'Verify the service manually or on the host.'
    elsif versions.empty? && !partial.empty?
      result = FAILED
      reason = "Only a partial PHP version was disclosed (#{partial.uniq.join(', ')}), which cannot be compared with a fixed release."
      action = 'Authenticated host-side package and runtime inspection is required.'
    elsif versions.empty?
      result = FAILED
      reason = 'No PHP version was disclosed (expose_php may be Off, PHP may be absent, or a proxy may hide it). ' \
               'The active PHP runtime and package patch state were not verified.'
      action = 'Authenticated host-side package and runtime inspection is required.'
    elsif versions.length > 1
      result = FAILED
      reason = "Conflicting PHP versions were disclosed: #{versions.keys.join(', ')}. " \
               'Different paths may be served by different back ends.'
      action = 'Inspect each back end on its host.'
    else
      v, s = versions.values.first
      result, reason, action = classify(v, s)
    end

    scheme = datastore['SSL'] ? 'https' : 'http'
    target = any_response ? "#{scheme}://#{ip}:#{rport}  Host: #{host_sent}" : "#{ip}:#{rport} (no response, transport unknown)"
    checked_at = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

    msg = "#{peer} - #{result}: #{reason}"
    case result
    when BELOW then print_warning(msg)
    when ABOVE then print_good(msg)
    else print_status(msg)
    end
    vprint_status("#{peer} - action: #{action}")
    vprint_status("#{peer} - target: #{target}")
    evidence.each { |e| vprint_status("#{peer} - evidence: #{e}") }

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: (datastore['SSL'] ? 'https' : 'http'),
      type: 'php2shell.banner',
      update: :unique_data,
      data: {
        result: result,
        reason: reason,
        action: action,
        target: target,
        evidence: evidence,
        rules: "PHP security releases of 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12); rule set dated #{RULES_DATE}",
        checked_at: checked_at,
        cves: 'CVE-2026-109618, CVE-2026-109619 (both in the CISA KEV catalog)'
      }
    )
  end
end
