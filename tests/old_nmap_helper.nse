-- Copyright 2026 Drexx Laggui
-- SPDX-License-Identifier: Apache-2.0
--
-- Test helper for nse-tests.sh. It makes nmap 7.94 or newer behave like an
-- older nmap (7.80 to 7.93) in the one way that matters to
-- php2shell-detect.nse: the url.ascii_hostname function, added in 7.94, is
-- removed before the other scripts run.

local url = require "url"

description = "Test helper: removes url.ascii_hostname to imitate nmap before 7.94."
categories = {"safe"}

prerule = function() return true end

action = function()
  url.ascii_hostname = nil
  return "url.ascii_hostname removed (imitating nmap before 7.94)"
end
