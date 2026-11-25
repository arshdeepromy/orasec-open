#!/usr/bin/env python3
"""Wazuh integration: send an alert to OraSec the moment Wazuh raises it.

Wazuh calls:  custom-orasec <alert file> <api_key> <hook_url>
  api_key  = the OraSec webhook token (bearer), hook_url = https://.../orasec/wazuh/alert/
OraSec decides with its own rule whether the alert is a suspected hack or unauthorised action. Alerts that can never
be one (vulnerabilities, CIS checks) are not sent at all, so a vulnerability scan does not call OraSec once per CVE.
A failure is logged and never stops Wazuh; the 5-minute read in OraSec still picks the alert up.
"""
import json
import sys
import time
import urllib.error
import urllib.request

LOG = "/var/ossec/logs/integrations.log"
NEVER = {"vulnerability-detector", "sca"}


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write("%s custom-orasec: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S"), msg))
    except OSError:
        pass


def main(argv):
    if len(argv) < 4:
        log("usage: custom-orasec <alert file> <api_key> <hook_url>")
        return 0
    path, token, url = argv[1], argv[2], argv[3]
    try:
        with open(path) as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        log("cannot read alert file: %s" % e)
        return 0
    if NEVER & set((alert.get("rule") or {}).get("groups") or []):
        return 0
    req = urllib.request.Request(url, data=json.dumps(alert).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except urllib.error.HTTPError as e:
        log("OraSec answered HTTP %s for alert %s" % (e.code, alert.get("id")))
    except Exception as e:  # noqa: BLE001  (never stop Wazuh)
        log("could not reach OraSec for alert %s: %s" % (alert.get("id"), e))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
