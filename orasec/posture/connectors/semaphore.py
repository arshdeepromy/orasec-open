"""
Semaphore UI connector: Ansible patch deployment from OraSec.

API (Semaphore 2.x, Bearer token from POST /api/auth/login + POST /api/user/tokens):
  GET  /api/project/{p}/inventory              Ansible inventories (static INI text in "inventory")
  GET  /api/project/{p}/templates              task templates
  POST /api/project/{p}/tasks                  {"template_id", "limit", "message"} -> task
  GET  /api/project/{p}/tasks/{id}             status: waiting | starting | running | success | error | stopped
  GET  /api/project/{p}/tasks/{id}/output      [{"time", "output"}, ...]
  POST /api/project/{p}/tasks/{id}/stop

Options: {"project_id": 1, "apply_template": <id>, "check_template": <id>,
          "production_groups": ["aws"], "patchmon_refresh_minutes": 5}
Secrets: {"api_token": "..."}

Collect() records which inventory hosts are patchable (asset attribute "semaphore") and the
recent task history; it does not create findings.
"""
import configparser
import json
import re

from orasec.posture.connectors.base import AssetRecord, BaseConnector, CollectResult, ConnectorError, register

DONE = {"success", "error", "stopped"}


def parse_ini_inventory(text):
    """Return {host: {"group": str, "ansible_host": str, "vars": {...}}} from a static INI inventory."""
    hosts, group = {}, "ungrouped"
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("[") else raw.strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            group = m.group(1)
            continue
        if ":" in group:  # [group:vars] / [group:children]
            continue
        parts = line.split()
        name, kv = parts[0], dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        hosts.setdefault(name, {"group": group, "ansible_host": kv.get("ansible_host", name), "vars": kv})
    return hosts


@register
class SemaphoreConnector(BaseConnector):
    kind = "semaphore"
    secret_fields = ("api_token",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.headers.update({"Authorization": f"Bearer {self.secrets.get('api_token', '')}", "Accept": "application/json"})
        self.pid = int(self.options.get("project_id", 1))
        self.P = f"/api/project/{self.pid}"

    def test(self):
        tpls = self.http.get(f"{self.P}/templates")
        names = ", ".join(t.get("name", "?") for t in tpls)
        return f"Semaphore project {self.pid}: {len(tpls)} templates ({names[:200]})"

    def inventory(self):
        hosts = {}
        for inv in self.http.get(f"{self.P}/inventory"):
            if inv.get("type", "static") in ("static", "static-yaml", "") and inv.get("inventory"):
                for h, v in parse_ini_inventory(inv["inventory"]).items():
                    v["inventory_id"] = inv.get("id")
                    hosts[h] = v
        return hosts

    def launch(self, template_id, limit, message=""):
        # Semaphore applies a per-task --limit only via "arguments" on templates that allow overriding
        # arguments; "limit" alone is ignored by some versions. Send both; the poller verifies the recap.
        body = {"template_id": int(template_id), "limit": limit, "arguments": json.dumps(["--limit", limit]), "message": message[:250]}
        task = self.http.post(f"{self.P}/tasks", json=body)
        if not task.get("id"):
            msg = f"Semaphore did not return a task id: {task}"
            raise ConnectorError(msg)
        return task

    def task(self, task_id):
        return self.http.get(f"{self.P}/tasks/{task_id}")

    def output(self, task_id):
        return self.http.get(f"{self.P}/tasks/{task_id}/output")

    def stop(self, task_id):
        self.http.request("POST", f"{self.P}/tasks/{task_id}/stop", json={}, expect_json=False)

    def collect(self):
        res = CollectResult()
        hosts = self.inventory()
        tpls = {t["id"]: t.get("name") for t in self.http.get(f"{self.P}/templates")}
        res.stats["templates"] = tpls
        res.stats["inventory_hosts"] = {h: {"group": v["group"], "ansible_host": v["ansible_host"]} for h, v in hosts.items()}
        for t in ("apply_template", "check_template"):
            if self.options.get(t) and int(self.options[t]) not in tpls:
                res.warnings.append(f"option {t}={self.options[t]} is not a template in project {self.pid}")
        try:
            res.stats["recent_tasks"] = [{"id": t.get("id"), "template_id": t.get("template_id"), "status": t.get("status"),
                                          "created": t.get("created"), "limit": t.get("limit")} for t in self.http.get(f"{self.P}/tasks/last")[:20]]
        except ConnectorError as e:
            res.warnings.append(f"task history unavailable ({e})")
        prod = set(self.options.get("production_groups", []))
        for h, v in hosts.items():
            ip = v["ansible_host"] if re.match(r"^\d+\.\d+\.\d+\.\d+$", v["ansible_host"]) else ""
            res.assets.append(AssetRecord(
                key=f"host:{h}", name=h, hostname="" if ip else v["ansible_host"], ip_address=ip, asset_type="server",
                attributes={"inventory_host": h, "group": v["group"], "ansible_host": v["ansible_host"], "production": v["group"] in prod,
                            "user": v["vars"].get("ansible_user")}))
        return res


__all__ = ["DONE", "SemaphoreConnector", "configparser", "parse_ini_inventory"]

