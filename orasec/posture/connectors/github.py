"""
GitHub connector: repository inventory, Dependabot / code-scanning / secret-scanning alerts and
repository security settings (REST API v2022-11-28).

Token: fine-grained PAT, read-only: Metadata, Contents (read), Administration (read), Dependabot alerts (read),
Code scanning alerts (read), Secret scanning alerts (read), Vulnerability alerts.
  GET /user/repos?affiliation=owner,organization_member     repositories (or /orgs/{org}/repos)
  GET /repos/{o}/{r}/dependabot/alerts?state=open           vulnerable dependencies
  GET /repos/{o}/{r}/code-scanning/alerts?state=open        SAST (needs code scanning / GHAS on private repos)
  GET /repos/{o}/{r}/secret-scanning/alerts?state=open      leaked secrets (needs secret scanning)
  GET /repos/{o}/{r}/vulnerability-alerts                   204 = Dependabot alerts enabled
  GET /repos/{o}/{r}/branches/{b}/protection                default-branch protection

Secrets: {"token": "..."}. Options: {"owner": "your-github-user", "org": "", "repos": [], "include_archived": false,
          "product_map": {"orasec": "OraSec"}, "exclude_repos": ["owner/repo"]}
exclude_repos: repositories switched off on the Code & Repositories page. They stay in the inventory (so they can be
switched back on) but get no security checks and no findings.
"""
from orasec.posture.connectors.base import AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low", "warning": "Medium",
       "error": "High", "note": "Low", "none": "Info"}


@register
class GitHubConnector(BaseConnector):
    kind = "github"
    secret_fields = ("token",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.headers.update({"Authorization": f"Bearer {self.secrets.get('token', '')}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28"})

    def _paged(self, path, **params):
        out, page = [], 1
        while True:
            r = self.http.request("GET", path, expect_json=False, params={**params, "per_page": 100, "page": page})
            data = r.json()
            if isinstance(data, dict):
                return data  # unexpected object: let the caller handle it
            out.extend(data)
            if 'rel="next"' not in r.headers.get("Link", ""):
                return out
            page += 1

    def _status(self, path):
        try:
            r = self.http.request("GET", path, expect_json=False)
            return r.status_code, r
        except ConnectorError as e:
            code = int(str(e).split("HTTP ")[1][:3]) if "HTTP " in str(e) else 0
            return code, str(e)

    def _excluded(self):
        return {x.lower() for x in (self.options.get("exclude_repos") or [])}

    def test(self):
        me = self.http.get("/user")
        repos, exc = self._repos(), self._excluded()
        off = sum(1 for r in repos if r["full_name"].lower() in exc)
        return f"GitHub as {me.get('login')} — {len(repos) - off} repositories monitored, {off} switched off"

    def _repos(self):
        if self.options.get("org"):
            repos = self._paged(f"/orgs/{self.options['org']}/repos", type="all")
        else:
            repos = self._paged("/user/repos", affiliation="owner,organization_member")
        owner = (self.options.get("owner") or "").lower()
        names = {r.lower() for r in self.options.get("repos", [])}
        out = []
        for r in repos if isinstance(repos, list) else []:
            if owner and r["owner"]["login"].lower() != owner and not self.options.get("org"):
                continue
            if names and r["name"].lower() not in names:
                continue
            if r.get("archived") and not self.options.get("include_archived"):
                continue
            out.append(r)
        return out

    def collect(self):  # noqa: C901, PLR0912, PLR0915
        res = CollectResult()
        per_product = {}
        pmap = {k.lower(): v for k, v in (self.options.get("product_map") or {}).items()}
        stats = {"repos": 0, "excluded": [], "dependabot_open": 0, "code_scanning_open": 0, "secret_scanning_open": 0, "unprotected": 0, "features": {}}
        excluded = self._excluded()
        for r in self._repos():
            full, name, branch = r["full_name"], r["name"], r.get("default_branch", "main")
            if full.lower() in excluded:
                # switched off: keep it in the inventory, but make no security calls and raise no findings
                stats["excluded"].append(full)
                res.assets.append(AssetRecord(key=f"repo:{full}", name=full, asset_type="application", vendor="GitHub", model="repository",
                                              internet_exposed=not r.get("private"), scanned=False,
                                              attributes={"private": r.get("private"), "default_branch": branch, "language": r.get("language"),
                                                          "pushed_at": r.get("pushed_at"), "url": r.get("html_url"), "excluded": True}))
                continue
            stats["repos"] += 1
            product = pmap.get(name.lower(), self.options.get("product_name"))
            f = per_product.setdefault(product, [])
            host = f"github.com/{full}"
            feat = stats["features"][full] = {"private": r.get("private"), "dependabot": None, "code_scanning": None, "secret_scanning": None, "branch_protection": None}
            res.assets.append(AssetRecord(key=f"repo:{full}", name=full, asset_type="application", vendor="GitHub", model="repository",
                                          internet_exposed=not r.get("private"), scanned=True,
                                          attributes={"private": r.get("private"), "default_branch": branch, "language": r.get("language"),
                                                      "pushed_at": r.get("pushed_at"), "url": r.get("html_url")}))
            base = {"host": host, "tags": ["github", "code"]}
            # Dependabot alerts
            code, resp = self._status(f"/repos/{full}/vulnerability-alerts")
            feat["dependabot"] = code == 204
            if code == 404:
                f.append({**base, "title": f"Dependabot alerts disabled: {full}", "severity": "Medium", "component_name": "repository-settings",
                          "description": f"Dependency vulnerability alerts are not enabled on **{full}**.", "unique_id": f"github:{full}:dependabot-off",
                          "mitigation": "Settings → Code security → enable Dependabot alerts (and security updates)."})
            if feat["dependabot"]:
                try:
                    alerts = self._paged(f"/repos/{full}/dependabot/alerts", state="open")
                    for a in alerts if isinstance(alerts, list) else []:
                        adv, dep = a.get("security_advisory") or {}, a.get("dependency") or {}
                        vuln = a.get("security_vulnerability") or {}
                        pkg = (dep.get("package") or {}).get("name", "")
                        stats["dependabot_open"] += 1
                        f.append({**base, "title": f"{adv.get('cve_id') or adv.get('ghsa_id')}: {pkg} in {full}", "severity": SEV.get(adv.get("severity"), "Medium"),
                                  "description": f"{adv.get('summary', '')}\n\nManifest: `{dep.get('manifest_path')}`  \nVulnerable range: `{vuln.get('vulnerable_version_range')}`",
                                  "mitigation": f"Upgrade {pkg} to {((vuln.get('first_patched_version') or {}).get('identifier')) or 'a patched version'}.",
                                  "component_name": pkg, "fix_version": (vuln.get("first_patched_version") or {}).get("identifier"),
                                  "cves": [adv["cve_id"]] if adv.get("cve_id") else [], "references": a.get("html_url", ""),
                                  "unique_id": f"github:{full}:dependabot:{a.get('number')}", "tags": ["github", "dependabot", "sca"],
                                  "cvss_score": (adv.get("cvss") or {}).get("score")})
                except ConnectorError as e:
                    res.warnings.append(f"{full}: Dependabot alerts unavailable ({str(e)[:80]})")
            # code scanning
            code, resp = self._status(f"/repos/{full}/code-scanning/alerts?state=open&per_page=1")
            feat["code_scanning"] = code == 200
            if code == 200:
                for a in self._paged(f"/repos/{full}/code-scanning/alerts", state="open"):
                    rule = a.get("rule") or {}
                    loc = ((a.get("most_recent_instance") or {}).get("location") or {})
                    stats["code_scanning_open"] += 1
                    f.append({**base, "title": f"{rule.get('description') or rule.get('id')} in {full}", "severity": SEV.get(rule.get("security_severity_level") or rule.get("severity"), "Medium"),
                              "description": f"{(a.get('tool') or {}).get('name')}: {rule.get('description')}\n\n`{loc.get('path')}:{loc.get('start_line')}`",
                              "component_name": loc.get("path"), "references": a.get("html_url", ""), "unique_id": f"github:{full}:codescan:{a.get('number')}",
                              "tags": ["github", "sast"]})
            # secret scanning
            code, resp = self._status(f"/repos/{full}/secret-scanning/alerts?state=open&per_page=1")
            feat["secret_scanning"] = code == 200
            if code == 200:
                for a in self._paged(f"/repos/{full}/secret-scanning/alerts", state="open"):
                    stats["secret_scanning_open"] += 1
                    f.append({**base, "title": f"Exposed secret ({a.get('secret_type_display_name')}) in {full}", "severity": "Critical",
                              "description": f"GitHub detected a **{a.get('secret_type_display_name')}** in the repository. Validity: {a.get('validity', 'unknown')}.",
                              "mitigation": "Revoke/rotate the credential at the provider, then remove it from history.", "references": a.get("html_url", ""),
                              "unique_id": f"github:{full}:secret:{a.get('number')}", "tags": ["github", "secrets"], "component_name": "secret"})
            elif not r.get("private") and code == 404:
                f.append({**base, "title": f"Secret scanning disabled on public repo: {full}", "severity": "Medium", "component_name": "repository-settings",
                          "description": "Secret scanning (free for public repositories) is not enabled.", "unique_id": f"github:{full}:secretscan-off",
                          "mitigation": "Settings → Code security → enable Secret scanning and push protection."})
            # branch protection
            code, resp = self._status(f"/repos/{full}/branches/{branch}/protection")
            feat["branch_protection"] = code == 200
            if code == 404:
                stats["unprotected"] += 1
                f.append({**base, "title": f"Default branch not protected: {full}@{branch}", "severity": "Medium", "component_name": "repository-settings",
                          "description": f"`{branch}` accepts direct pushes and force-pushes; no review is required (ISO 27001 A.8.32 / A.8.4).",
                          "unique_id": f"github:{full}:branch-protection", "mitigation": "Add a branch ruleset: require PRs, block force-push and deletion."})
            elif code == 403:
                feat["branch_protection"] = "unavailable on plan"
        stats["product_split"] = {k or "default": len(v) for k, v in per_product.items()}
        res.stats.update(stats)
        for product, f in per_product.items():
            res.batches.append(TestBatch(title=f"GitHub security: {product or 'repositories'}", scan_type="OraSec GitHub", payload={"findings": f},
                                         count=len(f), product_name=product))
        return res

