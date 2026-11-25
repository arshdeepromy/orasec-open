# Site profile

The site profile is one JSON file that tells OraSec about **your** organisation and network. It is optional: without
it OraSec uses neutral defaults and draws an example network.

Keep the file out of version control. It describes your own network and people.

## Turn it on

1. Write the file, for example `site.json` (start from the example below).
2. Point the setting `ORASEC_SITE_FILE` at it, for the web and the worker containers. With Docker Compose, a
   `docker-compose.override.yml` beside the main file does both:

   ```yaml
   x-site: &site
     environment:
       ORASEC_SITE_FILE: /app/site/site.json
     volumes:
       - ./site.json:/app/site/site.json:ro

   services:
     uwsgi: *site
     celeryworker: *site
     celerybeat: *site
   ```

3. Restart those containers. The file is read once when a process starts.

A file that cannot be read (missing, not valid JSON) is logged as an error and the defaults are used, so a typing
mistake never stops OraSec.

## Keys

Every key is optional.

| Key | What it is for | Default |
|---|---|---|
| `org_name` | Shown in page headers, reports and download file names | `Your organisation` |
| `security_contact` | E-mail address in the page footer and on the support page | none |
| `issues_url` | Where the support page sends bug reports | this project's issues page |
| `security_txt_url` | Your `security.txt`; the ISO/IEC 27001 communication check fetches it | none (the check warns) |
| `review_repos` | `owner/repo` list for the second-person code review check (the GitHub connector option of the same name wins) | none (the check warns) |
| `asset_owners` | Default joint owners of inventory assets, e.g. `["Alex Lee - CTO"]` | none |
| `office_cidrs` | Address ranges that are "head office" in the asset inventory | `["192.168.10.0/24"]` |
| `office_networks` | UniFi network names whose clients are company assets, and which the web-filtering check looks at | `["Office"]` |
| `locations` | Words for where assets sit: `cloud`, `onprem`, `office`, `information` | `Cloud`, `On-premises`, `Head office`, `Company systems` |
| `classification_words` | Extra name hints for default classification: `{"restricted": ["payroll"], "confidential": ["wiki"]}` | none |
| `attack_map_target` | The point attacks are drawn towards, and your own country (ISO code, not drawn as an attacker): `{"name": "...", "lat": 0, "lon": 0, "country": "AU"}` | `Head office` at 0, 0 |
| `policy_tool` | `{"name": "the policy tool", "organization": "your-org"}` for the policy tool connector | generic name |
| `default_product_type` | Product type for connector imports that have no product yet | `Infrastructure` |
| `notify_emails` | Pre-filled recipients in new automation rules | none |
| `org_aliases` | Names an impostor might claim to speak for; the Ora assistant's guardrails watch for them | none |
| `topology` | Your documented network for the topology page (below) | an example network |

## The network drawing (`topology`)

Machines are **not** listed here. They come from the asset inventory, which the connectors keep current. The site
profile only holds the network fabric that no API describes on its own.

| Key | Meaning |
|---|---|
| `cloud_cidr` | One range or a list. Machines inside it are drawn in the cloud zone, other private addresses on-prem |
| `firewall_ip` | Private address of the cloud firewall (drawn by the model, so not drawn again from the inventory) |
| `firewall_asset` | Its name in the asset inventory (for agent status) |
| `firewall_name` | How link descriptions refer to it, e.g. `the cloud firewall` |
| `subnet_labels` | `{"10.20.2.0/24": "App subnet"}` |
| `fallback_cloud_rows` | Lines for the cloud panel when the AWS connector has no data yet |
| `zones` | Two boxes with ids `onprem` and `aws` |
| `nodes` | Fabric nodes. Ids with a meaning: `internet`, `cloudflare`, `gateway` (office gateway), `firewall` (cloud firewall), `private`. Leave out what you do not have |
| `links` | Documented links between fabric nodes. Ids with a meaning: `vpn`, `inet-firewall` |
| `lan` | `vlans` (name, cidr, vlan id) and the default restrictions for LAN links |

A node with `"fixed": true` keeps a place in the cloud column. A node with `"instance_ip"` follows the state of the
cloud instance with that address.

If you give a `topology`, your `zones`, `nodes` and `links` replace the example completely; the simple keys you leave
out keep their example values. The full example is `EXAMPLE_TOPOLOGY` in [`orasec/site.py`](../orasec/site.py); copy
it and change it.

## Example

```json
{
  "org_name": "Example Ltd",
  "security_contact": "security@example.com",
  "security_txt_url": "https://example.com/.well-known/security.txt",
  "asset_owners": ["Alex Lee - CTO", "Dana Smith - Cloud Engineer"],
  "office_cidrs": ["192.168.10.0/24"],
  "office_networks": ["Office"],
  "locations": {"cloud": "AWS Sydney", "office": "Head office"},
  "attack_map_target": {"name": "Example Ltd · Sydney", "lat": -33.87, "lon": 151.21, "country": "AU"},
  "topology": {
    "cloud_cidr": "10.20.0.0/16",
    "firewall_ip": "10.20.0.11",
    "firewall_asset": "cloud-fw"
  }
}
```

## Other settings to check on a new install

These are ordinary settings (environment variables), not part of the site profile:

- `ORASEC_TIME_ZONE` (default `Pacific/Auckland`): the schedules run in this time zone.
- `ORASEC_OIDC_ALLOWED_GROUP` (default `OraSec Users`) and `ORASEC_OIDC_BUTTON_TEXT`, when you use single sign-on.
- AWS connector option `regions` (default `["us-east-1"]`).

