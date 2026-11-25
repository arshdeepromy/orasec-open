"""
AWS connector: inventory, security-group exposure and cloud security posture (CSPM).

Credentials: an IAM user with the AWS-managed SecurityAudit + ViewOnlyAccess policies (read-only).
username = access key id; secrets {"secret_access_key": "..."}.
Options: {"regions": ["us-east-1"], "account_name": "Example", "product_name": "Infrastructure",
          "stopped_days": 30, "key_age_days": 90, "security_hub": true, "guardduty": true, "inspector": true}

Other ways to sign in (all read-only, nothing is written to AWS):
- Temporary credentials: add the secret ``session_token`` next to the key pair.
- No key at all: leave the user name and the secret blank and the server's own identity is used (instance profile,
  task role, environment), through the usual AWS credential chain.
- Another account: option ``role_arn`` (and ``external_id`` when the role asks for one). The identity above assumes
  that role for each run and reads with it; the role needs SecurityAudit + ViewOnlyAccess and must trust the
  identity. One connector for each account covers an organisation from one central identity.

Checks (each records a finding that closes automatically when fixed):
  IAM: root MFA / root access keys, console users without MFA, stale access keys, password policy
  Logging & detection: multi-region CloudTrail, GuardDuty, VPC flow logs, Security Hub
  Network: security groups open to 0.0.0.0/0 or ::/0 (all traffic / admin & database ports), default VPCs,
           default security groups that allow traffic, public RDS
  Data: S3 public-access block / public policy, unencrypted EBS / RDS, RDS backups
  Compute: IMDSv1, long-stopped instances, deprecated Lambda runtimes
  Native services: GuardDuty, Security Hub and Inspector findings are imported as findings
"""
import csv
import datetime
import io
import time

from orasec.posture.connectors.base import AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 5900: "VNC", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
               1433: "MSSQL", 1521: "Oracle", 6379: "Redis", 27017: "MongoDB", 9200: "OpenSearch", 11211: "Memcached", 2375: "Docker API"}
DEPRECATED_RUNTIMES = ("python2", "python3.6", "python3.7", "python3.8", "nodejs10", "nodejs12", "nodejs14", "nodejs16", "ruby2.5", "ruby2.7",
                       "java8", "dotnetcore2", "dotnetcore3", "dotnet5", "go1.x")
SEV_GD = [(7.0, "High"), (4.0, "Medium"), (0.0, "Low")]
SEV_SH = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFORMATIONAL": "Info"}


def _name(tags, default):
    return next((t["Value"] for t in tags or [] if t.get("Key") == "Name"), default)


@register
class AWSConnector(BaseConnector):
    kind = "aws"
    secret_fields = ("secret_access_key", "session_token")
    _role = None  # credentials of the assumed role, kept for the run

    def _session(self, region=None):
        try:
            import boto3  # noqa: PLC0415
        except ImportError as e:
            msg = "boto3 is not installed"
            raise ConnectorError(msg) from e
        region = region or self.regions[0]
        key = (self.connector.username or "").strip()
        if key:
            own = boto3.session.Session(aws_access_key_id=key, aws_secret_access_key=self.secrets.get("secret_access_key", ""),
                                        aws_session_token=self.secrets.get("session_token") or None, region_name=region)
        else:
            own = boto3.session.Session(region_name=region)  # the server's own identity
        arn = (self.options.get("role_arn") or "").strip()
        if not arn:
            return own
        now = datetime.datetime.now(datetime.UTC)
        if not self._role or self._role["Expiration"] - now < datetime.timedelta(minutes=5):
            kw = {"RoleArn": arn, "RoleSessionName": "orasec-connector", "DurationSeconds": 3600}
            if self.options.get("external_id"):
                kw["ExternalId"] = str(self.options["external_id"])
            try:
                self._role = own.client("sts").assume_role(**kw)["Credentials"]
            except Exception as e:
                self.log.append(f"sts.assume_role -> {e.__class__.__name__}")
                msg = f"The role {arn} could not be assumed: {e.__class__.__name__}: {str(e)[:200]}"
                raise ConnectorError(msg) from e
            self.log.append("sts.assume_role -> ok")
        return boto3.session.Session(aws_access_key_id=self._role["AccessKeyId"], aws_secret_access_key=self._role["SecretAccessKey"],
                                     aws_session_token=self._role["SessionToken"], region_name=region)

    @property
    def regions(self):
        return self.options.get("regions") or ["us-east-1"]

    def _call(self, fn, *a, **kw):
        t0 = time.monotonic()
        try:
            r = fn(*a, **kw)
            self.log.append(f"{fn.__self__.meta.service_model.service_name}.{fn.__name__} -> ok ({int((time.monotonic() - t0) * 1000)} ms)")
            return r
        except Exception as e:
            self.log.append(f"{getattr(getattr(fn, '__self__', None), 'meta', None) and fn.__self__.meta.service_model.service_name}.{fn.__name__} -> {e.__class__.__name__}")
            raise

    def _pages(self, client, op, key, **kw):
        out = []
        for page in client.get_paginator(op).paginate(**kw):
            out.extend(page.get(key, []))
        self.log.append(f"{client.meta.service_model.service_name}.{op} -> {len(out)} items")
        return out

    def test(self):
        ident = self._session().client("sts").get_caller_identity()
        return f"AWS account {ident['Account']} as {ident['Arn'].split('/')[-1]}"

    def _flow_rejects(self, res):
        """Read REJECT records (default v2 flow-log format) for the last N hours and store them as attack events.
        Needs logs:FilterLogEvents on the group (not part of SecurityAudit/ViewOnlyAccess)."""
        import datetime as _dt  # noqa: PLC0415

        from django.utils import timezone as _tz  # noqa: PLC0415

        from orasec.posture import geo  # noqa: PLC0415
        group = self.options["flow_log_group"]
        region = self.options.get("flow_log_region") or self.regions[0]
        names = self.options.get("flow_log_targets") or {}          # private ip -> label, e.g. {"10.20.0.11": "cloud-fw"}
        hours = int(self.options.get("attack_window_hours", 24))
        start = int((_tz.now() - _dt.timedelta(hours=hours)).timestamp() * 1000)
        logs = self._session(region).client("logs")
        events, token, pages = [], None, 0
        try:
            while pages < int(self.options.get("flow_log_max_pages", 20)):
                kw = {"logGroupName": group, "startTime": start, "filterPattern": "REJECT", "limit": 10000}
                if token:
                    kw["nextToken"] = token
                r = logs.filter_log_events(**kw)
                pages += 1
                for ev in r.get("events", []):
                    f = ev["message"].split()
                    if len(f) < 14 or f[12] != "REJECT":
                        continue
                    _v, _acct, eni, src, dst, sport, dport, proto, pkts, _b, t0, _t1, _act, _st = f[:14]
                    events.append({"event_id": f"flow:{eni}:{src}:{dst}:{dport}:{proto}:{t0}", "src_ip": src,
                                   "occurred_at": _dt.datetime.fromtimestamp(int(t0), tz=_dt.UTC), "dst_ip": dst,
                                   "dst_port": int(dport) if dport.isdigit() else None, "protocol": {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto, proto),
                                   "target": names.get(dst, dst), "action": "block", "hits": int(pkts) if pkts.isdigit() else 1,
                                   "rule": "AWS security group (edge)", "detail": f"VPC flow log REJECT on {eni}"})
                token = r.get("nextToken")
                if not token:
                    break
            res.stats["sg_rejects"] = len(events)
            res.stats["attack_events_new"] = geo.store_events("aws", events)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"flow-log rejects unavailable ({e.__class__.__name__}: {str(e)[:120]})")

    def collect(self):  # noqa: C901, PLR0912, PLR0915
        res = CollectResult()
        f = []
        sess = self._session()
        acct = sess.client("sts").get_caller_identity()["Account"]
        aname = self.options.get("account_name", acct)
        host = f"aws:{acct}"
        topo = {"account": acct, "regions": {}}

        def add(title, sev, desc, uid, mitig="", comp="aws", tags=(), refs=""):
            f.append({"title": title, "severity": sev, "description": desc, "mitigation": mitig, "unique_id": f"aws:{acct}:{uid}",
                      "component_name": comp, "host": host, "tags": ["aws", "cspm", *tags], "references": refs})

        # ---------------- IAM (global) ----------------
        iam = sess.client("iam")
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if not summary.get("AccountMFAEnabled"):
                add("AWS root account has no MFA", "Critical", "The root user of the account does not have MFA enabled.", "iam:root-mfa",
                    "Enable a hardware or virtual MFA device on the root user and lock the credentials away.", "iam", ["iam", "mfa"])
            if summary.get("AccountAccessKeysPresent"):
                add("AWS root account has access keys", "Critical", "The root user has programmatic access keys.", "iam:root-keys",
                    "Delete the root access keys; use IAM users/roles instead.", "iam", ["iam"])
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"IAM summary unavailable ({e.__class__.__name__})")
        try:
            for _ in range(10):
                if iam.generate_credential_report()["State"] == "COMPLETE":
                    break
                time.sleep(2)
            rep = list(csv.DictReader(io.StringIO(iam.get_credential_report()["Content"].decode())))
            now = datetime.datetime.now(datetime.UTC)
            age_days = int(self.options.get("key_age_days", 90))
            res.stats["iam_users"] = len(rep) - 1
            for u in rep:
                if u["user"] == "<root_account>":
                    continue
                if u.get("password_enabled") == "true" and u.get("mfa_active") != "true":
                    add(f"IAM console user without MFA: {u['user']}", "High", f"IAM user **{u['user']}** can sign in to the console without MFA.",
                        f"iam:user-mfa:{u['user']}", "Enforce MFA (IAM policy with aws:MultiFactorAuthPresent) and register a device.", "iam", ["iam", "mfa"])
                for n in ("1", "2"):
                    if u.get(f"access_key_{n}_active") == "true" and u.get(f"access_key_{n}_last_rotated", "N/A") not in ("N/A", ""):
                        rot = datetime.datetime.fromisoformat(u[f"access_key_{n}_last_rotated"].replace("Z", "+00:00"))
                        if (now - rot).days > age_days:
                            add(f"Access key older than {age_days} days: {u['user']}", "Medium",
                                f"Access key {n} of **{u['user']}** was last rotated {(now - rot).days} days ago.",
                                f"iam:key-age:{u['user']}:{n}", "Rotate the key and remove the old one.", "iam", ["iam", "key-rotation"])
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"credential report unavailable ({e.__class__.__name__})")
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            add("No IAM password policy", "Medium", "The account has no IAM password policy.", "iam:password-policy",
                "Set a password policy (length ≥ 14, reuse prevention).", "iam", ["iam"])
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"password policy unavailable ({e.__class__.__name__})")

        # ---------------- S3 (global) ----------------
        s3 = sess.client("s3")
        try:
            try:
                acct_pab = sess.client("s3control").get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"]
            except Exception:  # noqa: BLE001
                acct_pab = {}
            acct_blocked = acct_pab and all(acct_pab.values())
            for b in s3.list_buckets().get("Buckets", []):
                bn = b["Name"]
                res.assets.append(AssetRecord(key=f"s3:{bn}", name=f"s3://{bn}", asset_type="application", vendor="AWS", model="S3 bucket",
                                              attributes={"account": acct}))
                try:
                    pab = s3.get_public_access_block(Bucket=bn)["PublicAccessBlockConfiguration"]
                    blocked = all(pab.values())
                except Exception:  # noqa: BLE001
                    blocked = False
                if not blocked and not acct_blocked:
                    add(f"S3 bucket without Block Public Access: {bn}", "High", f"Bucket **{bn}** does not have all four Block Public Access settings (bucket or account).",
                        f"s3:{bn}:pab", "Enable Block Public Access at account and bucket level.", "s3", ["s3", "data"])
                try:
                    if s3.get_bucket_policy_status(Bucket=bn)["PolicyStatus"].get("IsPublic"):
                        add(f"S3 bucket policy is public: {bn}", "Critical", f"The bucket policy of **{bn}** grants public access.",
                            f"s3:{bn}:public-policy", "Remove public principals from the bucket policy.", "s3", ["s3", "data"])
                except Exception:  # noqa: BLE001, S110 no policy
                    pass
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"S3 unavailable ({e.__class__.__name__})")

        # ---------------- per region ----------------
        for region in self.regions:
            rs = self._session(region)
            ec2 = rs.client("ec2")
            rt = topo["regions"][region] = {"vpcs": [], "subnets": [], "security_groups": [], "instances": [], "igws": [], "nat": [],
                                           "route_tables": [], "rds": [], "elb": [], "lambda": []}
            try:
                vpcs = self._pages(ec2, "describe_vpcs", "Vpcs")
                flow = {fl["ResourceId"] for fl in self._pages(ec2, "describe_flow_logs", "FlowLogs")}
                for v in vpcs:
                    rt["vpcs"].append({"id": v["VpcId"], "cidr": v["CidrBlock"], "default": v.get("IsDefault"), "name": _name(v.get("Tags"), v["VpcId"])})
                    if v.get("IsDefault"):
                        add(f"Default VPC present in {region}", "Low", f"Default VPC {v['VpcId']} exists. Default VPCs have public subnets and an internet gateway.",
                            f"{region}:vpc:{v['VpcId']}:default", "Delete unused default VPCs.", "vpc", ["network-security"])
                    if v["VpcId"] not in flow and not v.get("IsDefault"):
                        add(f"VPC flow logs disabled: {_name(v.get('Tags'), v['VpcId'])}", "Medium", f"VPC {v['VpcId']} ({v['CidrBlock']}) has no flow logs.",
                            f"{region}:vpc:{v['VpcId']}:flowlogs", "Enable VPC flow logs to CloudWatch Logs or S3 (ISO 27001 A.8.15).", "vpc", ["logging"])
                rt["subnets"] = [{"id": s["SubnetId"], "vpc": s["VpcId"], "cidr": s["CidrBlock"], "az": s["AvailabilityZone"],
                                  "public_ip_on_launch": s.get("MapPublicIpOnLaunch"), "name": _name(s.get("Tags"), s["SubnetId"])}
                                 for s in self._pages(ec2, "describe_subnets", "Subnets")]
                rt["igws"] = [{"id": g["InternetGatewayId"], "vpcs": [a["VpcId"] for a in g.get("Attachments", [])]}
                              for g in self._pages(ec2, "describe_internet_gateways", "InternetGateways")]
                rt["nat"] = [{"id": n["NatGatewayId"], "subnet": n.get("SubnetId"), "state": n.get("State")}
                             for n in self._pages(ec2, "describe_nat_gateways", "NatGateways")]
                rt["route_tables"] = [{"id": r["RouteTableId"], "vpc": r["VpcId"], "subnets": [a.get("SubnetId") for a in r.get("Associations", []) if a.get("SubnetId")],
                                       "routes": [{"dst": x.get("DestinationCidrBlock"), "via": x.get("GatewayId") or x.get("NatGatewayId") or x.get("NetworkInterfaceId") or x.get("InstanceId")}
                                                  for x in r.get("Routes", [])]} for r in self._pages(ec2, "describe_route_tables", "RouteTables")]
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: VPC data unavailable ({e.__class__.__name__})")

            # security groups
            attached = set()
            try:
                for ni in self._pages(ec2, "describe_network_interfaces", "NetworkInterfaces"):
                    attached.update(g["GroupId"] for g in ni.get("Groups", []))
                for g in self._pages(ec2, "describe_security_groups", "SecurityGroups"):
                    sgd = {"id": g["GroupId"], "name": g["GroupName"], "vpc": g.get("VpcId"), "description": g.get("Description"), "in_use": g["GroupId"] in attached,
                           "ingress": [], "egress": []}
                    for direction, perms in (("ingress", g.get("IpPermissions", [])), ("egress", g.get("IpPermissionsEgress", []))):
                        for p in perms:
                            proto = "all" if p.get("IpProtocol") == "-1" else p.get("IpProtocol")
                            ports = "all" if proto == "all" else (str(p.get("FromPort")) if p.get("FromPort") == p.get("ToPort") else f"{p.get('FromPort')}-{p.get('ToPort')}")
                            srcs = [(r["CidrIp"], r.get("Description", "")) for r in p.get("IpRanges", [])] + \
                                   [(r["CidrIpv6"], r.get("Description", "")) for r in p.get("Ipv6Ranges", [])] + \
                                   [(f"sg:{r['GroupId']}", r.get("Description", "")) for r in p.get("UserIdGroupPairs", [])] + \
                                   [(f"pl:{r['PrefixListId']}", r.get("Description", "")) for r in p.get("PrefixListIds", [])]
                            for src, desc in srcs:
                                sgd[direction].append({"proto": proto, "ports": ports, "peer": src, "description": desc})
                                if direction == "ingress" and src in ("0.0.0.0/0", "::/0"):
                                    sev_boost = g["GroupId"] in attached
                                    if proto == "all":
                                        add(f"Security group allows ALL traffic from the internet: {g['GroupName']}", "Critical" if sev_boost else "Medium",
                                            f"{g['GroupId']} ({g['GroupName']}) allows all protocols/ports from {src}. In use: {sev_boost}.",
                                            f"{region}:sg:{g['GroupId']}:all:{src}", "Remove the rule; allow only required ports from known sources.",
                                            "security-group", ["firewall", "network-security"])
                                    else:
                                        lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
                                        for port, svc in ADMIN_PORTS.items():
                                            if lo <= port <= hi:
                                                add(f"{svc} ({port}) open to the internet: {g['GroupName']}", "High" if sev_boost else "Medium",
                                                    f"{g['GroupId']} ({g['GroupName']}) allows {proto}/{ports} from {src}, exposing {svc}. In use: {sev_boost}.",
                                                    f"{region}:sg:{g['GroupId']}:{port}:{src}", "Restrict to the VPN/office CIDR or use SSM Session Manager.",
                                                    "security-group", ["firewall", "network-security"])
                    if g["GroupName"] == "default" and (g.get("IpPermissions") and any(p.get("IpRanges") or p.get("Ipv6Ranges") for p in g["IpPermissions"])):
                        add(f"Default security group allows traffic ({g.get('VpcId')})", "Low", f"The default security group {g['GroupId']} has CIDR-based ingress rules.",
                            f"{region}:sg:{g['GroupId']}:default", "Remove all rules from default security groups (CIS 5.4).", "security-group", ["network-security"])
                    rt["security_groups"].append(sgd)
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: security groups unavailable ({e.__class__.__name__})")

            # instances + volumes
            try:
                vols = {v["VolumeId"]: v for v in self._pages(ec2, "describe_volumes", "Volumes")}
                for r in self._pages(ec2, "describe_instances", "Reservations"):
                    for i in r["Instances"]:
                        nm = _name(i.get("Tags"), i["InstanceId"])
                        state = i["State"]["Name"]
                        sgs = [g["GroupId"] for g in i.get("SecurityGroups", [])]
                        rt["instances"].append({"id": i["InstanceId"], "name": nm, "state": state, "type": i.get("InstanceType"), "private_ip": i.get("PrivateIpAddress"),
                                                "public_ip": i.get("PublicIpAddress"), "subnet": i.get("SubnetId"), "vpc": i.get("VpcId"), "sgs": sgs,
                                                "role": next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Role"), "")})
                        if state != "terminated":
                            res.assets.append(AssetRecord(key=f"ec2:{i['InstanceId']}", name=nm, hostname=nm, asset_type="cloud_instance",
                                ip_address=i.get("PrivateIpAddress") or "", vendor="AWS", model=i.get("InstanceType", ""), online=state == "running",
                                internet_exposed=bool(i.get("PublicIpAddress")), scanned=False,
                                attributes={"instance_id": i["InstanceId"], "region": region, "state": state, "public_ip": i.get("PublicIpAddress"),
                                            "subnet": i.get("SubnetId"), "vpc": i.get("VpcId"), "security_groups": sgs, "arch": i.get("Architecture")}))
                        if state == "running" and i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                            add(f"IMDSv1 enabled: {nm}", "Medium", f"Instance {i['InstanceId']} ({nm}) allows IMDSv1 (token-less metadata), which SSRF can abuse.",
                                f"{region}:ec2:{i['InstanceId']}:imdsv1", "Require IMDSv2 (HttpTokens=required).", "ec2", ["hardening"])
                        if state == "stopped":
                            reason = i.get("StateTransitionReason", "")
                            when = None
                            if "(" in reason and "GMT" in reason:
                                try:
                                    when = datetime.datetime.strptime(reason.split("(")[1].split(" GMT")[0], "%Y-%m-%d %H:%M:%S")
                                except ValueError:
                                    when = None
                            days = (datetime.datetime.utcnow() - when).days if when else None
                            if days is None or days >= int(self.options.get("stopped_days", 30)):
                                add(f"Long-stopped EC2 instance: {nm}", "Low", f"Instance {i['InstanceId']} ({nm}) has been stopped{f' for {days} days' if days is not None else ''}. "
                                    "Stopped instances keep volumes, keys and IAM roles and miss patches.", f"{region}:ec2:{i['InstanceId']}:stopped",
                                    "Terminate it (after snapshot if needed) or start and patch it.", "ec2", ["hygiene"])
                        for bdm in i.get("BlockDeviceMappings", []):
                            vid = bdm.get("Ebs", {}).get("VolumeId")
                            if vid in vols and not vols[vid].get("Encrypted"):
                                add(f"Unencrypted EBS volume on {nm}", "Medium", f"Volume {vid} attached to {nm} is not encrypted.",
                                    f"{region}:ebs:{vid}:encryption", "Enable EBS encryption by default and migrate the volume via an encrypted snapshot.",
                                    "ebs", ["crypto", "data"])
                try:
                    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
                        add(f"EBS encryption by default is off ({region})", "Medium", "New EBS volumes are not encrypted by default.",
                            f"{region}:ebs:default-encryption", "Turn on EBS encryption by default in the EC2 settings.", "ebs", ["crypto"])
                except Exception:  # noqa: BLE001, S110
                    pass
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: EC2 unavailable ({e.__class__.__name__})")

            # RDS
            try:
                rds = rs.client("rds")
                for d in self._pages(rds, "describe_db_instances", "DBInstances"):
                    rt["rds"].append({"id": d["DBInstanceIdentifier"], "engine": d["Engine"], "public": d.get("PubliclyAccessible"), "encrypted": d.get("StorageEncrypted"),
                                      "vpc": (d.get("DBSubnetGroup") or {}).get("VpcId"), "endpoint": (d.get("Endpoint") or {}).get("Address")})
                    res.assets.append(AssetRecord(key=f"rds:{d['DBInstanceIdentifier']}", name=d["DBInstanceIdentifier"], asset_type="application", vendor="AWS",
                                                  model=f"RDS {d['Engine']} {d.get('EngineVersion')}", online=d.get("DBInstanceStatus") == "available",
                                                  internet_exposed=bool(d.get("PubliclyAccessible"))))
                    if d.get("PubliclyAccessible"):
                        add(f"RDS instance publicly accessible: {d['DBInstanceIdentifier']}", "High", "The database has a public endpoint.",
                            f"{region}:rds:{d['DBInstanceIdentifier']}:public", "Set PubliclyAccessible=false and use private subnets.", "rds", ["network-security", "data"])
                    if not d.get("StorageEncrypted"):
                        add(f"RDS storage not encrypted: {d['DBInstanceIdentifier']}", "High", "Database storage is not encrypted at rest.",
                            f"{region}:rds:{d['DBInstanceIdentifier']}:encryption", "Restore from an encrypted snapshot.", "rds", ["crypto", "data"])
                    if d.get("BackupRetentionPeriod", 0) == 0:
                        add(f"RDS automated backups disabled: {d['DBInstanceIdentifier']}", "Medium", "Backup retention is 0 days.",
                            f"{region}:rds:{d['DBInstanceIdentifier']}:backup", "Set a backup retention period (ISO 27001 A.8.13).", "rds", ["backup"])
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: RDS unavailable ({e.__class__.__name__})")

            # ELB and Lambda (inventory + deprecated runtimes)
            try:
                elb = rs.client("elbv2")
                for lb in self._pages(elb, "describe_load_balancers", "LoadBalancers"):
                    rt["elb"].append({"name": lb["LoadBalancerName"], "scheme": lb.get("Scheme"), "dns": lb.get("DNSName"), "vpc": lb.get("VpcId"), "type": lb.get("Type")})
                    res.assets.append(AssetRecord(key=f"elb:{lb['LoadBalancerName']}", name=lb["LoadBalancerName"], asset_type="network_device", vendor="AWS",
                                                  model=f"{lb.get('Type')} load balancer", internet_exposed=lb.get("Scheme") == "internet-facing"))
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: ELB unavailable ({e.__class__.__name__})")
            try:
                lam = rs.client("lambda")
                for fn in self._pages(lam, "list_functions", "Functions"):
                    rt["lambda"].append({"name": fn["FunctionName"], "runtime": fn.get("Runtime")})
                    if any(str(fn.get("Runtime", "")).startswith(d) for d in DEPRECATED_RUNTIMES):
                        add(f"Deprecated Lambda runtime: {fn['FunctionName']} ({fn.get('Runtime')})", "Medium", "The runtime no longer receives security patches.",
                            f"{region}:lambda:{fn['FunctionName']}:runtime", "Upgrade to a supported runtime.", "lambda", ["end-of-life"])
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: Lambda unavailable ({e.__class__.__name__})")

            # CloudTrail
            try:
                trails = rs.client("cloudtrail").describe_trails().get("trailList", [])
                multi = [t for t in trails if t.get("IsMultiRegionTrail")]
                res.stats.setdefault("cloudtrail", {})[region] = [t["Name"] for t in trails]
                if not multi:
                    add("No multi-region CloudTrail trail", "High", "No CloudTrail trail records API activity across all regions.",
                        "cloudtrail:multi-region", "Create a multi-region trail with log file validation to an S3 bucket with restricted access (ISO 27001 A.8.15).",
                        "cloudtrail", ["logging"])
            except Exception as e:  # noqa: BLE001
                res.warnings.append(f"{region}: CloudTrail unavailable ({e.__class__.__name__})")

            # GuardDuty
            if self.options.get("guardduty", True):
                try:
                    gd = rs.client("guardduty")
                    dets = gd.list_detectors().get("DetectorIds", [])
                    if not dets:
                        add(f"GuardDuty not enabled ({region})", "Medium", "Amazon GuardDuty threat detection is not enabled.",
                            f"{region}:guardduty:off", "Enable GuardDuty (ISO 27001 A.8.16).", "guardduty", ["monitoring"])
                    for det in dets:
                        ids = self._pages(gd, "list_findings", "FindingIds", DetectorId=det, FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}})
                        for i in range(0, len(ids), 50):
                            for x in gd.get_findings(DetectorId=det, FindingIds=ids[i:i + 50]).get("Findings", []):
                                sev = next(s for t, s in SEV_GD if x.get("Severity", 0) >= t)
                                f.append({"title": f"GuardDuty: {x.get('Title')}", "severity": sev, "description": x.get("Description", ""),
                                          "unique_id": f"aws:{acct}:guardduty:{x['Id']}", "component_name": x.get("Type", "guardduty"), "host": host,
                                          "tags": ["aws", "guardduty", "threat"], "date": str(x.get("UpdatedAt", ""))[:10],
                                          "mitigation": "Investigate per the GuardDuty finding type remediation guidance."})
                except Exception as e:  # noqa: BLE001
                    res.warnings.append(f"{region}: GuardDuty unavailable ({e.__class__.__name__})")

            # Security Hub
            if self.options.get("security_hub", True):
                try:
                    sh = rs.client("securityhub")
                    flt = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}], "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
                           "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]}
                    for x in self._pages(sh, "get_findings", "Findings", Filters=flt)[:2000]:
                        f.append({"title": f"Security Hub: {x.get('Title')}"[:500], "severity": SEV_SH.get((x.get("Severity") or {}).get("Label"), "Low"),
                                  "description": x.get("Description", ""), "mitigation": ((x.get("Remediation") or {}).get("Recommendation") or {}).get("Text", ""),
                                  "references": ((x.get("Remediation") or {}).get("Recommendation") or {}).get("Url", ""),
                                  "unique_id": f"aws:{acct}:securityhub:{x['Id']}"[:480], "component_name": (x.get("Resources") or [{}])[0].get("Type", "aws"),
                                  "host": host, "tags": ["aws", "security-hub", "cspm"]})
                except Exception as e:  # noqa: BLE001
                    name = e.__class__.__name__
                    if "InvalidAccess" in name or "NotSubscribed" in str(e):
                        add(f"Security Hub not enabled ({region})", "Low", "AWS Security Hub (CSPM standards) is not enabled.",
                            f"{region}:securityhub:off", "Enable Security Hub with the AWS Foundational Security Best Practices standard.", "securityhub", ["cspm"])
                    else:
                        res.warnings.append(f"{region}: Security Hub unavailable ({name})")

            # Inspector (CVEs on EC2 / ECR / Lambda)
            if self.options.get("inspector", True):
                try:
                    insp = rs.client("inspector2")
                    for x in self._pages(insp, "list_findings", "findings", filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]})[:3000]:
                        pkg = (x.get("packageVulnerabilityDetails") or {})
                        cve = pkg.get("vulnerabilityId", "")
                        res_id = (x.get("resources") or [{}])[0].get("id", "")
                        f.append({"title": f"{cve or x.get('title')} on {res_id}"[:500], "severity": SEV_SH.get(x.get("severity"), "Low"),
                                  "description": x.get("description", ""), "cves": [cve] if cve.startswith("CVE-") else [],
                                  "component_name": ((pkg.get("vulnerablePackages") or [{}])[0]).get("name", ""),
                                  "component_version": ((pkg.get("vulnerablePackages") or [{}])[0]).get("version", ""),
                                  "fix_version": ((pkg.get("vulnerablePackages") or [{}])[0]).get("fixedInVersion", ""),
                                  "unique_id": f"aws:{acct}:inspector:{x['findingArn'].split('/')[-1]}", "host": res_id or host,
                                  "tags": ["aws", "inspector"]})
                except Exception as e:  # noqa: BLE001
                    if e.__class__.__name__ == "EndpointConnectionError":  # service not offered in this region
                        res.stats.setdefault("services_not_in_region", []).append(f"inspector2:{region}")
                    else:
                        res.warnings.append(f"{region}: Inspector unavailable ({e.__class__.__name__})")

        # cloud edge: security-group REJECTs from VPC Flow Logs (CloudWatch Logs) -> attack map
        if self.options.get("flow_log_group"):
            self._flow_rejects(res)
        res.stats["topology"] = topo
        res.stats["findings_by_check"] = len(f)
        res.batches.append(TestBatch(title=f"AWS CSPM: {aname} ({acct})", scan_type="OraSec AWS", payload={"findings": f}, count=len(f),
                                     product_name=self.options.get("product_name")))
        return res

