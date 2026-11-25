"""
Active Directory sign-in on the normal login form (settings ORASEC_LDAP_*, plugin ``sso.ldap``).

A read-only service account finds the person, then the person's own bind proves the password. The domain
controller checks the password; OraSec never stores it.

Rules, the same as for every other way in:
- Only an existing, active OraSec account can sign in. The directory entry is matched to it by e-mail address (the
  ``mail`` attribute, else the user principal name). It is never matched by logon name: a directory account that
  happens to be called "admin" must not open a local account of that name. No account is created and no permission
  is changed.
- With ORASEC_LDAP_ALLOWED_GROUP set, the person must be a direct member of that group (name or DN).
- A disabled directory account is refused.
- The local accounts are tried first, so the break-glass login keeps working when the domain controller is down.

The password never travels in clear text: LDAPS by default, StartTLS when ORASEC_LDAP_USE_SSL is off, and the
certificate is always verified (ORASEC_LDAP_CA_CERTS for a private certificate authority).

The anonymous bind trap: a bind with a DN and an EMPTY password is an "unauthenticated bind" that many servers
answer with success. Code that passes the submitted password straight to the bind therefore lets anyone in with a
blank password. An empty password is refused here before any connection is made.

Needs the ``ldap3`` package. The unit tests use a fake directory. The whole flow was also run against a Samba 4.22
Active Directory domain controller (LDAPS and StartTLS, wrong name and unknown authority refused); it has not been
run against Windows Server yet.

Certificates: Python 3.13 and later refuse a server certificate without an Authority Key Identifier. A certificate
from a certificate authority has one; the certificate Samba generates for itself does not.
"""
import logging
import ssl

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

logger = logging.getLogger(__name__)

ATTRIBUTES = ["mail", "sAMAccountName", "userPrincipalName", "memberOf", "userAccountControl"]
ACCOUNT_DISABLED = 0x2


def available():
    try:
        import ldap3  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def configured():
    s = settings
    return bool(getattr(s, "ORASEC_LDAP_ENABLED", False) and getattr(s, "ORASEC_LDAP_HOST", "") and getattr(s, "ORASEC_LDAP_BASE_DN", "")
                and getattr(s, "ORASEC_LDAP_BIND_DN", "") and getattr(s, "ORASEC_LDAP_BIND_PASSWORD", ""))


def enabled():
    if not configured() or not available():
        return False
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    return plugins.is_on("sso.ldap")


def group_cn(dn):
    """The name of a group from its DN: "CN=OraSec Users,OU=Groups,DC=corp,DC=example" gives "OraSec Users"."""
    first = str(dn).split(",", 1)[0]
    return first.split("=", 1)[1].strip() if "=" in first else first.strip()


def in_group(member_of, allowed):
    allowed = (allowed or "").strip().lower()
    if not allowed:
        return True
    return any(allowed in {str(dn).strip().lower(), group_cn(dn).lower()} for dn in member_of or [])


def _connect(user, password):
    """A bound connection, or an exception. One place builds connections so that tests can replace it."""
    import ldap3  # noqa: PLC0415
    s = settings
    use_ssl = bool(s.ORASEC_LDAP_USE_SSL)
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=s.ORASEC_LDAP_CA_CERTS or None)
    server = ldap3.Server(s.ORASEC_LDAP_HOST, port=int(s.ORASEC_LDAP_PORT) or (636 if use_ssl else 389), use_ssl=use_ssl, tls=tls,
                          connect_timeout=10, get_info=ldap3.NONE)
    conn = ldap3.Connection(server, user=user, password=password, receive_timeout=10, read_only=True, raise_exceptions=False,
                            auto_referrals=False)
    if not use_ssl and not conn.start_tls():
        msg = "StartTLS was refused; the password is not sent without encryption"
        raise OSError(msg)
    if not conn.bind():
        conn.unbind()
        return None
    return conn


def _escape(value):
    from ldap3.utils.conv import escape_filter_chars  # noqa: PLC0415
    return escape_filter_chars(value)


def find_entry(username):
    """The one directory entry for a login name, as a dict, or None. Raises when the directory cannot be asked."""
    conn = _connect(settings.ORASEC_LDAP_BIND_DN, settings.ORASEC_LDAP_BIND_PASSWORD)
    if conn is None:
        msg = "the service account bind was rejected"
        raise OSError(msg)
    try:
        u = _escape(username)
        conn.search(settings.ORASEC_LDAP_BASE_DN,
                    f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={u})(userPrincipalName={u})(mail={u})))",
                    attributes=ATTRIBUTES, size_limit=2)
        entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
    finally:
        conn.unbind()
    if len(entries) != 1:  # none, or an ambiguous name: never guess between two people
        return None
    attrs = entries[0].get("attributes") or {}

    def one(name):
        v = attrs.get(name)
        return str((v[0] if v else "") if isinstance(v, (list, tuple)) else (v or "")).strip()

    member_of = attrs.get("memberOf") or []
    return {"dn": entries[0].get("dn") or "", "mail": one("mail"), "sam": one("sAMAccountName"), "upn": one("userPrincipalName"),
            "member_of": [member_of] if isinstance(member_of, str) else list(member_of),
            "disabled": bool(int(one("userAccountControl") or 0) & ACCOUNT_DISABLED)}


def test():
    """For the Plugins page: bind with the service account and say what the search base holds."""
    if not available():
        return False, "The ldap3 package is not installed on this server."
    try:
        conn = _connect(settings.ORASEC_LDAP_BIND_DN, settings.ORASEC_LDAP_BIND_PASSWORD)
    except Exception as e:  # shown to the administrator, without the credential
        return False, f"The domain controller could not be reached: {e.__class__.__name__}"
    if conn is None:
        return False, "The service account bind was rejected."
    conn.unbind()
    return True, "The service account can bind."


class LDAPBackend(ModelBackend):

    """Checks the password against Active Directory and returns the matching OraSec account."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password or not str(password).strip():
            return None  # the anonymous bind trap: an empty password must never reach the directory
        if not enabled():
            return None
        try:
            entry = find_entry(str(username).strip())
            if not entry or not entry["dn"]:
                return None
            if entry["disabled"]:
                logger.warning("ldap: sign-in refused: the directory account of %s is disabled", username)
                return None
            if not in_group(entry["member_of"], settings.ORASEC_LDAP_ALLOWED_GROUP):
                logger.warning("ldap: sign-in refused: %s is not in the allowed group", username)
                return None
            conn = _connect(entry["dn"], password)
            if conn is None:
                return None
            conn.unbind()
        except Exception as e:  # directory down or misconfigured: the local accounts still work
            logger.warning("ldap: the directory could not be asked: %s", e.__class__.__name__)
            return None
        user = self._account_for(entry)
        if user is None:
            logger.warning("ldap: sign-in refused: no single active OraSec account for %s", username)
            return None
        logger.info("ldap: %s signed in through Active Directory", user.username)
        return user

    def _account_for(self, entry):
        users = get_user_model().objects
        for value in (entry["mail"], entry["upn"]):
            if not value or "@" not in value:
                continue
            found = list(users.filter(email__iexact=value)[:2])
            if len(found) == 1:
                return found[0] if self.user_can_authenticate(found[0]) else None
            if len(found) > 1:
                return None
        return None

