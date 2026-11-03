#!/usr/bin/env python3
"""An independent check of the app manifest vector file, written without Go.

Everything here is rebuilt from the prose in app-manifest/app-manifest.schema.json
(the descriptions of the manifest, release_digest, encrypted_machine, placement,
secrets, resources, network and the store, front_and_back_end, when_down and
backup definitions) and from ADR-012 Amendment 5, not from the Go code. Each
vector is read, the rules are applied to its manifest, and the outcome (accepted
or refused) and the row a refusal is about must be the ones the file states. If
this script and the vector file ever disagree, the prose no longer says what
the code does.

Run: python3 check_app_manifest_vectors.py app-manifest-vectors.json
Needs nothing beyond the Python standard library.
"""
import json
import sys

failures = []

# Unicode White_Space: a name with no character outside this set is not a name.
WHITE_SPACE = set("\t\n\v\f\r \u0085      　") | {chr(c) for c in range(0x2000, 0x200B)}
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGIT = "0123456789"
HEX = "0123456789abcdef"

APP_ROWS = ["release_digest", "encrypted_machine", "store", "placement", "front_and_back_end", "secrets", "when_down", "backup"]


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def digest(value, algorithm):
    """algorithm, ':' and exactly 64 lower-case hex digits."""
    if not isinstance(value, str) or not value.startswith(algorithm + ":"):
        return False
    h = value[len(algorithm) + 1:]
    return len(h) == 64 and all(c in HEX for c in h)


def token(value, extra, longest):
    """A lower-case letter, then lower-case letters, digits and the extras."""
    if not isinstance(value, str) or not 1 <= len(value) <= longest or value[0] not in LOWER:
        return False
    return all(c in LOWER + DIGIT + extra for c in value[1:])


def label(l):
    """1 to 63 lower-case letters, digits or '-', and not '-' at either end."""
    return (1 <= len(l) <= 63 and l[0] != "-" and l[-1] != "-"
            and all(c in LOWER + DIGIT + "-" for c in l))


def port(p):
    """1 to 65535, decimal digits, no leading zero."""
    return 1 <= len(p) <= 5 and p[0] != "0" and all(c in DIGIT for c in p) and int(p) <= 65535


def outbound_host(entry):
    """host | host:port | *.host | **.host | either wildcard with :port."""
    if not isinstance(entry, str):
        return False
    parts = entry.split(":")
    if len(parts) > 2:
        return False
    if len(parts) == 2 and not port(parts[1]):
        return False
    name = parts[0]
    if not 1 <= len(name) <= 253:
        return False
    least = 1
    if name.startswith("**."):
        name, least = name[3:], 2
    elif name.startswith("*."):
        name, least = name[2:], 2
    if all(c in DIGIT + "." for c in name):  # an IP address, or nothing
        return False
    labels = name.split(".")
    return len(labels) >= least and all(label(l) for l in labels)


def static_url(u):
    """https:// then an exact host (no wildcard), optional :port, optional path."""
    if not isinstance(u, str) or not u.startswith("https://"):
        return False
    rest = u[len("https://"):]
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    if authority.startswith("*") or not outbound_host(authority):
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + LOWER + DIGIT + "-._~!$&'()*+,;=:@/")
    i = 0
    while i < len(path):
        c = path[i]
        if c in allowed:
            i += 1
        elif c == "%" and len(path) >= i + 3 and all(x in "0123456789abcdefABCDEF" for x in path[i + 1:i + 3]):
            i += 3
        else:
            return False
    return True


def refuse(row, why):
    return (row, why)


# The keys each object has, spelt exactly, from the properties the schema
# declares. A key not listed is refused at every depth.
KEYS = {
    "manifest": "id name description version author execution_type display_method network_mode container binary "
                "resources network capabilities log_level signature publisher_key signature_algorithm api_schema "
                "kind sub_type provides host_control supported_platforms isolation release_digest encrypted_machine "
                "store placement front_and_back_end secrets when_down backup".split(),
    "container": "image ports environment volumes display_path".split(),
    "binary": "path args environment hash".split(),
    "resources": "cpu_cores memory_mb disk_mb egress_kbps ingress_kbps".split(),
    "network": "tls_mode allowed_domains blocked_domains".split(),
    "capabilities": "allowed blocked".split(),
    "provided_capability": "id name description request_contract docs acdc_scope enabled_by_default host_control "
                           "require_signed_request minimum_score".split(),
    "host_control": "grants_required kill_switch".split(),
    "platform_binary": "os min_version arch binary hash".split(),
    "store": "format size_mb".split(),
    "front_and_back_end": "static_front_end_url back_end_port device_front_ends".split(),
    "when_down": "person_sees queue_requests queue_max_seconds".split(),
    "backup": "what every_hours".split(),
}
# Which object (or list of objects) a key holds.
CHILD = {
    ("manifest", "container"): ("object", "container"), ("manifest", "binary"): ("object", "binary"),
    ("manifest", "resources"): ("object", "resources"), ("manifest", "network"): ("object", "network"),
    ("manifest", "capabilities"): ("object", "capabilities"), ("manifest", "provides"): ("list", "provided_capability"),
    ("manifest", "host_control"): ("object", "host_control"),
    ("manifest", "supported_platforms"): ("list", "platform_binary"), ("manifest", "store"): ("object", "store"),
    ("manifest", "front_and_back_end"): ("object", "front_and_back_end"),
    ("manifest", "when_down"): ("object", "when_down"), ("manifest", "backup"): ("object", "backup"),
}
# The only keys that may hold null; a key with no value is left out.
NULLABLE = {"signature", "publisher_key", "signature_algorithm", "api_schema", "binary.args", "binary.environment"}
# Keys whose value is never the empty string.
NOT_EMPTY = {"kind", "sub_type", "isolation", "release_digest", "encrypted_machine", "placement"}


def shape(value, kind, path):
    """(row, why) for the first unknown key, null or forbidden empty string, else None."""
    if isinstance(value, dict):
        for key in sorted(value):
            here = path + "." + key if path else key
            if kind in KEYS and key not in KEYS[kind]:
                # The row is the object that holds the stray key; at the top, the key.
                return (path or key, "not a key a manifest has (keys are spelt exactly)")
            if value[key] is None:
                if here not in NULLABLE:
                    return (here, "null is not a value, the key is left out")
                continue
            if kind == "manifest" and key in NOT_EMPTY and value[key] == "":
                return (here, "never empty")
            sub = CHILD.get((kind, key))
            if sub and sub[0] == "object":
                found = shape(value[key], sub[1], here)
            elif sub:
                found = None
                for i, item in enumerate(value[key] if isinstance(value[key], list) else []):
                    found = found or shape(item, sub[1], "%s[%d]" % (here, i))
            else:
                found = shape(value[key], None, here)
            if found:
                return found
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if item is None:
                return ("%s[%d]" % (path, i), "null is not a value")
            found = shape(item, None, "%s[%d]" % (path, i))
            if found:
                return found
    return None


def check(m):
    """None if the app manifest is accepted, else (row, why)."""
    bad = shape(m, "manifest", "")
    if bad:
        return bad
    if m.get("kind") != "app":
        for r in APP_ROWS:
            if r in m:
                return refuse(r, "a row of an app, on a manifest that is not one")
        return None
    name = m.get("name")
    if not isinstance(name, str) or all(c in WHITE_SPACE for c in name):
        return refuse("name", "no character that is not white space")
    if m.get("isolation") == "host":
        return refuse("isolation", "an app is never a host plug-in")
    # The release and its one name.
    kind = m.get("execution_type")
    algorithm = "sha256" if kind == "container" else "blake3"
    if "release_digest" not in m:
        return refuse("release_digest", "missing")
    if not digest(m["release_digest"], algorithm):
        return refuse("release_digest", "not a %s digest" % algorithm)
    if m.get("supported_platforms"):
        return refuse("supported_platforms", "an app is one release")
    # An app is its executable or its image, never both.
    if kind == "compiled" and "container" in m:
        return refuse("container", "a compiled app is its executable")
    if kind == "container" and "binary" in m:
        return refuse("binary", "a container app is its image")
    if "hash" in (m.get("binary") or {}):
        return refuse("binary.hash", "release_digest is the one name, even empty")
    if kind == "container":
        image = (m.get("container") or {}).get("image")
        if not isinstance(image, str) or not image or "@" in image or any(c in WHITE_SPACE for c in image):
            return refuse("container.image", "an image name with no digest and no white space")
    # Resources: requests, with units.
    r = m.get("resources") or {}
    if not (is_num(r.get("cpu_cores")) and 0 < r["cpu_cores"] <= 1024):
        return refuse("resources.cpu_cores", "more than 0, at most 1024")
    for k in ("memory_mb", "disk_mb"):
        if not (is_int(r.get(k)) and 1 <= r[k] <= 16777216):
            return refuse("resources." + k, "1 to 16777216 MiB")
    for k in ("egress_kbps", "ingress_kbps"):
        if not (is_int(r.get(k)) and 0 <= r[k] <= 100000000):
            return refuse("resources." + k, "0 to 100000000")
    if m.get("encrypted_machine") not in ("required", "preferred", "not_needed"):
        return refuse("encrypted_machine", "one of three values, never assumed")
    s = m.get("store")
    if not isinstance(s, dict):
        return refuse("store", "missing")
    if not token(s.get("format"), "-_", 32):
        return refuse("store.format", "a token")
    size = s.get("size_mb")
    if s["format"] == "none":
        if size != 0 or not is_int(size):
            return refuse("store.size_mb", "0 when there is no store")
    elif not (is_int(size) and 1 <= size <= 16777216):
        return refuse("store.size_mb", "1 to 16777216 MiB")
    # A volume of an app is not a host path: the one it may declare is "store",
    # its own encrypted store, mounted at an absolute path in the container.
    for key, target in ((m.get("container") or {}).get("volumes") or {}).items():
        if key != "store" or s["format"] == "none" or not isinstance(target, str) or not target.startswith("/"):
            return refuse("container.volumes", "only 'store', at an absolute path, and only when there is a store")
    if "placement" in m and m["placement"] not in ("own_machine", "shared_machine"):
        return refuse("placement", "own_machine or shared_machine, never inside the Identity Agent")
    e = m.get("front_and_back_end")
    if not isinstance(e, dict):
        return refuse("front_and_back_end", "missing")
    if "static_front_end_url" not in e and "back_end_port" not in e:
        return refuse("front_and_back_end", "neither a front end nor a back end")
    if "static_front_end_url" in e and not static_url(e["static_front_end_url"]):
        return refuse("front_and_back_end.static_front_end_url", "not a fixed https address")
    if "back_end_port" in e and not (is_int(e["back_end_port"]) and 1 <= e["back_end_port"] <= 65535):
        return refuse("front_and_back_end.back_end_port", "1 to 65535")
    d = e.get("device_front_ends")
    if (not isinstance(d, list) or any(x not in ("installed_app", "browser") for x in d)
            or len(set(d)) != len(d)
            or ("static_front_end_url" in e and "browser" not in d)):
        return refuse("front_and_back_end.device_front_ends", "installed_app and/or browser, each once, browser for a static front end")
    sec = m.get("secrets")
    if (not isinstance(sec, list) or len(sec) > 64 or len(set(map(str, sec))) != len(sec)
            or not all(token(x, "_", 64) for x in sec)):
        return refuse("secrets", "a list of unique lower-case names, empty if none")
    w = m.get("when_down")
    if not isinstance(w, dict):
        return refuse("when_down", "missing")
    if w.get("person_sees") not in ("notice", "last_known_data"):
        return refuse("when_down.person_sees", "notice or last_known_data")
    if not isinstance(w.get("queue_requests"), bool):
        return refuse("when_down.queue_requests", "true or false")
    q = w.get("queue_max_seconds")
    if w["queue_requests"]:
        if not (is_int(q) and 1 <= q <= 86400):
            return refuse("when_down.queue_max_seconds", "1 to 86400 when requests queue")
    elif "queue_max_seconds" in w:
        return refuse("when_down.queue_max_seconds", "left out when nothing queues")
    b = m.get("backup")
    if not isinstance(b, dict):
        return refuse("backup", "missing")
    what = b.get("what")
    if not isinstance(what, list) or any(x not in ("store", "settings") for x in what) or len(set(what)) != len(what):
        return refuse("backup.what", "store and/or settings, each once")
    if what:
        h = b.get("every_hours")
        if not (is_int(h) and 1 <= h <= 8760):
            return refuse("backup.every_hours", "1 to 8760 when something is backed up")
    elif "every_hours" in b:
        return refuse("backup.every_hours", "left out when nothing is backed up")
    hosts = (m.get("network") or {}).get("allowed_domains")
    if not isinstance(hosts, list):
        return refuse("network.allowed_domains", "declared, empty if none")
    if hosts and m.get("network_mode") in ("isolated", "local_only"):
        return refuse("network.allowed_domains", "this network_mode reaches no outside host")
    if not all(outbound_host(h) for h in hosts):
        return refuse("network.allowed_domains", "an entry in none of the five forms")
    return None


def main(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    vectors = doc["vectors"]
    accepted = refused = 0
    refused_rows = set()
    for v in vectors:
        got = check(v["manifest"])
        if v["outcome"] == "accepted":
            accepted += 1
            if got is not None:
                failures.append("%s: the file accepts it, the written rules refuse it for %s (%s)" % (v["name"], got[0], got[1]))
        elif v["outcome"] == "refused":
            refused += 1
            refused_rows.add(v["row"])
            if got is None:
                failures.append("%s: the file refuses it for %s, the written rules accept it" % (v["name"], v["row"]))
            elif got[0] != v["row"]:
                failures.append("%s: the file refuses it for %s, the written rules for %s (%s)" % (v["name"], v["row"], got[0], got[1]))
        else:
            failures.append("%s: outcome %r" % (v["name"], v["outcome"]))
    # Every row an app declares has a manifest refused for leaving it out.
    for row in ("name", "release_digest", "encrypted_machine", "resources.cpu_cores", "store", "front_and_back_end",
                "secrets", "when_down", "backup", "network.allowed_domains"):
        if row not in refused_rows:
            failures.append("no vector is refused for %s" % row)
    if accepted < 10:
        failures.append("only %d accepted vectors" % accepted)
    # The outbound host forms, apart from the vectors.
    for h in ("a", "a.example.org", "a.example.org:8443", "*.example.org", "**.example.org", "**.example.org:443"):
        if not outbound_host(h):
            failures.append("host form %r refused" % h)
    for h in ("", "*", "*.com", "10.0.0.1", "A.example.org", "a.example.org:0", "a.example.org:080", "http://a.example.org", "a.*.example.org"):
        if outbound_host(h):
            failures.append("host form %r accepted" % h)
    if failures:
        print("FAILED: %d disagreement(s)" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("ok: %d vectors (%d accepted, %d refused) agree with the written rules" % (len(vectors), accepted, refused))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
