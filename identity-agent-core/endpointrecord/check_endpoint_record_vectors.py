#!/usr/bin/env python3
"""An independent check of endpoint-record-vectors.json, written without Go.

Built from the form's description in endpointrecord.go, not from its code:

  * a record is exactly five string fields: type, aid, origin, issued, signature;
  * the signature is Ed25519 over the other four as a JSON object, keys sorted,
    no whitespace, printable ASCII only (ADR-049's form);
  * the signature is CESR qb64, code 0B: 88 characters, base64url, the two
    leading characters standing for two zero bytes (so the first is '0', the
    second is 'B', and nothing else is accepted: ADR-060);
  * an origin is scheme://host:port in one spelling, or empty (a withdrawal);
  * an address becomes an origin by lower-casing scheme and host and always
    writing the port;
  * issued is YYYY-MM-DDTHH:MM:SSZ, and a record more than ten minutes ahead of
    the verifier's clock is refused;
  * a record replaces another only when it speaks for the same identifier and
    was issued strictly after it.

Needs the `cryptography` package. Run: python3 check_endpoint_record_vectors.py [file]
"""
import base64
import datetime
import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TYPE = "endpoint-record/1"
FIELDS = ["type", "aid", "origin", "issued", "signature"]
B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
NUMERIC = re.compile(r"^(0[xX][0-9a-fA-F]*|[0-9]+)$")
PORT = re.compile(r"^[1-9][0-9]{0,4}$")


class Refused(Exception):
    pass


def b64url_strict(s):
    """Decode unpadded base64url, refusing any string a lenient decoder would
    also read: characters outside the alphabet, or non-zero spare bits."""
    if not B64URL.match(s):
        raise Refused("outside base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        raise Refused("spare bits")
    return raw


def key_raw(qb64):
    if len(qb64) != 44 or qb64[0] not in "DB":
        raise Refused("not a qb64 Ed25519 key")
    raw = b64url_strict("A" + qb64[1:])
    if raw[0] != 0:
        raise Refused("lead bits")
    return raw[1:]


def sig_raw(qb64):
    if len(qb64) != 88 or qb64[:2] != "0B":
        raise Refused("not a 0B signature")
    raw = b64url_strict("AA" + qb64[2:])
    if raw[:2] != b"\x00\x00":
        raise Refused("lead bits")
    return raw[2:]


def printable(s):
    return all(0x20 <= ord(c) <= 0x7E for c in s)


def canonical(rec):
    body = {k: v for k, v in rec.items() if k != "signature"}
    for k, v in body.items():
        if not printable(k) or not isinstance(v, str) or not printable(v):
            raise Refused("not printable ASCII strings")
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def check_origin(o):
    if "://" not in o:
        raise Refused("no scheme")
    scheme, rest = o.split("://", 1)
    if scheme not in ("http", "https"):
        raise Refused("scheme")
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0 or not rest[end + 1:].startswith(":"):
            raise Refused("ipv6 form")
        inner, port = rest[1:end], rest[end + 2:]
        if "%" in inner:
            raise Refused("zone")
        try:
            ip = ipaddress.IPv6Address(inner)
        except ValueError:
            raise Refused("ipv6")
        # one spelling: compressed, lower case, and not an IPv4-mapped address
        if ip.ipv4_mapped is not None or ip.compressed != inner:
            raise Refused("ipv6 spelling")
    else:
        if ":" not in rest:
            raise Refused("no port")
        host, port = rest.rsplit(":", 1)
        if not host or len(host) > 253:
            raise Refused("host")
        for label in host.split("."):
            if len(label) > 63 or not LABEL.match(label):
                raise Refused("host label")
        # A host whose last label is a number, or reads as one (0x7f), is an IPv4
        # address to a resolver ("127.1", "2130706433" and "0x7f.1" are all
        # 127.0.0.1), so it is accepted only as the one spelling: four decimal
        # numbers without a leading zero.
        if NUMERIC.match(host.rsplit(".", 1)[-1]):
            try:
                ok = str(ipaddress.IPv4Address(host)) == host
            except ValueError:
                ok = False
            if not ok:
                raise Refused("numeric host")
    if not PORT.match(port) or int(port) > 65535:
        raise Refused("port")


def origin_of(address):
    """The origin an address stands for, or None: scheme and host in lower case,
    the port always written, nothing else kept."""
    p = urlsplit(address)
    scheme = p.scheme.lower()
    netloc = p.netloc
    if scheme not in ("http", "https") or not netloc or "@" in netloc:
        return None
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            return None
        host, rest = "[" + netloc[1:end].lower() + "]", netloc[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    elif ":" in netloc:
        host, _, port = netloc.rpartition(":")
        host = host.lower()
    else:
        host, port = netloc.lower(), ""
    if not host or host == "[]":
        return None
    origin = "%s://%s:%s" % (scheme, host, port or {"http": "80", "https": "443"}[scheme])
    try:
        check_origin(origin)
    except Refused:
        return None
    return origin


def parse_issued(s):
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", s):
        raise Refused("issued spelling")
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise Refused("issued value")


def verify(rec, key_qb64, now):
    if not isinstance(rec, dict) or sorted(rec.keys()) != sorted(FIELDS):
        raise Refused("fields")
    for k in FIELDS:
        if not isinstance(rec[k], str):
            raise Refused("not a string")
    if rec["type"] != TYPE:
        raise Refused("type")
    if not rec["aid"] or len(rec["aid"]) > 128:
        raise Refused("aid")
    if rec["origin"] != "":  # an empty origin is a withdrawal
        check_origin(rec["origin"])
    issued = parse_issued(rec["issued"])
    if issued > now + datetime.timedelta(minutes=10):
        raise Refused("future")
    if issued < now - datetime.timedelta(days=90):
        raise Refused("expired")
    sig = sig_raw(rec["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(key_raw(key_qb64)).verify(sig, canonical(rec).encode("ascii"))
    except InvalidSignature:
        raise Refused("signature")


def newer(a_aid, a_issued, b_aid, b_issued):
    if a_aid != b_aid:
        return False
    try:
        return parse_issued(a_issued) > parse_issued(b_issued)
    except Refused:
        return False


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoint-record-vectors.json")
    with open(path) as f:
        data = json.load(f)
    failures = 0
    now = parse_issued(data["now"])
    seed = bytes.fromhex(data["seed_hex"])
    derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    if key_raw(data["public_key"]) != derived:
        print("public_key is not the key of seed_hex")
        failures += 1
    next_seed = bytes.fromhex(data["next_seed_hex"])
    if key_raw(data["next_public_key"]) != Ed25519PrivateKey.from_private_bytes(next_seed).public_key().public_bytes_raw():
        print("next_public_key is not the key of next_seed_hex")
        failures += 1
    keys = {"public_key": data["public_key"], "other_public_key": data["other_public_key"],
            "next_public_key": data["next_public_key"]}
    seeds = {"public_key": seed, "next_public_key": next_seed}
    for v in data["records"]:
        rec = v["record"]
        try:
            if v.get("canonical") is not None and "canonical" in v:
                got = canonical(rec)
                if got != v["canonical"]:
                    print("CANONICAL MISMATCH %s:\n  python %s\n  file   %s" % (v["name"], got, v["canonical"]))
                    failures += 1
        except Refused:
            pass
        try:
            verify(rec, keys[v["key"]], now)
            verdict = True
        except Refused:
            verdict = False
        if verdict != v["valid"]:
            print("VERDICT MISMATCH %s: file says valid=%s, python says %s" % (v["name"], v["valid"], verdict))
            failures += 1
        # A record that verifies must also have been signed by the seed: the
        # file's signatures are reproducible, not merely checkable.
        if verdict and v["key"] in seeds:
            again = Ed25519PrivateKey.from_private_bytes(seeds[v["key"]]).sign(canonical(rec).encode("ascii"))
            if again != sig_raw(rec["signature"]):
                print("SIGNATURE NOT REPRODUCED %s" % v["name"])
                failures += 1
    for o in data["origins"]:
        try:
            check_origin(o["origin"])
            verdict = True
        except Refused:
            verdict = False
        if verdict != o["ok"]:
            print("ORIGIN MISMATCH %r: file says %s, python says %s" % (o["origin"], o["ok"], verdict))
            failures += 1
    for a in data["addresses"]:
        got = origin_of(a["address"]) or ""
        if got != a["origin"]:
            print("ADDRESS MISMATCH %r: file says %r, python says %r" % (a["address"], a["origin"], got))
            failures += 1
    for o in data["ordering"]:
        if newer(o["a_aid"], o["a_issued"], o["b_aid"], o["b_issued"]) != o["newer"]:
            print("ORDER MISMATCH %s" % o["name"])
            failures += 1
    for r in data["requests"]:
        # The third form puts the origin on a line of its own after the Identity
        # Agent; the second names none. Built here from the parts, never read
        # from the file's own string.
        if r["origin"]:
            head = ["IA-CONTROLLER-REQ-V3", r["controller"], r["identity_agent"], r["origin"]]
        else:
            head = ["IA-CONTROLLER-REQ-V2", r["controller"], r["identity_agent"]]
        got = "\n".join(head + [r["method"].upper(), r["path"], r["timestamp"], r["level"], r["measured_at"],
                               str(r["score"]), r["body_digest"]])
        if got != r["signed"]:
            print("REQUEST MISMATCH %s:\n  python %r\n  file   %r" % (r["name"], got, r["signed"]))
            failures += 1
    if failures:
        sys.exit(1)
    print("ok: %d records, %d origins, %d addresses, %d orderings, %d requests" % (
        len(data["records"]), len(data["origins"]), len(data["addresses"]), len(data["ordering"]), len(data["requests"])))


if __name__ == "__main__":
    main()
