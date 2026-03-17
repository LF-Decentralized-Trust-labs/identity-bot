#!/usr/bin/env python3
"""
Codemagic CI/CD helper — trigger builds, poll status, fetch logs.

Usage:
  python scripts/codemagic.py trigger android-release [--branch sprint-2]
  python scripts/codemagic.py trigger ios-release windows-release --branch main
  python scripts/codemagic.py status <buildId>
  python scripts/codemagic.py logs <buildId>
  python scripts/codemagic.py list [--limit 10]
  python scripts/codemagic.py cancel <buildId>
  python scripts/codemagic.py wait <buildId>        # poll until done, print result
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

API_BASE = "https://api.codemagic.io"
API_KEY  = "kjGL-i5hFdJItB7pzA1iwZ4NhVemNSEQVZNGez6H5pk"
APP_ID   = "69976a0ba4f5fa66579c4326"

WORKFLOWS = [
    "android-release",
    "ios-release",
    "windows-release",
    "macos-release",
    "linux-release",
]

HEADERS = {
    "x-auth-token": API_KEY,
    "Content-Type": "application/json",
}


def _request(method, path, body=None):
    url = API_BASE + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        print("HTTP %d: %s" % (e.code, raw[:500]), file=sys.stderr)
        sys.exit(1)


def cmd_trigger(args):
    branch = args.branch or "sprint-2"
    for wf in args.workflows:
        if wf not in WORKFLOWS:
            print("Unknown workflow '%s'. Valid: %s" % (wf, ", ".join(WORKFLOWS)))
            sys.exit(1)
        body = {"appId": APP_ID, "workflowId": wf, "branch": branch}
        result = _request("POST", "/builds", body)
        build_id = result.get("buildId", result.get("build", {}).get("_id", "?"))
        print("Triggered %s on branch '%s' -> build ID: %s" % (wf, branch, build_id))
        print("  Dashboard: https://codemagic.io/app/%s/build/%s" % (APP_ID, build_id))


def cmd_status(args):
    build = _request("GET", "/builds/%s" % args.build_id)
    b = build.get("build", build)
    print("Build ID:   %s" % b.get("_id", args.build_id))
    print("Workflow:   %s" % (b.get("fileWorkflowId") or b.get("workflowId") or b.get("workflowName") or "?"))
    print("Branch:     %s" % b.get("branch", "?"))
    print("Status:     %s" % b.get("status", "?"))
    print("Started:    %s" % b.get("startedAt", "?"))
    print("Finished:   %s" % b.get("finishedAt", "-"))
    steps = b.get("buildActions", b.get("steps", []))
    if steps:
        print("\nSteps:")
        for s in steps:
            status = s.get("status", "?")
            name   = s.get("name", s.get("id", "?"))
            dur    = s.get("durationSeconds", "")
            dur_s  = ("  (%ss)" % dur) if dur else ""
            print("  [%s] %s%s" % (status, name, dur_s))


def _strip_html(text):
    """Remove HTML span tags from Codemagic log output."""
    import re
    return re.sub(r'<[^>]+>', '', text)


def _fetch_step_log(log_url):
    """Fetch plain-text log from a step logUrl."""
    req = urllib.request.Request(log_url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return _strip_html(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        return "(could not fetch log: %s)" % e


def cmd_logs(args):
    build = _request("GET", "/builds/%s" % args.build_id)
    b = build.get("build", build)
    actions = b.get("buildActions", [])

    if not actions:
        print("No build actions found for build %s." % args.build_id)
        return

    # If --failed, only show steps that didn't succeed
    show_steps = actions
    if getattr(args, "failed", False):
        show_steps = [a for a in actions if a.get("status") not in ("success",)]
        if not show_steps:
            print("No failed steps found.")
            return

    all_lines = []
    for action in show_steps:
        name    = action.get("name", "?")
        status  = action.get("status", "?")
        log_url = action.get("logUrl")
        all_lines.append("\n" + "=" * 70)
        all_lines.append("[%s] %s" % (status.upper(), name))
        all_lines.append("=" * 70)
        if log_url:
            all_lines.append(_fetch_step_log(log_url))
        else:
            # Logs are sometimes on subactions instead of the parent action
            subactions = action.get("subactions", [])
            if subactions:
                for sub in subactions:
                    sub_url = sub.get("logUrl")
                    if sub_url:
                        all_lines.append(_fetch_step_log(sub_url))
            else:
                all_lines.append("(no log URL)")

    full_log = "\n".join(all_lines)
    if args.tail:
        lines = full_log.splitlines()
        print("\n".join(lines[-args.tail:]))
    else:
        print(full_log)


def cmd_list(args):
    result = _request("GET", "/builds?appId=%s&limit=%d" % (APP_ID, args.limit))
    builds = result.get("builds", [])
    if not builds:
        print("No builds found.")
        return
    print("%-24s  %-18s  %-10s  %-20s  %s" % (
        "Build ID", "Workflow", "Status", "Branch", "Started"))
    print("-" * 90)
    for b in builds:
        wf = b.get("fileWorkflowId") or b.get("workflowId") or b.get("workflowName") or "?"
        print("%-24s  %-18s  %-10s  %-20s  %s" % (
            b.get("_id", "?"),
            wf[:18],
            b.get("status", "?")[:10],
            (b.get("branch") or "?")[:20],
            b.get("startedAt", "?"),
        ))


def cmd_cancel(args):
    _request("POST", "/builds/%s/cancel" % args.build_id)
    print("Cancelled build %s." % args.build_id)


def cmd_wait(args):
    poll = args.poll or 20
    timeout = args.timeout or 7200
    elapsed = 0
    print("Polling build %s every %ds (timeout %ds)..." % (args.build_id, poll, timeout))
    while elapsed < timeout:
        build = _request("GET", "/builds/%s" % args.build_id)
        b = build.get("build", build)
        status = b.get("status", "unknown")
        print("  [%ds] status: %s" % (elapsed, status))
        if status in ("finished", "failed", "canceled", "timeout", "skipped"):
            print("\nFinal status: %s" % status)
            steps = b.get("buildActions", b.get("steps", []))
            failed = [s for s in steps if s.get("status") not in ("success", "skipped", None)]
            if failed:
                print("Failed steps:")
                for s in failed:
                    print("  [%s] %s" % (s.get("status"), s.get("name", s.get("id", "?"))))
            if status == "finished":
                print("Build succeeded.")
                sys.exit(0)
            else:
                print("Build did NOT succeed. Run: python scripts/codemagic.py logs %s" % args.build_id)
                sys.exit(1)
        time.sleep(poll)
        elapsed += poll
    print("Timed out waiting for build %s." % args.build_id)
    sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Codemagic CI/CD helper")
    sub = p.add_subparsers(dest="cmd")

    t = sub.add_parser("trigger", help="Trigger one or more workflows")
    t.add_argument("workflows", nargs="+", choices=WORKFLOWS + ["all"])
    t.add_argument("--branch", default="sprint-2")

    s = sub.add_parser("status", help="Show build status")
    s.add_argument("build_id")

    lg = sub.add_parser("logs", help="Print build logs")
    lg.add_argument("build_id")
    lg.add_argument("--tail", type=int, default=0, help="Print last N lines only")
    lg.add_argument("--failed", action="store_true", help="Only show failed/errored steps")

    ls = sub.add_parser("list", help="List recent builds")
    ls.add_argument("--limit", type=int, default=10)

    c = sub.add_parser("cancel", help="Cancel a running build")
    c.add_argument("build_id")

    w = sub.add_parser("wait", help="Poll until build completes")
    w.add_argument("build_id")
    w.add_argument("--poll", type=int, default=20, help="Seconds between polls (default 20)")
    w.add_argument("--timeout", type=int, default=7200, help="Max wait seconds (default 7200)")

    args = p.parse_args()

    if args.cmd == "trigger":
        if "all" in args.workflows:
            args.workflows = WORKFLOWS
        cmd_trigger(args)
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "logs":
        cmd_logs(args)
    elif args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "cancel":
        cmd_cancel(args)
    elif args.cmd == "wait":
        cmd_wait(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
