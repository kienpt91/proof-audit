#!/usr/bin/env python3
"""Host-side relay for scripts/docker-smoke.sh.

The smoke test runs the real container provider inside a Node container that has no docker CLI, no docker
socket and no network. Every docker call the provider makes is written as a request file under out/relay;
this script runs it on the host with the real docker CLI and writes the answer back. Only the exact shapes
of command the provider issues are allowed, so the test process cannot use the relay for anything else.
"""
import json
import os
import re
import subprocess
import sys
import time

RELAY = sys.argv[1]
FORBIDDEN_RUN_FLAGS = {"-p", "--publish", "-P", "-v", "--volume", "--mount", "--privileged", "--cap-add", "--pid", "--ipc", "--device"}
NAME = re.compile(r"^proof-audit-[0-9a-f]{12}$")


def allowed(argv):
    if not argv or not all(isinstance(a, str) for a in argv):
        return "argv must be a list of strings"
    verb = argv[0]
    if verb == "run":
        if argv[1:5] != ["-d", "--rm", "--pull", "never"]:
            return "run must be detached, self-removing and never pull"
        if "--network" not in argv or argv[argv.index("--network") + 1] != "none":
            return "run must use --network none"
        if "--read-only" not in argv:
            return "run must be read-only"
        if FORBIDDEN_RUN_FLAGS & set(argv):
            return "run uses a forbidden flag"
        return None
    if verb == "exec":
        # exec -i [-e PGOPTIONS=...] <container> psql ...
        i = 2
        if len(argv) > 4 and argv[2] == "-e" and argv[3].startswith("PGOPTIONS="):
            i = 4
        ok = len(argv) > i + 1 and argv[1] == "-i" and NAME.match(argv[i]) and argv[i + 1] == "psql"
        return None if ok else "exec is only for psql in a proof-audit container"
    if verb == "ps":
        return None if argv[1:4] == ["-a", "--filter", "label=proof-audit=1"] else "ps is only for proof-audit containers"
    if verb == "context":
        return None if argv[1] == "inspect" and "--format" in argv else "context is only for inspect"
    if verb in ("inspect", "logs"):
        return None if NAME.match(argv[-1]) else f"{verb} is only for proof-audit containers"
    if verb == "rm":
        return None if argv[1:3] == ["-f", "-v"] and NAME.match(argv[3]) else "rm is only for proof-audit containers"
    return f"docker {verb} is not allowed"


def handle(path):
    with open(path) as f:
        req = json.load(f)
    why = allowed(req.get("argv"))
    if why:
        resp = {"code": 126, "stdout": "", "stderr": "relay refused: " + why, "timedOut": False, "truncated": False}
    else:
        try:
            p = subprocess.run(["docker", *req["argv"]], input=(req.get("stdin") or "").encode(), capture_output=True, timeout=req["timeoutMs"] / 1000)
            resp = {"code": p.returncode, "stdout": p.stdout.decode("utf8", "replace"), "stderr": p.stderr.decode("utf8", "replace"), "timedOut": False, "truncated": len(p.stdout) > req["maxOutputBytes"]}
        except subprocess.TimeoutExpired:
            resp = {"code": None, "stdout": "", "stderr": "", "timedOut": True, "truncated": False}
    out = path.replace("req-", "resp-")
    with open(out + ".tmp", "w") as f:
        json.dump(resp, f)
    os.rename(out + ".tmp", out)


def main():
    while not os.path.exists(os.path.join(RELAY, "stop")):
        for name in sorted(os.listdir(RELAY)):
            if name.startswith("req-") and name.endswith(".json") and not os.path.exists(os.path.join(RELAY, name.replace("req-", "resp-"))):
                handle(os.path.join(RELAY, name))
        time.sleep(0.02)


main()
