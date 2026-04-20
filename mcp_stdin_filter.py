"""
Remote-side MCP stdin filter.
Deploy to ~/mcp_stdin_filter.py on the GCE VM.
Runs beast_intel_mcp.py as a child, but strips non-JSON lines from stdin
before forwarding them (catches the 'y\\n' plink/gcloud artefact).
Runs both processes unbuffered to avoid response-flush delays.
"""
import sys
import subprocess
import threading
import json
import os

# Force unbuffered output for this process too
sys.stdout = os.fdopen(sys.stdout.fileno(), 'wb', 0)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'wb', 0)

env = {**os.environ, "PYTHONUNBUFFERED": "1"}

proc = subprocess.Popen(
    ["python3", "-u", "/home/eagle/beast_intel_mcp.py"],
    stdin=subprocess.PIPE,
    stdout=sys.stdout,
    stderr=sys.stderr,
    env=env,
)


def forward_stdin():
    buf = b""
    try:
        raw_in = os.fdopen(sys.stdin.fileno(), 'rb', 0)
        while True:
            chunk = raw_in.read(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    json.loads(stripped)
                    proc.stdin.write(line + b"\n")
                    proc.stdin.flush()
                except json.JSONDecodeError:
                    sys.stderr.write(
                        b"[stdin_filter discarded] " + line + b"\n"
                    )
    except Exception as e:
        sys.stderr.write(f"[stdin_filter error] {e}\n".encode())
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass


threading.Thread(target=forward_stdin, daemon=True).start()
proc.wait()
