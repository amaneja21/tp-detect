"""Runtime instrumentation for a Python MCP server process (used by Layers 3 and 4).

Run a server as:  python -m tpdetect.sandbox <server.py> [args...]
A PEP 578 audit hook records security-relevant events (file opens, socket connects,
subprocess/exec, deletes) and appends them as JSON lines to $TPD_EVENT_FILE. In enforce
mode ($TPD_ENFORCE=1) events outside the server-level capability manifest ($TPD_MANIFEST)
raise PermissionError inside the hook, so the operation never happens.
The proxy brackets each tools/call so events are attributed to exactly one invocation."""
import sys, os, json, runpy, time

_path = os.environ.get("TPD_EVENT_FILE")
_out = open(_path, "a", buffering=1) if _path else None
_MAN = json.load(open(os.environ["TPD_MANIFEST"])) if os.environ.get("TPD_MANIFEST") else None
_ENFORCE = os.environ.get("TPD_ENFORCE") == "1"

def _allowed(kind, target):
    if _MAN is None: return True
    if kind in ("fs_read", "fs_write", "fs_delete"):
        key = "fs_write" if kind != "fs_read" else "fs_read"
        return any(target.startswith(p) for p in _MAN.get(key, [])) or (key == "fs_read" and any(target.startswith(p) for p in _MAN.get("fs_write", [])))
    if kind == "net":
        return target in _MAN.get("net", []) or target.split(":")[0] in _MAN.get("net", [])
    if kind == "dns":
        return target in _MAN.get("dns", []) or target in [n.split(":")[0] for n in _MAN.get("net", [])]
    if kind == "exec":
        return bool(_MAN.get("exec"))
    return True
_busy = [False]
# Test-harness exclusion: the evaluation's ground-truth trigger log is not server behaviour.
_HARNESS = {os.environ.get("TPD_TRUTH")} - {None}
_IGNORE_PREFIX = (sys.prefix, sys.base_prefix, "/usr/lib", "/usr/local/lib", "/proc", "/dev", "/etc/ld.so", "/sys")

def _emit(kind, target):
    if _busy[0]: return
    ok = _allowed(kind, target)
    if _out is not None:
        _busy[0] = True
        try: _out.write(json.dumps({"t": time.time(), "k": kind, "x": target, "ok": ok}) + "\n")
        finally: _busy[0] = False
    if _ENFORCE and not ok:
        raise PermissionError(f"TP-Detect: {kind} {target} outside manifest")

def _hook(event, args):
    if _busy[0]: return
    try:
        _dispatch(event, args)
    except PermissionError:
        raise
    except Exception:
        pass

def _dispatch(event, args):
    if True:
        if event == "open":
            p, mode = args[0], (args[1] if len(args) > 1 else "r")
            if isinstance(p, int) or p is None: return
            p = os.fsdecode(p)
            if p.endswith((".py", ".pyc", ".so")) or p.startswith(_IGNORE_PREFIX) or "__pycache__" in p: return
            if os.path.abspath(p) in _HARNESS: return
            m = str(mode) if mode is not None else "r"
            _emit("fs_write" if any(c in m for c in "wax+") else "fs_read", os.path.abspath(p))
        elif event == "socket.connect":
            addr = args[1]
            if isinstance(addr, tuple): _emit("net", f"{addr[0]}:{addr[1]}")
        elif event == "socket.getaddrinfo":
            _emit("dns", str(args[0]))
        elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn"):
            _emit("exec", str(args[0])[:200])
        elif event in ("os.remove", "os.unlink", "shutil.rmtree", "os.rename"):
            _emit("fs_delete", os.fsdecode(args[0]) if args and not isinstance(args[0], int) else "?")

def install():
    sys.addaudithook(_hook)

if __name__ == "__main__":
    target = sys.argv[1]; sys.argv = sys.argv[1:]
    install()
    runpy.run_path(target, run_name="__main__")
