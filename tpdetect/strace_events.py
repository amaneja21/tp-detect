"""Parse strace output into TP-Detect events (L3/L4 for servers in any language, monitor mode)."""
import re, os
OPEN = re.compile(r'openat\(\w+, "([^"]+)", ([A-Z_|]+)')
CONN = re.compile(r'connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), (?:sin_addr=inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")')
EXEC = re.compile(r'execve\("([^"]+)"')
IGNORE = ("/proc/", "/dev/", "/sys/", "/usr/lib", "/lib", "/usr/share", "/etc/ld.so", "/etc/ssl", "/opt/node", "/usr/local/lib")
def parse(text):
    ev = []
    for line in text.splitlines():
        if "= -1" in line or "<unfinished" in line and "openat" not in line: pass
        m = OPEN.search(line)
        if m and "= -1 ENOENT" not in line:
            p = m.group(1)
            if p.startswith(IGNORE) or "/node_modules/" in p or "tpd_truth" in p: continue
            ev.append({"k": "fs_write" if ("O_WRONLY" in m.group(2) or "O_RDWR" in m.group(2) or "O_CREAT" in m.group(2)) else "fs_read",
                       "x": os.path.abspath(p)}); continue
        m = CONN.search(line)
        if m:
            ev.append({"k": "net", "x": f"{m.group(2) or m.group(3)}:{m.group(1)}"}); continue
        m = EXEC.search(line)
        if m: ev.append({"k": "exec", "x": m.group(1)})
    return ev
def allowed(man, kind, target):
    if man is None: return True
    if kind == "fs_read": return any(target.startswith(p) for p in man.get("fs_read", []) + man.get("fs_write", []))
    if kind == "fs_write": return any(target.startswith(p) for p in man.get("fs_write", []))
    if kind == "net": return target in man.get("net", [])
    if kind == "exec": return bool(man.get("exec"))
    return True
