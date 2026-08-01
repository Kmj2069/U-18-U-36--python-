import glob
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

try:
    import pwd
except ImportError:
    pwd = None


GOOD = "양호"
VULN = "취약"
NA = "N/A"

NOLOGIN_SHELLS = {
    "",
    "/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/nologin",
    "/usr/bin/false",
    "/dev/null",
}


def result(code, title, status, detail):
    return {"code": code, "title": title, "status": status, "detail": detail}


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def read_lines(path):
    text = read_text(path)
    return [] if text is None else text.splitlines()


def parse_passwd(path="/etc/passwd"):
    users = []
    for line in read_lines(path):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue
        users.append(
            {
                "name": parts[0],
                "uid": uid,
                "gid": gid,
                "gecos": parts[4],
                "home": parts[5],
                "shell": parts[6].strip(),
            }
        )
    return users


def passwd_user(name):
    for user in parse_passwd():
        if user["name"] == name:
            return user
    return None


def owner_name(path):
    st = os.stat(path)
    if pwd is None:
        return str(st.st_uid)
    try:
        return pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        return str(st.st_uid)


def file_owner_mode_ok(path, owner="root", max_mode=0o640):
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    actual_owner = owner_name(path)
    if actual_owner != owner:
        return False, f"소유자 {actual_owner}, 권한 {mode:03o}"
    if mode > max_mode or mode & stat.S_IWOTH:
        return False, f"소유자 {actual_owner}, 권한 {mode:03o}"
    return True, f"소유자 {actual_owner}, 권한 {mode:03o}"


def run_command(args, timeout=3):
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError) as exc:
        return 127, "", str(exc)


def command_exists(name):
    return shutil.which(name) is not None


def systemctl_is_active(*names):
    if not command_exists("systemctl"):
        return False
    for name in names:
        code, stdout, _ = run_command(["systemctl", "is-active", name])
        if code == 0 and stdout.strip() == "active":
            return True
    return False


def pgrep_any(*patterns):
    if command_exists("pgrep"):
        for pattern in patterns:
            code, _, _ = run_command(["pgrep", "-x", pattern])
            if code == 0:
                return True
    proc = Path("/proc")
    if not proc.exists():
        return False
    wanted = set(patterns)
    for comm in proc.glob("[0-9]*/comm"):
        name = read_text(comm)
        if name and name.strip() in wanted:
            return True
    return False


def is_listening_on_port(port):
    for command in (["ss", "-lntup"], ["netstat", "-lntup"]):
        if not command_exists(command[0]):
            continue
        code, stdout, _ = run_command(command)
        if code == 0 and re.search(rf":{port}\s", stdout):
            return True
    return False


def ftp_service_active():
    return (
        systemctl_is_active("vsftpd", "proftpd", "pure-ftpd")
        or pgrep_any("vsftpd", "proftpd", "pure-ftpd")
        or is_listening_on_port(21)
    )


def snmp_service_active():
    return systemctl_is_active("snmpd") or pgrep_any("snmpd") or is_listening_on_port(161)


def glob_existing(patterns):
    paths = []
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))


def summarize(items, limit=6):
    if not items:
        return ""
    head = items[:limit]
    suffix = "" if len(items) <= limit else f" 외 {len(items) - limit}건"
    return ", ".join(head) + suffi
