#U-27: $HOME/.rhosts, hosts.equiv 사용 금지

import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

from .common import GOOD, VULN, result, summarize


CODE = "U-27"
TITLE = "$HOME/.rhosts, hosts.equiv 사용 금지"

HOSTS_EQUIV = "/etc/hosts.equiv"

R_SERVICE_NAMES = {
    "rsh",
    "shell",
    "rlogin",
    "login",
    "rexec",
    "exec",
}

R_SERVICE_UNITS = [
    "rsh.service",
    "rsh.socket",
    "rlogin.service",
    "rlogin.socket",
    "rexec.service",
    "rexec.socket",
]


def _run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _systemd_service_evidence():
    evidence = []

    if shutil.which("systemctl") is None:
        return evidence

    for unit in R_SERVICE_UNITS:
        completed = _run(["systemctl", "is-active", unit])

        if completed is not None and completed.returncode == 0:
            evidence.append(f"systemd:{unit}")

    return evidence


def _inetd_service_evidence():
    path = "/etc/inetd.conf"
    evidence = []

    if not os.path.isfile(path):
        return evidence

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                tokens = stripped.split()

                if not tokens:
                    continue

                service_name = tokens[0].lower()

                if (
                    service_name in R_SERVICE_NAMES
                    or re.search(
                        r"\b(in\.)?(rshd|rlogind|rexecd)\b",
                        stripped,
                        re.I,
                    )
                ):
                    evidence.append(f"{path}:{line_number}")

    except (PermissionError, OSError):
        evidence.append(f"{path}:확인 실패")

    return evidence


def _xinetd_service_evidence():
    directory = "/etc/xinetd.d"
    evidence = []

    if not os.path.isdir(directory):
        return evidence

    for filename in sorted(os.listdir(directory)):
        path = os.path.join(directory, filename)

        if not os.path.isfile(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                active_config = False
                related_service = filename.lower() in R_SERVICE_NAMES

                for line in file:
                    stripped = line.strip()

                    if not stripped or stripped.startswith("#"):
                        continue

                    if re.search(
                        r"\bservice\s+(rsh|shell|rlogin|login|rexec|exec)\b",
                        stripped,
                        re.I,
                    ):
                        related_service = True

                    if re.search(r"^\s*disable\s*=\s*no\b", stripped, re.I):
                        active_config = True

                if related_service and active_config:
                    evidence.append(path)

        except (PermissionError, OSError):
            evidence.append(f"{path}:확인 실패")

    return evidence


def _r_service_evidence():
    evidence = []

    evidence.extend(_systemd_service_evidence())
    evidence.extend(_inetd_service_evidence())
    evidence.extend(_xinetd_service_evidence())

    return evidence


def _collect_trust_files():
    """
    반환 형식:
        {
            경로: {
                "allowed_uids": 허용 UID 집합,
                "fix_uid": 잘못된 소유자를 변경할 UID
            }
        }
    """
    targets = {}

    if os.path.lexists(HOSTS_EQUIV):
        targets[HOSTS_EQUIV] = {
            "allowed_uids": {0},
            "fix_uid": 0,
        }

    for account in pwd.getpwall():
        home = account.pw_dir

        if not home or not os.path.isabs(home):
            continue

        path = os.path.join(home, ".rhosts")

        if not os.path.lexists(path):
            continue

        targets[path] = {
            "allowed_uids": {0, account.pw_uid},
            "fix_uid": account.pw_uid,
        }

    return targets


def _plus_line_numbers(path):
    """
    '+ +', '+ 사용자', '호스트 +'처럼 독립된 + 토큰이 있는
    설정 줄을 검색한다.
    """
    line_numbers = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                content = line.split("#", 1)[0].strip()

                if not content:
                    continue

                if "+" in content.split():
                    line_numbers.append(line_number)

    except (PermissionError, OSError):
        return None

    return line_numbers


def _get_issues():
    targets = _collect_trust_files()
    issues = []

    for path, info in sorted(targets.items()):
        try:
            file_stat = os.lstat(path)
        except (PermissionError, OSError) as error:
            issues.append(f"{path}: 확인 실패({error})")
            continue

        if stat.S_ISLNK(file_stat.st_mode):
            issues.append(f"{path}: 심볼릭 링크")
            continue

        if not stat.S_ISREG(file_stat.st_mode):
            issues.append(f"{path}: 일반 파일 아님")
            continue

        mode = stat.S_IMODE(file_stat.st_mode)

        if file_stat.st_uid not in info["allowed_uids"]:
            issues.append(f"{path}: 소유자 UID={file_stat.st_uid}")

        if mode & ~0o600:
            issues.append(f"{path}: 권한={mode:04o}")

        plus_lines = _plus_line_numbers(path)

        if plus_lines is None:
            issues.append(f"{path}: 내용 확인 실패")
        elif plus_lines:
            issues.append(
                f"{path}: '+' 설정 줄={','.join(map(str, plus_lines))}"
            )

    return targets, issues


def _remove_plus_lines(path):
    directory = os.path.dirname(path) or "."
    backup_path = f"{path}.u27.bak"

    if not os.path.exists(backup_path):
        shutil.copy2(path, backup_path)

    with open(path, "r", encoding="utf-8", errors="ignore") as source:
        original_lines = source.readlines()

    retained_lines = []

    for line in original_lines:
        content = line.split("#", 1)[0].strip()

        if content and "+" in content.split():
            continue

        retained_lines.append(line)

    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=".u27_",
        dir=directory,
        text=True,
    )

    try:
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
        ) as temporary_file:
            temporary_file.writelines(retained_lines)

        os.replace(temporary_path, path)

    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def _fix(targets):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for path, info in sorted(targets.items()):
        try:
            file_stat = os.lstat(path)

            if stat.S_ISLNK(file_stat.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(file_stat.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            plus_lines = _plus_line_numbers(path)

            if plus_lines:
                _remove_plus_lines(path)

            os.chown(path, info["fix_uid"], -1)
            os.chmod(path, 0o600)

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def check():
    service_evidence = _r_service_evidence()

    if not service_evidence:
        return result(
            CODE,
            TITLE,
            GOOD,
            "rlogin, rsh, rexec 서비스 활성 징후가 없습니다.",
        )

    targets, issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            (
                f"r 계열 서비스 활성 징후는 있으나 신뢰 파일 설정이 적절합니다: "
                f"{summarize(service_evidence)}"
            ),
        )

    before = summarize(issues)
    fix_errors = _fix(targets)

    _, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 신뢰 파일 설정 확인 후 조치 완료: {before}. "
            f"소유자·권한을 정상화하고 '+' 설정을 제거했습니다."
        )

        if fix_errors:
            detail += f" 조치 중 경고: {summarize(fix_errors)}"

        return result(CODE, TITLE, GOOD, detail)

    detail = (
        f"조치 전 취약 항목: {before}. "
        f"조치 후에도 남은 항목: {summarize(remaining_issues)}"
    )

    if fix_errors:
        detail += f". 조치 오류: {summarize(fix_errors)}"

    return result(CODE, TITLE, VULN, detail)
