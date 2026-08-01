#U-34: Finger 서비스 비활성화

import os
import re
import shutil
import subprocess

from .common import GOOD, VULN, result, summarize


CODE = "U-34"
TITLE = "Finger 서비스 비활성화"

INETD_PATH = "/etc/inetd.conf"
XINETD_DIR = "/etc/xinetd.d"

SYSTEMD_UNITS = [
    "finger.service",
    "finger.socket",
    "fingerd.service",
    "fingerd.socket",
]


def _run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _unit_enabled_or_active(unit):
    if shutil.which("systemctl") is None:
        return False

    active = _run(["systemctl", "is-active", unit])

    if active is not None and active.returncode == 0:
        return True

    enabled = _run(["systemctl", "is-enabled", unit])

    return enabled is not None and enabled.returncode == 0


def _active_systemd_units():
    return [
        unit
        for unit in SYSTEMD_UNITS
        if _unit_enabled_or_active(unit)
    ]


def _inetd_finger_lines():
    matches = []
    errors = []

    if not os.path.isfile(INETD_PATH):
        return matches, errors

    try:
        with open(
            INETD_PATH,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for line_number, line in enumerate(file, start=1):
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                tokens = stripped.split()

                if not tokens:
                    continue

                service_name = tokens[0].lower()

                if (
                    service_name == "finger"
                    or re.search(r"\bfingerd\b", stripped, re.I)
                ):
                    matches.append(line_number)

    except (PermissionError, OSError) as error:
        errors.append(f"{INETD_PATH}: 확인 실패({error})")

    return matches, errors


def _xinetd_finger_files():
    vulnerable_files = []
    errors = []

    if not os.path.isdir(XINETD_DIR):
        return vulnerable_files, errors

    try:
        filenames = sorted(os.listdir(XINETD_DIR))
    except (PermissionError, OSError) as error:
        return [], [f"{XINETD_DIR}: 탐색 실패({error})"]

    for filename in filenames:
        path = os.path.join(XINETD_DIR, filename)

        if not os.path.isfile(path):
            continue

        related = filename.lower() in {"finger", "fingerd"}
        disable_value = None

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                for line in file:
                    stripped = line.strip()

                    if not stripped or stripped.startswith("#"):
                        continue

                    if re.search(
                        r"^\s*service\s+finger\b",
                        stripped,
                        re.I,
                    ):
                        related = True

                    match = re.match(
                        r"^\s*disable\s*=\s*(yes|no)\b",
                        stripped,
                        re.I,
                    )

                    if match:
                        disable_value = match.group(1).lower()

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 확인 실패({error})")
            continue

        if related and disable_value != "yes":
            vulnerable_files.append(path)

    return vulnerable_files, errors


def _get_issues():
    issues = []

    for unit in _active_systemd_units():
        issues.append(f"systemd 활성화: {unit}")

    inetd_lines, inetd_errors = _inetd_finger_lines()

    for line_number in inetd_lines:
        issues.append(
            f"{INETD_PATH}:{line_number}: Finger 서비스 활성 설정"
        )

    issues.extend(inetd_errors)

    xinetd_files, xinetd_errors = _xinetd_finger_files()

    for path in xinetd_files:
        issues.append(f"{path}: disable=yes 미설정")

    issues.extend(xinetd_errors)

    return issues


def _backup(path):
    backup_path = f"{path}.u34.bak"

    if not os.path.exists(backup_path):
        shutil.copy2(path, backup_path)


def _disable_inetd():
    errors = []

    if not os.path.isfile(INETD_PATH):
        return errors

    try:
        _backup(INETD_PATH)

        with open(
            INETD_PATH,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        changed = False
        new_lines = []

        for line in lines:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            tokens = stripped.split()
            service_name = tokens[0].lower() if tokens else ""

            if (
                service_name == "finger"
                or re.search(r"\bfingerd\b", stripped, re.I)
            ):
                new_lines.append(f"# U-34 disabled: {line}")
                changed = True
            else:
                new_lines.append(line)

        if changed:
            with open(
                INETD_PATH,
                "w",
                encoding="utf-8",
            ) as file:
                file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        errors.append(f"{INETD_PATH}: 조치 실패({error})")

    return errors


def _disable_xinetd_file(path):
    try:
        _backup(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        changed = False
        new_lines = []

        for line in lines:
            stripped = line.lstrip()

            if stripped.startswith("#"):
                new_lines.append(line)
                continue

            if re.match(
                r"^\s*disable\s*=",
                line,
                re.I,
            ):
                indentation = line[: len(line) - len(line.lstrip())]
                new_lines.append(f"{indentation}disable = yes\n")
                changed = True
            else:
                new_lines.append(line)

        if not changed:
            inserted = False
            completed_lines = []

            for line in new_lines:
                completed_lines.append(line)

                if not inserted and "{" in line:
                    completed_lines.append("\tdisable = yes\n")
                    inserted = True

            if not inserted:
                return [f"{path}: xinetd 블록 형식을 확인하지 못함"]

            new_lines = completed_lines

        with open(path, "w", encoding="utf-8") as file:
            file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        return [f"{path}: 조치 실패({error})"]

    return []


def _restart_active_unit(unit):
    if shutil.which("systemctl") is None:
        return None

    active = _run(["systemctl", "is-active", unit])

    if active is None or active.returncode != 0:
        return None

    return _run(["systemctl", "restart", unit])


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for unit in _active_systemd_units():
        completed = _run(
            ["systemctl", "disable", "--now", unit]
        )

        if completed is None or completed.returncode != 0:
            message = ""

            if completed is not None:
                message = (
                    completed.stderr.strip()
                    or completed.stdout.strip()
                )

            errors.append(
                f"{unit}: 중지·비활성화 실패"
                + (f"({message})" if message else "")
            )

    errors.extend(_disable_inetd())

    xinetd_files, xinetd_errors = _xinetd_finger_files()
    errors.extend(xinetd_errors)

    for path in xinetd_files:
        errors.extend(_disable_xinetd_file(path))

    for unit in [
        "xinetd.service",
        "openbsd-inetd.service",
        "inetutils-inetd.service",
        "inetd.service",
    ]:
        completed = _restart_active_unit(unit)

        if completed is not None and completed.returncode != 0:
            errors.append(f"{unit}: 재시작 실패")

    return errors


def check():
    issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "Finger 서비스가 비활성화되어 있습니다.",
        )

    before = summarize(issues)
    fix_errors = _fix()

    remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"Finger 서비스 활성 설정 확인 후 조치 완료: {before}. "
            f"서비스를 중지하고 자동 시작 및 inetd/xinetd 설정을 "
            f"비활성화했습니다."
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
