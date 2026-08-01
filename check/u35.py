#U-35: 공유 서비스에 대한 익명 접근 제한 설정

import os
import re
import shutil
import subprocess

from .common import GOOD, VULN, result, summarize


CODE = "U-35"
TITLE = "공유 서비스에 대한 익명 접근 제한 설정"

VSFTPD_FILES = [
    "/etc/vsftpd.conf",
    "/etc/vsftpd/vsftpd.conf",
]

PROFTPD_FILES = [
    "/etc/proftpd/proftpd.conf",
    "/etc/proftpd.conf",
]

NFS_EXPORTS = "/etc/exports"

SAMBA_FILES = [
    "/etc/samba/smb.conf",
    "/usr/lib/smb.conf",
]

SERVICE_UNITS = {
    "vsftpd": ["vsftpd.service"],
    "proftpd": ["proftpd.service"],
    "nfs": [
        "nfs-server.service",
        "nfs-kernel-server.service",
    ],
    "samba": [
        "smbd.service",
        "samba.service",
    ],
}

PROCESS_NAMES = {
    "vsftpd": ["vsftpd"],
    "proftpd": ["proftpd"],
    "nfs": ["rpc.nfsd"],
    "samba": ["smbd"],
}


def _run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _unit_in_use(unit):
    if shutil.which("systemctl") is None:
        return False

    active = _run(["systemctl", "is-active", unit])

    if active is not None and active.returncode == 0:
        return True

    enabled = _run(["systemctl", "is-enabled", unit])

    return enabled is not None and enabled.returncode == 0


def _process_running(process_name):
    if shutil.which("pgrep") is None:
        return False

    completed = _run(["pgrep", "-x", process_name])

    return completed is not None and completed.returncode == 0


def _service_in_use(service_name):
    for unit in SERVICE_UNITS[service_name]:
        if _unit_in_use(unit):
            return True

    for process_name in PROCESS_NAMES[service_name]:
        if _process_running(process_name):
            return True

    return False


def _active_services():
    return {
        service_name
        for service_name in SERVICE_UNITS
        if _service_in_use(service_name)
    }


def _active_config_lines(path):
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            return [
                (line_number, line.rstrip("\n"))
                for line_number, line in enumerate(file, start=1)
                if line.strip()
                and not line.lstrip().startswith(("#", ";"))
            ]
    except (PermissionError, OSError):
        return None


def _existing_files(paths):
    return [
        path
        for path in paths
        if os.path.isfile(path)
    ]


def _check_vsftpd():
    issues = []
    paths = _existing_files(VSFTPD_FILES)

    if not paths:
        return ["vsftpd 활성 상태이나 설정 파일을 찾지 못함"]

    for path in paths:
        lines = _active_config_lines(path)

        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue

        values = []

        for line_number, line in lines:
            match = re.match(
                r"^\s*anonymous_enable\s*=\s*(\S+)",
                line,
                re.I,
            )

            if match:
                values.append(
                    (line_number, match.group(1).upper())
                )

        if not values:
            issues.append(f"{path}: anonymous_enable 설정 없음")
            continue

        line_number, effective_value = values[-1]

        if effective_value != "NO":
            issues.append(
                f"{path}:{line_number}: "
                f"anonymous_enable={effective_value}"
            )

    return issues


def _check_proftpd():
    issues = []
    paths = _existing_files(PROFTPD_FILES)

    if not paths:
        return ["ProFTP 활성 상태이나 설정 파일을 찾지 못함"]

    for path in paths:
        lines = _active_config_lines(path)

        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue

        for line_number, line in lines:
            if re.match(r"^\s*<Anonymous\b", line, re.I):
                issues.append(
                    f"{path}:{line_number}: Anonymous 블록 활성"
                )

    return issues


def _check_nfs():
    issues = []

    if not os.path.isfile(NFS_EXPORTS):
        return issues

    lines = _active_config_lines(NFS_EXPORTS)

    if lines is None:
        return [f"{NFS_EXPORTS}: 내용 확인 실패"]

    for line_number, line in lines:
        options = re.findall(
            r"\b(?:anonuid|anongid)\s*=\s*[^,\s\)]+",
            line,
            re.I,
        )

        if options:
            issues.append(
                f"{NFS_EXPORTS}:{line_number}: "
                f"{','.join(options)}"
            )

    return issues


def _check_samba():
    issues = []
    paths = _existing_files(SAMBA_FILES)

    if not paths:
        return ["Samba 활성 상태이나 설정 파일을 찾지 못함"]

    for path in paths:
        lines = _active_config_lines(path)

        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue

        for line_number, line in lines:
            match = re.match(
                r"^\s*guest\s+ok\s*=\s*(\S+)",
                line,
                re.I,
            )

            if match and match.group(1).lower() in {
                "yes",
                "true",
                "1",
            }:
                issues.append(
                    f"{path}:{line_number}: guest ok={match.group(1)}"
                )

    return issues


def _get_issues():
    active_services = _active_services()
    issues = []

    if "vsftpd" in active_services:
        issues.extend(_check_vsftpd())

    if "proftpd" in active_services:
        issues.extend(_check_proftpd())

    if "nfs" in active_services:
        issues.extend(_check_nfs())

    if "samba" in active_services:
        issues.extend(_check_samba())

    return active_services, issues


def _backup(path):
    backup_path = f"{path}.u35.bak"

    if not os.path.exists(backup_path):
        shutil.copy2(path, backup_path)


def _set_vsftpd_anonymous_no(path):
    try:
        _backup(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        found = False
        new_lines = []

        for line in lines:
            if (
                line.strip()
                and not line.lstrip().startswith("#")
                and re.match(
                    r"^\s*anonymous_enable\s*=",
                    line,
                    re.I,
                )
            ):
                new_lines.append("anonymous_enable=NO\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines[-1] += "\n"

            new_lines.append("anonymous_enable=NO\n")

        with open(path, "w", encoding="utf-8") as file:
            file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        return [f"{path}: 조치 실패({error})"]

    return []


def _comment_proftpd_anonymous_blocks(path):
    try:
        _backup(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        inside_anonymous = False
        new_lines = []

        for line in lines:
            stripped = line.strip()

            if (
                not line.lstrip().startswith("#")
                and re.match(
                    r"^<Anonymous\b",
                    stripped,
                    re.I,
                )
            ):
                inside_anonymous = True

            if inside_anonymous and not line.lstrip().startswith("#"):
                new_lines.append(f"# U-35 disabled: {line}")
            else:
                new_lines.append(line)

            if (
                inside_anonymous
                and re.match(
                    r"^</Anonymous>",
                    stripped,
                    re.I,
                )
            ):
                inside_anonymous = False

        with open(path, "w", encoding="utf-8") as file:
            file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        return [f"{path}: 조치 실패({error})"]

    return []


def _remove_nfs_anonymous_options(path):
    try:
        _backup(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        def replace_option_group(match):
            options = [
                option.strip()
                for option in match.group(1).split(",")
            ]

            retained = [
                option
                for option in options
                if not re.match(
                    r"^(anonuid|anongid)\s*=",
                    option,
                    re.I,
                )
            ]

            return "(" + ",".join(retained) + ")"

        new_lines = []

        for line in lines:
            if line.lstrip().startswith("#"):
                new_lines.append(line)
                continue

            line = re.sub(
                r"\(([^)]*)\)",
                replace_option_group,
                line,
            )
            new_lines.append(line)

        with open(path, "w", encoding="utf-8") as file:
            file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        return [f"{path}: 조치 실패({error})"]

    return []


def _disable_samba_guest(path):
    try:
        _backup(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        new_lines = []

        for line in lines:
            if (
                line.strip()
                and not line.lstrip().startswith(("#", ";"))
                and re.match(
                    r"^\s*guest\s+ok\s*=",
                    line,
                    re.I,
                )
            ):
                indentation = line[: len(line) - len(line.lstrip())]
                new_lines.append(f"{indentation}guest ok = no\n")
            else:
                new_lines.append(line)

        with open(path, "w", encoding="utf-8") as file:
            file.writelines(new_lines)

    except (PermissionError, OSError) as error:
        return [f"{path}: 조치 실패({error})"]

    return []


def _restart_active_units(service_name):
    errors = []

    if shutil.which("systemctl") is None:
        return errors

    for unit in SERVICE_UNITS[service_name]:
        active = _run(["systemctl", "is-active", unit])

        if active is None or active.returncode != 0:
            continue

        restarted = _run(["systemctl", "restart", unit])

        if restarted is None or restarted.returncode != 0:
            errors.append(f"{unit}: 재시작 실패")

    return errors


def _fix(active_services):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    if "vsftpd" in active_services:
        paths = _existing_files(VSFTPD_FILES)

        if not paths:
            errors.append("vsftpd 설정 파일을 찾지 못해 조치하지 못함")

        for path in paths:
            errors.extend(_set_vsftpd_anonymous_no(path))

    if "proftpd" in active_services:
        paths = _existing_files(PROFTPD_FILES)

        if not paths:
            errors.append("ProFTP 설정 파일을 찾지 못해 조치하지 못함")

        for path in paths:
            errors.extend(
                _comment_proftpd_anonymous_blocks(path)
            )

    if (
        "nfs" in active_services
        and os.path.isfile(NFS_EXPORTS)
    ):
        errors.extend(
            _remove_nfs_anonymous_options(NFS_EXPORTS)
        )

    if "samba" in active_services:
        paths = _existing_files(SAMBA_FILES)

        if not paths:
            errors.append("Samba 설정 파일을 찾지 못해 조치하지 못함")

        for path in paths:
            errors.extend(_disable_samba_guest(path))

    for service_name in active_services:
        errors.extend(_restart_active_units(service_name))

    if (
        "nfs" in active_services
        and shutil.which("exportfs") is not None
    ):
        completed = _run(["exportfs", "-ra"])

        if completed is None or completed.returncode != 0:
            errors.append("exportfs -ra 실행 실패")

    if (
        "samba" in active_services
        and shutil.which("smbcontrol") is not None
    ):
        completed = _run(
            ["smbcontrol", "all", "reload-config"]
        )

        if completed is None or completed.returncode != 0:
            errors.append("Samba 설정 다시 읽기 실패")

    return errors


def check():
    active_services, issues = _get_issues()

    if not active_services:
        return result(
            CODE,
            TITLE,
            GOOD,
            "사용 중인 FTP, NFS 또는 Samba 공유 서비스가 없습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            (
                f"사용 중인 공유 서비스의 익명 접근이 제한되어 있습니다: "
                f"{', '.join(sorted(active_services))}"
            ),
        )

    before = summarize(issues)
    fix_errors = _fix(active_services)

    checked_services, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"공유 서비스 익명 접근 설정 확인 후 조치 완료: {before}. "
            f"익명·게스트 접근 설정을 비활성화했습니다."
        )

        if checked_services:
            detail += (
                f" 재점검 서비스: "
                f"{','.join(sorted(checked_services))}."
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
