#U-30: UMASK 설정 관리

import os
import re
import shutil
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-30"
TITLE = "UMASK 설정 관리"

TARGET_UMASK = 0o022

PROFILE_PATH = "/etc/profile"
LOGIN_DEFS_PATH = "/etc/login.defs"

VSFTPD_FILES = [
    "/etc/vsftpd.conf",
    "/etc/vsftpd/vsftpd.conf",
]

PROFTPD_FILES = [
    "/etc/proftpd/proftpd.conf",
    "/etc/proftpd.conf",
]


def _parse_umask(value):
    """
    022, 0022 형태의 문자열을 8진수 정수로 변환한다.
    """
    value = value.strip()

    if not re.fullmatch(r"[0-7]{3,4}", value):
        return None

    try:
        return int(value, 8)
    except ValueError:
        return None


def _umask_is_secure(value):
    """
    최소한 그룹 쓰기와 기타 사용자 쓰기 권한이
    마스킹되어 있는지 확인한다.

    양호 예시:
        022, 027, 077

    취약 예시:
        000, 002, 020
    """
    return (value & TARGET_UMASK) == TARGET_UMASK


def _active_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return [
                (line_number, line.strip())
                for line_number, line in enumerate(file, start=1)
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except (PermissionError, OSError):
        return None


def _check_profile(path):
    """
    /etc/profile의 다음 형태를 확인한다.

        umask 022
        umask=022
    """
    if not os.path.isfile(path):
        return [f"{path}: 파일 없음"]

    lines = _active_lines(path)

    if lines is None:
        return [f"{path}: 내용 확인 실패"]

    found = []
    issues = []

    pattern = re.compile(
        r"^\s*umask(?:\s+|=)\s*([0-7]{3,4})\b",
        re.I,
    )

    for line_number, line in lines:
        match = pattern.search(line)

        if not match:
            continue

        value = _parse_umask(match.group(1))
        found.append(value)

        if value is None:
            issues.append(f"{path}:{line_number}: UMASK 해석 실패")
        elif not _umask_is_secure(value):
            issues.append(
                f"{path}:{line_number}: umask={value:03o}"
            )

    if not found:
        issues.append(f"{path}: umask 설정 없음")

    return issues


def _check_login_defs(path):
    if not os.path.isfile(path):
        return [f"{path}: 파일 없음"]

    lines = _active_lines(path)

    if lines is None:
        return [f"{path}: 내용 확인 실패"]

    found = []
    issues = []

    pattern = re.compile(
        r"^\s*UMASK\s+([0-7]{3,4})\b",
        re.I,
    )

    for line_number, line in lines:
        match = pattern.search(line)

        if not match:
            continue

        value = _parse_umask(match.group(1))
        found.append(value)

        if value is None:
            issues.append(f"{path}:{line_number}: UMASK 해석 실패")
        elif not _umask_is_secure(value):
            issues.append(
                f"{path}:{line_number}: UMASK={value:03o}"
            )

    if not found:
        issues.append(f"{path}: UMASK 설정 없음")

    return issues


def _check_vsftpd(path):
    if not os.path.isfile(path):
        return []

    lines = _active_lines(path)

    if lines is None:
        return [f"{path}: 내용 확인 실패"]

    found = []
    issues = []

    pattern = re.compile(
        r"^\s*local_umask\s*=\s*([0-7]{3,4})\b",
        re.I,
    )

    for line_number, line in lines:
        match = pattern.search(line)

        if not match:
            continue

        value = _parse_umask(match.group(1))
        found.append(value)

        if value is None:
            issues.append(f"{path}:{line_number}: UMASK 해석 실패")
        elif not _umask_is_secure(value):
            issues.append(
                f"{path}:{line_number}: local_umask={value:03o}"
            )

    if not found:
        issues.append(f"{path}: local_umask 설정 없음")

    return issues


def _check_proftpd(path):
    if not os.path.isfile(path):
        return []

    lines = _active_lines(path)

    if lines is None:
        return [f"{path}: 내용 확인 실패"]

    found = []
    issues = []

    pattern = re.compile(
        r"^\s*Umask\s+([0-7]{3,4})\b",
        re.I,
    )

    for line_number, line in lines:
        match = pattern.search(line)

        if not match:
            continue

        value = _parse_umask(match.group(1))
        found.append(value)

        if value is None:
            issues.append(f"{path}:{line_number}: UMASK 해석 실패")
        elif not _umask_is_secure(value):
            issues.append(
                f"{path}:{line_number}: Umask={value:03o}"
            )

    if not found:
        issues.append(f"{path}: Umask 설정 없음")

    return issues


def _get_issues():
    issues = []

    issues.extend(_check_profile(PROFILE_PATH))
    issues.extend(_check_login_defs(LOGIN_DEFS_PATH))

    for path in VSFTPD_FILES:
        issues.extend(_check_vsftpd(path))

    for path in PROFTPD_FILES:
        issues.extend(_check_proftpd(path))

    return issues


def _backup(path):
    backup_path = f"{path}.u30.bak"

    if not os.path.exists(backup_path):
        shutil.copy2(path, backup_path)


def _replace_or_append(path, pattern, replacement):
    """
    활성화된 설정 줄을 권고값으로 변경한다.

    해당 설정이 없으면 파일 마지막에 추가한다.
    기존 주석 줄은 유지한다.
    """
    _backup(path)

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    changed = False
    new_lines = []

    for line in lines:
        stripped = line.lstrip()

        if stripped.startswith("#"):
            new_lines.append(line)
            continue

        if pattern.search(line):
            newline = "\n" if line.endswith("\n") else ""
            new_lines.append(replacement + newline)
            changed = True
        else:
            new_lines.append(line)

    if not changed:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"

        new_lines.append(replacement + "\n")

    with open(path, "w", encoding="utf-8") as file:
        file.writelines(new_lines)


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    settings = [
        (
            PROFILE_PATH,
            re.compile(
                r"^\s*umask(?:\s+|=)\s*[0-7]{3,4}\b",
                re.I,
            ),
            "umask 022",
            True,
        ),
        (
            LOGIN_DEFS_PATH,
            re.compile(
                r"^\s*UMASK\s+[0-7]{3,4}\b",
                re.I,
            ),
            "UMASK 022",
            True,
        ),
    ]

    for path in VSFTPD_FILES:
        settings.append(
            (
                path,
                re.compile(
                    r"^\s*local_umask\s*=\s*[0-7]{3,4}\b",
                    re.I,
                ),
                "local_umask=022",
                False,
            )
        )

    for path in PROFTPD_FILES:
        settings.append(
            (
                path,
                re.compile(
                    r"^\s*Umask\s+[0-7]{3,4}\b",
                    re.I,
                ),
                "Umask 022",
                False,
            )
        )

    for path, pattern, replacement, required in settings:
        if not os.path.isfile(path):
            if required:
                errors.append(f"{path}: 파일이 없어 조치하지 못함")
            continue

        try:
            file_stat = os.lstat(path)

            if stat.S_ISLNK(file_stat.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(file_stat.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            _replace_or_append(path, pattern, replacement)

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def check():
    issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "시스템 및 설치된 FTP 서비스의 UMASK가 022 이상으로 설정되어 있습니다.",
        )

    before = summarize(issues)
    fix_errors = _fix()

    remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 UMASK 설정 확인 후 조치 완료: {before}. "
            f"시스템 및 FTP 설정 파일의 UMASK를 022로 설정했습니다."
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
