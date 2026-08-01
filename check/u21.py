#U-21: /etc/(r)syslog.conf 파일 소유자 및 권한 설정

import os
import pwd
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-21"
TITLE = "/etc/(r)syslog.conf 파일 소유자 및 권한 설정"

CONFIG_FILES = [
    "/etc/syslog.conf",
    "/etc/rsyslog.conf",
]

TARGET_MODE = 0o640


def _allowed_owner_uids():
    """
    가이드에서 허용하는 소유자:
    root, bin, sys
    """
    allowed_uids = {0}

    for username in ("bin", "sys"):
        try:
            allowed_uids.add(pwd.getpwnam(username).pw_uid)
        except KeyError:
            # 해당 계정이 없는 시스템에서는 제외한다.
            continue

    return allowed_uids


def _get_issues():
    issues = []
    targets = []

    allowed_uids = _allowed_owner_uids()

    for path in CONFIG_FILES:
        if not os.path.lexists(path):
            continue

        targets.append(path)

        try:
            st = os.lstat(path)
        except (PermissionError, OSError) as error:
            issues.append(f"{path}: 확인 실패({error})")
            continue

        if stat.S_ISLNK(st.st_mode):
            issues.append(f"{path}: 심볼릭 링크")
            continue

        if not stat.S_ISREG(st.st_mode):
            issues.append(f"{path}: 일반 파일 아님")
            continue

        mode = stat.S_IMODE(st.st_mode)

        if st.st_uid not in allowed_uids:
            issues.append(f"{path}: 소유자 UID={st.st_uid}")

        # 0640에서 허용하지 않는 권한 비트가 존재하면 취약
        if mode & ~TARGET_MODE:
            issues.append(f"{path}: 권한={mode:04o}")

    return targets, issues


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for path in CONFIG_FILES:
        if not os.path.lexists(path):
            continue

        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            # chown root <파일>에 해당한다.
            # 그룹은 기존 값을 유지한다.
            os.chown(path, 0, -1)

            # chmod 640 <파일>
            os.chmod(path, TARGET_MODE)

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def check():
    targets, issues = _get_issues()

    if not targets:
        return result(
            CODE,
            TITLE,
            GOOD,
            "syslog.conf 또는 rsyslog.conf 파일이 존재하지 않습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"로그 설정 파일 {len(targets)}개의 소유자와 권한이 적절합니다.",
        )

    before = summarize(issues)

    fix_errors = _fix()

    checked_targets, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 설정 확인 후 조치 완료: {before}. "
            f"설정 파일 {len(checked_targets)}개의 소유자를 root로 변경하고 "
            f"권한을 0640으로 설정했습니다."
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
