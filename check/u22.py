#U-22: /etc/services 파일 소유자 및 권한 설정

import os
import pwd
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-22"
TITLE = "/etc/services 파일 소유자 및 권한 설정"

PATH = "/etc/services"
TARGET_MODE = 0o644


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
            continue

    return allowed_uids


def _get_issues():
    issues = []

    if not os.path.lexists(PATH):
        return [f"{PATH}: 파일 없음"]

    try:
        st = os.lstat(PATH)
    except (PermissionError, OSError) as error:
        return [f"{PATH}: 확인 실패({error})"]

    if stat.S_ISLNK(st.st_mode):
        return [f"{PATH}: 심볼릭 링크"]

    if not stat.S_ISREG(st.st_mode):
        return [f"{PATH}: 일반 파일 아님"]

    mode = stat.S_IMODE(st.st_mode)
    allowed_uids = _allowed_owner_uids()

    if st.st_uid not in allowed_uids:
        issues.append(f"{PATH}: 소유자 UID={st.st_uid}")

    # 0644에서 허용하지 않는 권한 비트가 존재하면 취약
    if mode & ~TARGET_MODE:
        issues.append(f"{PATH}: 권한={mode:04o}")

    return issues


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    if not os.path.lexists(PATH):
        return [f"{PATH}: 파일이 없어 조치할 수 없음"]

    try:
        st = os.lstat(PATH)

        if stat.S_ISLNK(st.st_mode):
            return [f"{PATH}: 심볼릭 링크이므로 자동 조치하지 않음"]

        if not stat.S_ISREG(st.st_mode):
            return [f"{PATH}: 일반 파일이 아니므로 자동 조치하지 않음"]

        os.chown(PATH, 0, -1)
        os.chmod(PATH, TARGET_MODE)

    except (PermissionError, OSError) as error:
        errors.append(f"{PATH}: 조치 실패({error})")

    return errors


def check():
    issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"{PATH} 파일의 소유자와 권한이 적절합니다.",
        )

    before = summarize(issues)

    fix_errors = _fix()

    remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 설정 확인 후 조치 완료: {before}. "
            f"소유자를 root로 변경하고 권한을 0644로 설정했습니다."
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
