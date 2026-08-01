#U-18: /etc/shadow 파일 소유자 및 권한 설정

import os
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-18"
TITLE = "/etc/shadow 파일 소유자 및 권한 설정"

PATH = "/etc/shadow"
TARGET_MODE = 0o400


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

    if st.st_uid != 0:
        issues.append(f"{PATH}: 소유자 UID={st.st_uid}")

    # 허용되는 권한 비트는 소유자 읽기 권한인 04000만 허용.(이외 권한은 허용 x)
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

        # 가이드의 chown root /etc/shadow에 해당한다.
        # 그룹은 변경하지 않고 기존 값을 유지한다.
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
            f"{PATH} 파일의 소유자가 root이고 권한이 0400 이하입니다.",
        )

    before = summarize(issues)
    fix_errors = _fix()
    remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 설정 확인 후 조치 완료: {before}. "
            f"소유자를 root로 변경하고 권한을 0400으로 설정했습니다."
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
