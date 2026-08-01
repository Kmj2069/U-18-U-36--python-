#U-24: 사용자, 시스템 환경변수 파일 소유자 및 권한 설정

import os
import pwd
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-24"
TITLE = "사용자, 시스템 환경변수 파일 소유자 및 권한 설정"

ENV_FILE_NAMES = (
    ".profile",
    ".kshrc",
    ".cshrc",
    ".bashrc",
    ".bash_profile",
    ".login",
    ".exrc",
    ".netrc",
)


def _collect_targets():
    """
    /etc/passwd에 등록된 계정의 홈 디렉터리에서
    점검 대상 환경변수 파일을 수집한다.
    """
    targets = {}

    for account in pwd.getpwall():
        home = account.pw_dir

        if not home or not os.path.isabs(home):
            continue

        if not os.path.isdir(home):
            continue

        for filename in ENV_FILE_NAMES:
            path = os.path.join(home, filename)

            if not os.path.lexists(path):
                continue

            info = targets.setdefault(
                path,
                {
                    "home": home,
                    "account_uids": set(),
                    "accounts": set(),
                },
            )

            info["account_uids"].add(account.pw_uid)
            info["accounts"].add(account.pw_name)

    return targets


def _preferred_owner_uid(info):
    """
    잘못된 소유자를 자동 조치할 때 사용할 UID를 결정한다.

    홈 디렉터리 소유자가 해당 계정 중 하나라면 그 UID를 사용하고,
    그렇지 않으면 등록된 계정 UID 중 하나를 사용한다.
    """
    try:
        home_stat = os.lstat(info["home"])

        if home_stat.st_uid in info["account_uids"]:
            return home_stat.st_uid
    except OSError:
        pass

    return min(info["account_uids"])


def _get_issues():
    targets = _collect_targets()
    issues = []

    for path, info in sorted(targets.items()):
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

        allowed_uids = set(info["account_uids"])
        allowed_uids.add(0)

        if st.st_uid not in allowed_uids:
            issues.append(
                f"{path}: 소유자 UID={st.st_uid}, "
                f"허용 계정={','.join(sorted(info['accounts']))}"
            )

        # 그룹 또는 기타 사용자 쓰기 권한이 있으면 취약
        if mode & 0o022:
            issues.append(f"{path}: 그룹/기타 사용자 쓰기 권한, mode={mode:04o}")

    return targets, issues


def _fix(targets):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for path, info in sorted(targets.items()):
        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            allowed_uids = set(info["account_uids"])
            allowed_uids.add(0)

            if st.st_uid not in allowed_uids:
                new_uid = _preferred_owner_uid(info)
                os.chown(path, new_uid, -1)

            current_mode = stat.S_IMODE(st.st_mode)

            # 그룹과 기타 사용자의 쓰기 권한만 제거한다.
            fixed_mode = current_mode & ~0o022

            if fixed_mode != current_mode:
                os.chmod(path, fixed_mode)

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
            "점검 대상 홈 디렉터리 환경변수 파일이 없습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"환경변수 파일 {len(targets)}개의 소유자와 쓰기 권한이 적절합니다.",
        )

    before = summarize(issues)
    fix_errors = _fix(targets)

    checked_targets, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 설정 확인 후 조치 완료: {before}. "
            f"환경변수 파일 {len(checked_targets)}개의 소유자를 정상화하고 "
            f"그룹·기타 사용자 쓰기 권한을 제거했습니다."
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
