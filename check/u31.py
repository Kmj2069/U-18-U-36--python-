#U-31: 홈 디렉터리 소유자 및 권한 설정

import os
import pwd
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-31"
TITLE = "홈 디렉터리 소유자 및 권한 설정"


NOLOGIN_SHELLS = {
    "",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/nologin",
    "/dev/null",
}


def _collect_home_directories():
    """
    실제 로그인 가능한 계정의 홈 디렉터리를 수집한다.

    반환 형식:
        {
            홈 경로: [pwd.struct_passwd, ...]
        }

    동일한 홈 디렉터리를 여러 계정이 사용하는 경우를 확인하기 위해
    계정 목록 형태로 저장한다.
    """
    homes = {}

    for account in pwd.getpwall():
        if account.pw_shell in NOLOGIN_SHELLS:
            continue

        home = account.pw_dir

        if not home or not os.path.isabs(home):
            continue

        # U-32에서 존재하지 않는 홈 디렉터리를 별도로 검사한다.
        if not os.path.lexists(home):
            continue

        homes.setdefault(home, []).append(account)

    return homes


def _get_issues():
    homes = _collect_home_directories()
    issues = []

    for home, accounts in sorted(homes.items()):
        account_names = [account.pw_name for account in accounts]

        if len(accounts) > 1:
            issues.append(
                f"{home}: 여러 계정이 동일 홈 사용"
                f"({','.join(account_names)})"
            )
            continue

        account = accounts[0]

        try:
            directory_stat = os.lstat(home)
        except (PermissionError, OSError) as error:
            issues.append(f"{home}: 확인 실패({error})")
            continue

        if stat.S_ISLNK(directory_stat.st_mode):
            issues.append(f"{home}: 심볼릭 링크")
            continue

        if not stat.S_ISDIR(directory_stat.st_mode):
            issues.append(f"{home}: 디렉터리가 아님")
            continue

        mode = stat.S_IMODE(directory_stat.st_mode)

        if directory_stat.st_uid != account.pw_uid:
            issues.append(
                f"{home}: 소유자 UID={directory_stat.st_uid}, "
                f"권고 계정={account.pw_name}"
            )

        # 가이드의 chmod o-w에 해당한다.
        if mode & stat.S_IWOTH:
            issues.append(
                f"{home}: 기타 사용자 쓰기 권한, mode={mode:04o}"
            )

    return homes, issues


def _fix(homes):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for home, accounts in sorted(homes.items()):
        if len(accounts) != 1:
            account_names = ",".join(
                account.pw_name for account in accounts
            )

            errors.append(
                f"{home}: 여러 계정이 공동 사용하여 자동 조치하지 않음"
                f"({account_names})"
            )
            continue

        account = accounts[0]

        try:
            directory_stat = os.lstat(home)

            if stat.S_ISLNK(directory_stat.st_mode):
                errors.append(
                    f"{home}: 심볼릭 링크이므로 자동 조치하지 않음"
                )
                continue

            if not stat.S_ISDIR(directory_stat.st_mode):
                errors.append(
                    f"{home}: 디렉터리가 아니므로 자동 조치하지 않음"
                )
                continue

            if directory_stat.st_uid != account.pw_uid:
                # 그룹 소유자는 기존 값을 유지한다.
                os.chown(home, account.pw_uid, -1)

            current_mode = stat.S_IMODE(directory_stat.st_mode)
            fixed_mode = current_mode & ~stat.S_IWOTH

            if fixed_mode != current_mode:
                os.chmod(home, fixed_mode)

        except (PermissionError, OSError) as error:
            errors.append(f"{home}: 조치 실패({error})")

    return errors


def check():
    homes, issues = _get_issues()

    if not homes:
        return result(
            CODE,
            TITLE,
            GOOD,
            "점검할 로그인 가능 계정의 홈 디렉터리가 없습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            (
                f"홈 디렉터리 {len(homes)}개의 소유자가 해당 계정으로 "
                f"설정되어 있고 기타 사용자 쓰기 권한이 없습니다."
            ),
        )

    before = summarize(issues)
    fix_errors = _fix(homes)

    checked_homes, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 홈 디렉터리 설정 확인 후 조치 완료: {before}. "
            f"홈 디렉터리 {len(checked_homes)}개의 소유자를 정상화하고 "
            f"기타 사용자 쓰기 권한을 제거했습니다."
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
