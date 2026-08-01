#U-32: 홈 디렉토리로 지정한 디렉토리의 존재 관리

import os
import pwd
import re
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-32"
TITLE = "홈 디렉토리로 지정한 디렉토리의 존재 관리"

LOGIN_DEFS_PATH = "/etc/login.defs"

NOLOGIN_SHELLS = {
    "",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/nologin",
    "/usr/bin/nologin",
    "/dev/null",
}

# 이 경로 자체를 새 홈 디렉터리로 만들거나 소유권 변경하지 않는다.
UNSAFE_HOME_PATHS = {
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/run",
    "/sbin",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
}


def _uid_min():
    """
    /etc/login.defs의 UID_MIN을 읽는다.
    확인하지 못하면 Ubuntu 일반 사용자 기본값인 1000을 사용한다.
    """
    try:
        with open(
            LOGIN_DEFS_PATH,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for line in file:
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                match = re.match(r"^UID_MIN\s+(\d+)\b", stripped)

                if match:
                    return int(match.group(1))

    except (PermissionError, OSError, ValueError):
        pass

    return 1000


def _target_accounts():
    """
    실제 로그인 가능한 일반 사용자와 root 계정을 점검한다.

    시스템 서비스 계정의 /nonexistent 같은 의도적인 설정은
    자동 조치 대상에서 제외한다.
    """
    minimum_uid = _uid_min()
    accounts = []

    for account in pwd.getpwall():
        if account.pw_shell in NOLOGIN_SHELLS:
            continue

        if account.pw_uid != 0 and account.pw_uid < minimum_uid:
            continue

        accounts.append(account)

    return accounts


def _get_issues():
    accounts = _target_accounts()
    issues = []

    for account in accounts:
        home = account.pw_dir

        if not home:
            issues.append(f"{account.pw_name}: 홈 디렉터리 설정 없음")
            continue

        if not os.path.isabs(home):
            issues.append(
                f"{account.pw_name}: 절대 경로가 아닌 홈 디렉터리({home})"
            )
            continue

        if not os.path.exists(home):
            issues.append(
                f"{account.pw_name}: 홈 디렉터리 없음({home})"
            )
            continue

        if not os.path.isdir(home):
            issues.append(
                f"{account.pw_name}: 홈 경로가 디렉터리가 아님({home})"
            )

    return accounts, issues


def _safe_home_path(path):
    """
    시스템 핵심 경로나 상위 경로를 홈 디렉터리로 생성하지 않는다.
    """
    normalized = os.path.normpath(path)

    if normalized in UNSAFE_HOME_PATHS:
        return False

    if not os.path.isabs(normalized):
        return False

    return True


def _fix(accounts):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for account in accounts:
        home = account.pw_dir

        if not home or not os.path.isabs(home):
            errors.append(
                f"{account.pw_name}: 홈 경로 설정이 잘못되어 자동 조치하지 않음"
            )
            continue

        if os.path.isdir(home):
            continue

        if os.path.lexists(home):
            errors.append(
                f"{account.pw_name}: {home} 경로에 디렉터리가 아닌 항목이 존재함"
            )
            continue

        if not _safe_home_path(home):
            errors.append(
                f"{account.pw_name}: 위험한 홈 경로이므로 생성하지 않음({home})"
            )
            continue

        try:
            os.makedirs(home, mode=0o750, exist_ok=False)

            os.chown(
                home,
                account.pw_uid,
                account.pw_gid,
            )

            # root 홈은 조금 더 엄격하게 설정한다.
            if account.pw_uid == 0:
                os.chmod(home, 0o700)
            else:
                os.chmod(home, 0o750)

        except FileExistsError:
            if not os.path.isdir(home):
                errors.append(
                    f"{account.pw_name}: {home} 경로 생성 중 다른 항목이 생김"
                )

        except (PermissionError, OSError) as error:
            errors.append(
                f"{account.pw_name}: {home} 생성 실패({error})"
            )

    return errors


def check():
    accounts, issues = _get_issues()

    if not accounts:
        return result(
            CODE,
            TITLE,
            GOOD,
            "점검할 로그인 가능 계정이 없습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            (
                f"로그인 가능 계정 {len(accounts)}개의 홈 디렉터리가 "
                f"모두 존재합니다."
            ),
        )

    before = summarize(issues)
    fix_errors = _fix(accounts)

    checked_accounts, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"존재하지 않는 홈 디렉터리 확인 후 조치 완료: {before}. "
            f"누락된 홈 디렉터리를 생성하고 계정 소유권을 설정했습니다."
        )

        if fix_errors:
            detail += f" 조치 중 경고: {summarize(fix_errors)}"

        return result(CODE, TITLE, GOOD, detail)

    detail = (
        f"조치 전 취약 항목: {before}. "
        f"조치 후에도 남은 항목: {summarize(remaining_issues)}"
    )

    if checked_accounts:
        detail += f". 재점검 계정 수: {len(checked_accounts)}"

    if fix_errors:
        detail += f". 조치 오류: {summarize(fix_errors)}"

    return result(CODE, TITLE, VULN, detail)
