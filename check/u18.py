#U-18 취약점 보완 코드 
import os
import stat
from pathlib import Path

try:
    import pwd
except ImportError:
    pwd = None

from common import GOOD, VULN, NA, result


CODE = "U-18"
TITLE = "/etc/shadow 파일 소유자 및 권한 설정"

SHADOW_FILE = Path("/etc/shadow")
TARGET_OWNER_UID = 0
TARGET_MODE = 0o400


def owner_name(uid):
    """UID를 계정 이름으로 변환한다."""
    if pwd is None:
        return str(uid)

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"UID {uid}"


def permission_is_secure(mode):
    """
    /etc/shadow의 권한이 400 이하인지 판단한다.

    허용:
        400 : root 읽기 가능
        000 : 아무도 접근 불가

    취약 예시:
        600 : root 쓰기 권한 존재
        440 : 그룹 읽기 권한 존재
        404 : 기타 사용자 읽기 권한 존재
        777 : 모든 사용자 접근 가능

    단순히 mode <= 0o400으로 비교하면 040 같은 그룹 권한을
    잘못 양호로 판단할 수 있으므로 비트 단위로 검사한다.
    """
    allowed_bits = 0o400

    # 040, 004, 200, 100, SUID 등의 허용되지 않은 비트가
    # 하나라도 존재하면 False가 된다.
    return (mode & ~allowed_bits) == 0


def check():
    """
    U-18 취약점을 점검한다.

    반환값:
        common.result() 형식의 딕셔너리
    """
    if os.name != "posix":
        return result(
            CODE,
            TITLE,
            NA,
            "UNIX/Linux 계열 운영체제가 아니므로 점검할 수 없습니다.",
        )

    try:
        file_stat = os.lstat(SHADOW_FILE)

    except FileNotFoundError:
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일이 존재하지 않습니다.",
        )

    except PermissionError as error:
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일 정보를 확인할 권한이 없습니다: {error}",
        )

    except OSError as error:
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일 점검 중 오류가 발생했습니다: {error}",
        )

    # 심볼릭 링크를 따라가서 다른 파일의 권한을 변경하는 일을 방지한다.
    if stat.S_ISLNK(file_stat.st_mode):
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일이 심볼릭 링크입니다. 수동 확인이 필요합니다.",
        )

    if not stat.S_ISREG(file_stat.st_mode):
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 경로가 일반 파일이 아닙니다.",
        )

    current_uid = file_stat.st_uid
    current_owner = owner_name(current_uid)
    current_mode = stat.S_IMODE(file_stat.st_mode)

    owner_ok = current_uid == TARGET_OWNER_UID
    permission_ok = permission_is_secure(current_mode)

    problems = []

    if not owner_ok:
        problems.append(
            f"소유자가 root가 아닙니다. 현재 소유자: {current_owner}"
        )

    if not permission_ok:
        problems.append(
            f"권한이 기준을 만족하지 않습니다. 현재 권한: {current_mode:04o}"
        )

    detail = (
        f"점검 파일: {SHADOW_FILE}\n"
        f"현재 소유자: {current_owner} (UID={current_uid})\n"
        f"현재 권한: {current_mode:04o}\n"
        f"권고 소유자: root (UID=0)\n"
        f"권고 권한: 0400"
    )

    if problems:
        detail += "\n판단 근거:\n- " + "\n- ".join(problems)

        return result(
            CODE,
            TITLE,
            VULN,
            detail,
        )

    return result(
        CODE,
        TITLE,
        GOOD,
        detail + "\n소유자와 권한이 모두 기준을 만족합니다.",
    )


def fix():
    """
    /etc/shadow의 소유자를 root로, 권한을 0400으로 변경한다.

    조치 명령에 해당하는 Python 코드:
        chown root /etc/shadow
        chmod 400 /etc/shadow
    """
    if os.name != "posix":
        return result(
            CODE,
            TITLE,
            NA,
            "UNIX/Linux 계열 운영체제가 아니므로 조치할 수 없습니다.",
        )

    if os.geteuid() != 0:
        return result(
            CODE,
            TITLE,
            VULN,
            "소유자와 권한을 변경하려면 root 권한이 필요합니다. "
            "sudo를 사용하여 다시 실행해야 합니다.",
        )

    try:
        file_stat = os.lstat(SHADOW_FILE)

    except FileNotFoundError:
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일이 존재하지 않아 자동 조치하지 않았습니다.",
        )

    except OSError as error:
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일 확인 중 오류가 발생했습니다: {error}",
        )

    if stat.S_ISLNK(file_stat.st_mode):
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 파일이 심볼릭 링크이므로 자동 조치하지 않았습니다.",
        )

    if not stat.S_ISREG(file_stat.st_mode):
        return result(
            CODE,
            TITLE,
            VULN,
            f"{SHADOW_FILE} 경로가 일반 파일이므로 판단되지 않아 "
            "자동 조치하지 않았습니다.",
        )

    old_owner = owner_name(file_stat.st_uid)
    old_mode = stat.S_IMODE(file_stat.st_mode)

    try:
        # chown root /etc/shadow
        # 그룹은 변경하지 않기 위해 gid에 -1을 전달한다.
        os.chown(SHADOW_FILE, TARGET_OWNER_UID, -1)

        # chmod 400 /etc/shadow
        os.chmod(SHADOW_FILE, TARGET_MODE)

    except PermissionError as error:
        return result(
            CODE,
            TITLE,
            VULN,
            f"권한 부족으로 조치하지 못했습니다: {error}",
        )

    except OSError as error:
        return result(
            CODE,
            TITLE,
            VULN,
            f"조치 중 오류가 발생했습니다: {error}",
        )

    return result(
        CODE,
        TITLE,
        GOOD,
        (
            f"{SHADOW_FILE} 파일을 조치했습니다.\n"
            f"소유자 변경: {old_owner} → root\n"
            f"권한 변경: {old_mode:04o} → 0400"
        ),
    )


def run():
    """
    점검 → 취약 시 조치 → 재점검 과정을 수행한다.
    """
    before = check()

    # 이미 양호하거나 점검 대상이 아니면 변경하지 않는다.
    if before["status"] != VULN:
        return before

    fix_result = fix()
    after = check()

    combined_detail = (
        "[조치 전 점검]\n"
        f"{before['detail']}\n\n"
        "[조치 수행]\n"
        f"{fix_result['detail']}\n\n"
        "[조치 후 재점검]\n"
        f"{after['detail']}"
    )

    return result(
        CODE,
        TITLE,
        after["status"],
        combined_detail,
    )


def print_result(check_result):
    """터미널에 점검 결과를 출력한다."""
    print("=" * 70)
    print(f"[{check_result['code']}] {check_result['title']}")
    print(f"최종 상태: {check_result['status']}")
    print("-" * 70)
    print(check_result["detail"])
    print("=" * 70)


if __name__ == "__main__":
    print_result(run())
