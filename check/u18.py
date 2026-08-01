import os
import stat

from .common import GOOD, VULN, result


def check():
    code = "U-18"
    title = "/etc/shadow 파일 소유자 및 권한 설정"
    path = "/etc/shadow"

    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        return result(code, title, VULN, f"{path} 파일이 존재하지 않습니다.")
    except OSError as error:
        return result(code, title, VULN, f"{path} 파일 정보를 확인하지 못했습니다: {error}")

    if stat.S_ISLNK(file_stat.st_mode):
        return result(code, title, VULN, f"{path} 파일이 심볼릭 링크로 설정되어 있습니다.")

    if not stat.S_ISREG(file_stat.st_mode):
        return result(code, title, VULN, f"{path} 경로가 일반 파일이 아닙니다.")

    owner_uid = file_stat.st_uid
    mode = stat.S_IMODE(file_stat.st_mode)

    owner_ok = owner_uid == 0

    # 허용되는 권한 비트는 소유자의 읽기 권한 0400뿐이다.
    # 0000처럼 더 제한적인 권한도 허용한다.
    permission_ok = (mode & ~0o400) == 0

    if owner_ok and permission_ok:
        return result(
            code,
            title,
            GOOD,
            f"{path} 파일의 소유자가 root이고 권한이 {mode:04o}로 적절합니다.",
        )

    weak_evidence = []

    if not owner_ok:
        weak_evidence.append(f"소유자 UID={owner_uid}")

    if not permission_ok:
        weak_evidence.append(f"권한={mode:04o}")

    return result(
        code,
        title,
        VULN,
        f"{path} 파일의 소유자 또는 권한이 부적절합니다: {', '.join(weak_evidence)}",
    )
