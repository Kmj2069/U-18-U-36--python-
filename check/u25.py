#U-25: world writable 파일 점검

import os
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-25"
TITLE = "world writable 파일 점검"


# 운영상 world writable이 반드시 필요한 것으로 확인된 파일을 등록한다.
# 예:
# APPROVED_WORLD_WRITABLE = {
#     "/경로/정상적으로/필요한/파일",
# }
APPROVED_WORLD_WRITABLE = set()


SKIP_PATHS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
}


def _normalized_approved_paths():
    return {
        os.path.realpath(path)
        for path in APPROVED_WORLD_WRITABLE
    }


def _scan_world_writable_files():
    vulnerable_files = []
    scan_errors = []

    try:
        root_device = os.lstat("/").st_dev
    except OSError as error:
        return [], [f"/: 파일시스템 확인 실패({error})"]

    approved_paths = _normalized_approved_paths()

    def walk_error(error):
        path = error.filename or "알 수 없는 경로"
        scan_errors.append(f"{path}: 탐색 실패({error})")

    for current_dir, dirnames, filenames in os.walk(
        "/",
        topdown=True,
        followlinks=False,
        onerror=walk_error,
    ):
        accessible_dirs = []

        for dirname in dirnames:
            directory_path = os.path.join(current_dir, dirname)

            if directory_path in SKIP_PATHS:
                continue

            try:
                st = os.lstat(directory_path)
            except (PermissionError, OSError) as error:
                scan_errors.append(f"{directory_path}: 확인 실패({error})")
                continue

            if stat.S_ISLNK(st.st_mode):
                continue

            # 다른 마운트 지점은 탐색하지 않는다. find의 -xdev와 유사하다.
            if st.st_dev != root_device:
                continue

            accessible_dirs.append(dirname)

        dirnames[:] = accessible_dirs

        for filename in filenames:
            path = os.path.join(current_dir, filename)

            try:
                st = os.lstat(path)
            except (PermissionError, OSError) as error:
                scan_errors.append(f"{path}: 확인 실패({error})")
                continue

            if st.st_dev != root_device:
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            if not st.st_mode & stat.S_IWOTH:
                continue

            if os.path.realpath(path) in approved_paths:
                continue

            mode = stat.S_IMODE(st.st_mode)
            vulnerable_files.append((path, mode))

    return vulnerable_files, scan_errors


def _fix(paths):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for path in paths:
        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            current_mode = stat.S_IMODE(st.st_mode)

            # chmod o-w와 동일하게 기타 사용자 쓰기 권한만 제거
            fixed_mode = current_mode & ~stat.S_IWOTH

            os.chmod(path, fixed_mode)

        except FileNotFoundError:
            errors.append(f"{path}: 조치 전에 파일이 사라짐")
        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def _format_issues(files, scan_errors):
    issues = [
        f"{path}: mode={mode:04o}"
        for path, mode in files
    ]

    issues.extend(scan_errors)
    return issues


def check():
    vulnerable_files, scan_errors = _scan_world_writable_files()
    issues = _format_issues(vulnerable_files, scan_errors)

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "승인되지 않은 world writable 일반 파일이 없습니다.",
        )

    before = summarize(issues)

    fix_errors = _fix([path for path, _ in vulnerable_files])

    remaining_files, remaining_scan_errors = _scan_world_writable_files()
    remaining_issues = _format_issues(
        remaining_files,
        remaining_scan_errors,
    )

    if not remaining_issues:
        detail = (
            f"world writable 파일 확인 후 조치 완료: {before}. "
            f"총 {len(vulnerable_files)}개 파일에서 "
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
