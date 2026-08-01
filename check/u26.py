#U-26: /dev에 존재하지 않는 device 파일 점검

import os
import shutil
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-26"
TITLE = "/dev에 존재하지 않는 device 파일 점검"

DEV_PATH = "/dev"
QUARANTINE_DIR = "/root/u26_quarantine"

EXCLUDED_DIRS = {
    "/dev/shm",
    "/dev/mqueue",
}


def _scan_regular_files():
    suspicious_files = []
    scan_errors = []

    if not os.path.isdir(DEV_PATH):
        return [], [f"{DEV_PATH}: 디렉터리가 존재하지 않음"]

    def walk_error(error):
        path = error.filename or "알 수 없는 경로"
        scan_errors.append(f"{path}: 탐색 실패({error})")

    for current_dir, dirnames, filenames in os.walk(
        DEV_PATH,
        topdown=True,
        followlinks=False,
        onerror=walk_error,
    ):
        accessible_dirs = []

        for dirname in dirnames:
            directory_path = os.path.join(current_dir, dirname)

            if directory_path in EXCLUDED_DIRS:
                continue

            try:
                st = os.lstat(directory_path)
            except (PermissionError, OSError) as error:
                scan_errors.append(f"{directory_path}: 확인 실패({error})")
                continue

            if stat.S_ISLNK(st.st_mode):
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

            # 문자·블록 장치가 아닌 일반 파일만 탐지한다.
            if stat.S_ISREG(st.st_mode):
                suspicious_files.append(path)

    return sorted(suspicious_files), scan_errors


def _unique_destination(destination):
    if not os.path.lexists(destination):
        return destination

    index = 1

    while True:
        candidate = f"{destination}.{index}"

        if not os.path.lexists(candidate):
            return candidate

        index += 1


def _quarantine(paths):
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    try:
        os.makedirs(QUARANTINE_DIR, mode=0o700, exist_ok=True)
        os.chmod(QUARANTINE_DIR, 0o700)
    except (PermissionError, OSError) as error:
        return [f"{QUARANTINE_DIR}: 격리 디렉터리 생성 실패({error})"]

    for path in paths:
        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            relative_path = os.path.relpath(path, DEV_PATH)
            destination = os.path.join(QUARANTINE_DIR, relative_path)

            destination_parent = os.path.dirname(destination)
            os.makedirs(destination_parent, mode=0o700, exist_ok=True)

            destination = _unique_destination(destination)

            # 즉시 삭제하지 않고 복구 가능한 위치로 이동한다.
            shutil.move(path, destination)

        except FileNotFoundError:
            errors.append(f"{path}: 조치 전에 파일이 사라짐")
        except (PermissionError, OSError, shutil.Error) as error:
            errors.append(f"{path}: 격리 실패({error})")

    return errors


def _format_issues(files, scan_errors):
    issues = [f"{path}: /dev 내 일반 파일" for path in files]
    issues.extend(scan_errors)
    return issues


def check():
    suspicious_files, scan_errors = _scan_regular_files()
    issues = _format_issues(suspicious_files, scan_errors)

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "/dev에서 의심스러운 일반 파일이 발견되지 않았습니다.",
        )

    before = summarize(issues)

    fix_errors = _quarantine(suspicious_files)

    remaining_files, remaining_scan_errors = _scan_regular_files()
    remaining_issues = _format_issues(
        remaining_files,
        remaining_scan_errors,
    )

    if not remaining_issues:
        detail = (
            f"/dev 내 일반 파일 확인 후 조치 완료: {before}. "
            f"총 {len(suspicious_files)}개 파일을 "
            f"{QUARANTINE_DIR}으로 이동했습니다."
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
