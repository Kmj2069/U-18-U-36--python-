#U-23: SUID, SGID, Sticky bit 설정 파일 점검
"""코드 추가 점검 필요!!!"""

import os
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-23"
TITLE = "SUID, SGID, Sticky bit 설정 파일 점검"

SPECIAL_PERMISSION_MASK = 0o7000


# Ubuntu에서 정상적인 시스템 기능을 위해 특수 권한이 사용될 수 있는
# 대표적인 파일 목록이다.
#
# 이 목록은 KISA 가이드에 직접 제시된 목록이 아니라,
# 정상 시스템 파일의 특수 권한을 무조건 제거하지 않기 위한 구현용 기준이다.
EXPECTED_SPECIAL_FILES = {
    "/usr/bin/chage",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/crontab",
    "/usr/bin/expiry",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/newgrp",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/umount",
    "/usr/bin/wall",
    "/usr/bin/write.ul",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/snapd/snap-confine",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/sbin/unix_chkpwd",
}


def _normalized_expected_files():
    """
    /bin 등이 /usr/bin으로 연결된 merged-usr 환경을 고려하여
    허용 파일 경로를 실제 경로 형태로 정규화한다.
    """
    return {
        os.path.realpath(path)
        for path in EXPECTED_SPECIAL_FILES
    }


def _special_permission_text(mode):
    permissions = []

    if mode & stat.S_ISUID:
        permissions.append("SUID")

    if mode & stat.S_ISGID:
        permissions.append("SGID")

    if mode & stat.S_ISVTX:
        permissions.append("Sticky bit")

    return "/".join(permissions)


def _scan_special_files():
    """
    루트 파일시스템에서 특수 권한이 설정된 일반 파일을 검색한다.

    KISA 가이드의 다음 명령과 유사한 동작이다.

    find / -user root -type f
        \\( -perm -04000 -o -perm -02000 \\)
        -xdev -exec ls -al {} \\;

    다른 파일시스템은 탐색하지 않아 -xdev와 비슷하게 처리한다.
    """
    files = []
    scan_errors = []

    try:
        root_device = os.lstat("/").st_dev
    except OSError as error:
        return [], [f"/: 파일시스템 확인 실패({error})"]

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

            try:
                st = os.lstat(directory_path)
            except (PermissionError, OSError) as error:
                scan_errors.append(
                    f"{directory_path}: 확인 실패({error})"
                )
                continue

            if stat.S_ISLNK(st.st_mode):
                continue

            # /proc, /sys, /dev 등 다른 파일시스템은 탐색하지 않는다.
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

            mode = stat.S_IMODE(st.st_mode)
            special_permissions = mode & SPECIAL_PERMISSION_MASK

            if special_permissions:
                files.append((path, mode))

    return files, scan_errors


def _get_issues():
    special_files, scan_errors = _scan_special_files()
    expected_files = _normalized_expected_files()

    issues = list(scan_errors)
    unexpected_files = []

    for path, mode in special_files:
        normalized_path = os.path.realpath(path)

        if normalized_path in expected_files:
            continue

        unexpected_files.append(path)

        permission_text = _special_permission_text(mode)

        issues.append(
            f"{path}: {permission_text}, 권한={mode:04o}"
        )

    return unexpected_files, issues


def _fix(paths):
    """
    허용 목록에 없는 파일에서 SUID, SGID, Sticky bit를 제거한다.

    chmod -s는 SUID와 SGID만 제거하므로,
    Sticky bit까지 포함하기 위해 07000 비트를 제거한다.
    """
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    for path in paths:
        if not os.path.lexists(path):
            errors.append(f"{path}: 파일이 사라져 조치하지 못함")
            continue

        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            current_mode = stat.S_IMODE(st.st_mode)

            # 기존 읽기·쓰기·실행 권한은 유지하고
            # SUID, SGID, Sticky bit만 제거한다.
            fixed_mode = current_mode & ~SPECIAL_PERMISSION_MASK

            os.chmod(path, fixed_mode)

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def check():
    unexpected_files, issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "허용 목록 외의 SUID, SGID 또는 Sticky bit 설정 파일이 없습니다.",
        )

    before = summarize(issues)

    fix_errors = _fix(unexpected_files)

    remaining_files, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"의심스러운 특수 권한 파일 확인 후 조치 완료: {before}. "
            f"총 {len(unexpected_files)}개 파일에서 "
            f"SUID, SGID 또는 Sticky bit를 제거했습니다."
        )

        if fix_errors:
            detail += f" 조치 중 경고: {summarize(fix_errors)}"

        return result(CODE, TITLE, GOOD, detail)

    detail = (
        f"조치 전 취약 항목: {before}. "
        f"조치 후에도 남은 항목: {summarize(remaining_issues)}"
    )

    if remaining_files:
        detail += f". 미조치 파일 수: {len(remaining_files)}"

    if fix_errors:
        detail += f". 조치 오류: {summarize(fix_errors)}"

    return result(CODE, TITLE, VULN, detail)
