#U-20: /etc/(x)inetd.conf 파일 소유자 및 권한 설정

import os
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-20"
TITLE = "/etc/(x)inetd.conf 파일 소유자 및 권한 설정"

TARGET_MODE = 0o600

DIRECT_FILES = [
    "/etc/inetd.conf",
    "/etc/xinetd.conf",
    "/etc/systemd/system.conf",
]

CONFIG_DIRS = [
    "/etc/xinetd.d",
    "/etc/systemd",
]


def _collect_targets():
    """
    존재하는 U-20 점검 대상 일반 파일을 수집한다.

    /etc/systemd와 /etc/xinetd.d의 디렉터리 자체는 chmod 600으로
    변경하면 접근이 불가능해질 수 있으므로 내부 일반 파일만 대상으로 한다.
    """
    targets = set()
    scan_issues = []

    for path in DIRECT_FILES:
        if not os.path.lexists(path):
            continue

        try:
            st = os.lstat(path)
        except (PermissionError, OSError) as error:
            scan_issues.append(f"{path}: 확인 실패({error})")
            continue

        if stat.S_ISLNK(st.st_mode):
            scan_issues.append(f"{path}: 심볼릭 링크")
        elif stat.S_ISREG(st.st_mode):
            targets.add(path)
        else:
            scan_issues.append(f"{path}: 일반 파일 아님")

    def walk_error(error):
        path = error.filename or "알 수 없는 경로"
        scan_issues.append(f"{path}: 디렉터리 탐색 실패({error})")

    for directory in CONFIG_DIRS:
        if not os.path.isdir(directory):
            continue

        for current_dir, dirnames, filenames in os.walk(
            directory,
            followlinks=False,
            onerror=walk_error,
        ):
            # 심볼릭 링크 디렉터리는 탐색하지 않는다.
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not os.path.islink(os.path.join(current_dir, dirname))
            ]

            for filename in filenames:
                path = os.path.join(current_dir, filename)

                if path in targets:
                    continue

                try:
                    st = os.lstat(path)
                except (PermissionError, OSError) as error:
                    scan_issues.append(f"{path}: 확인 실패({error})")
                    continue

                # systemd에는 정상적인 심볼릭 링크가 많이 존재한다.
                # 링크 대상까지 임의로 chmod하지 않도록 제외한다.
                if stat.S_ISLNK(st.st_mode):
                    continue

                if stat.S_ISREG(st.st_mode):
                    targets.add(path)

    return sorted(targets), scan_issues


def _get_issues():
    targets, scan_issues = _collect_targets()
    issues = list(scan_issues)

    for path in targets:
        try:
            st = os.lstat(path)
        except (PermissionError, OSError) as error:
            issues.append(f"{path}: 확인 실패({error})")
            continue

        mode = stat.S_IMODE(st.st_mode)

        if st.st_uid != 0:
            issues.append(f"{path}: 소유자 UID={st.st_uid}")

        # 0600에 포함되지 않는 그룹·기타 사용자 권한이나
        # 특수 권한 비트가 있으면 취약하다.
        if mode & ~TARGET_MODE:
            issues.append(f"{path}: 권한={mode:04o}")

    return targets, issues


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    targets, scan_issues = _collect_targets()
    errors.extend(scan_issues)

    for path in targets:
        try:
            st = os.lstat(path)

            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{path}: 심볼릭 링크이므로 조치하지 않음")
                continue

            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{path}: 일반 파일이 아니므로 조치하지 않음")
                continue

            os.chown(path, 0, -1)
            os.chmod(path, TARGET_MODE)

        except (PermissionError, OSError) as error:
            errors.append(f"{path}: 조치 실패({error})")

    return errors


def check():
    targets, issues = _get_issues()

    if not targets and not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "inetd, xinetd 또는 systemd 관련 점검 대상 설정 파일이 없습니다.",
        )

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"관련 설정 파일 {len(targets)}개의 소유자가 root이고 "
            f"권한이 0600 이하입니다.",
        )

    before = summarize(issues)
    fix_errors = _fix()
    checked_targets, remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"취약 설정 확인 후 조치 완료: {before}. "
            f"관련 설정 파일 {len(checked_targets)}개의 소유자를 root로 변경하고 "
            f"권한을 0600으로 설정했습니다."
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
