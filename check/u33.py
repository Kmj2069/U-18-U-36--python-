#U-33: 숨겨진 파일 및 디렉토리 검색 및 제거

import os
import re
import shutil
import stat

from .common import GOOD, VULN, result, summarize


CODE = "U-33"
TITLE = "숨겨진 파일 및 디렉토리 검색 및 제거"

QUARANTINE_DIR = "/root/u33_quarantine"

SCAN_ROOTS = [
    "/root",
    "/home",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/etc",
    "/usr/local",
    "/opt",
]

TEMP_PATHS = {
    "/tmp",
    "/var/tmp",
    "/dev/shm",
}

# 취약화 스크립트에서 생성한 경로를 확인했다면 여기에 추가한다.
#
# 예:
# CONFIRMED_SUSPICIOUS_PATHS = {
#     "/tmp/.backdoor",
#     "/home/test/.hidden_shell",
# }
CONFIRMED_SUSPICIOUS_PATHS = set()


SUSPICIOUS_NAME_PATTERN = re.compile(
    r"""
    ^\.
    .*(
        backdoor
        |rootkit
        |rootshell
        |root_shell
        |hidden_shell
        |malware
        |exploit
        |hacktool
        |reverse_shell
        |bind_shell
    ).*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_hidden_name(name):
    return (
        name.startswith(".")
        and name not in {".", ".."}
    )


def _has_deceptive_name(name):
    """
    파일 목록에서 알아보기 어렵게 만든 이름을 탐지한다.
    """
    if name == "...":
        return True

    if name.startswith(". ") or name.endswith(" "):
        return True

    return any(ord(character) < 32 for character in name)


def _inside_temp_path(path):
    normalized = os.path.realpath(path)

    for temp_path in TEMP_PATHS:
        try:
            if os.path.commonpath([normalized, temp_path]) == temp_path:
                return True
        except ValueError:
            continue

    return False


def _looks_executable(path, file_stat):
    """
    실행 권한, 스크립트 shebang, ELF 헤더를 확인한다.
    """
    if file_stat.st_mode & 0o111:
        return True

    try:
        with open(path, "rb") as file:
            header = file.read(4)

        return (
            header.startswith(b"#!")
            or header.startswith(b"\x7fELF")
        )

    except (PermissionError, OSError):
        return False


def _high_risk_hidden_path(path, file_stat):
    name = os.path.basename(path)

    if not _is_hidden_name(name):
        return False

    if SUSPICIOUS_NAME_PATTERN.search(name):
        return True

    if _has_deceptive_name(name):
        return True

    if stat.S_ISREG(file_stat.st_mode):
        if file_stat.st_mode & (stat.S_ISUID | stat.S_ISGID):
            return True

        if (
            _inside_temp_path(path)
            and _looks_executable(path, file_stat)
        ):
            return True

    return False


def _scan_root(scan_root):
    findings = []
    errors = []

    if not os.path.isdir(scan_root):
        return findings, errors

    def walk_error(error):
        path = error.filename or scan_root
        errors.append(f"{path}: 탐색 실패({error})")

    for current_dir, dirnames, filenames in os.walk(
        scan_root,
        topdown=True,
        followlinks=False,
        onerror=walk_error,
    ):
        filtered_directories = []

        for dirname in dirnames:
            path = os.path.join(current_dir, dirname)

            # 격리 디렉터리를 다시 탐지하지 않는다.
            if os.path.realpath(path) == os.path.realpath(QUARANTINE_DIR):
                continue

            try:
                file_stat = os.lstat(path)
            except (PermissionError, OSError) as error:
                errors.append(f"{path}: 확인 실패({error})")
                continue

            if stat.S_ISLNK(file_stat.st_mode):
                if _high_risk_hidden_path(path, file_stat):
                    findings.append(path)
                continue

            if _high_risk_hidden_path(path, file_stat):
                findings.append(path)

                # 의심스러운 디렉터리 전체를 격리할 예정이므로
                # 내부는 별도로 탐색하지 않는다.
                continue

            filtered_directories.append(dirname)

        dirnames[:] = filtered_directories

        for filename in filenames:
            path = os.path.join(current_dir, filename)

            try:
                file_stat = os.lstat(path)
            except (PermissionError, OSError) as error:
                errors.append(f"{path}: 확인 실패({error})")
                continue

            if _high_risk_hidden_path(path, file_stat):
                findings.append(path)

    return findings, errors


def _scan_suspicious_paths():
    findings = []
    errors = []

    for path in CONFIRMED_SUSPICIOUS_PATHS:
        if os.path.lexists(path):
            findings.append(path)

    for scan_root in SCAN_ROOTS:
        root_findings, root_errors = _scan_root(scan_root)
        findings.extend(root_findings)
        errors.extend(root_errors)

    # 중복 제거
    findings = sorted(
        set(findings),
        key=lambda path: (path.count(os.sep), path),
    )

    # 상위 의심 디렉터리가 이미 포함되었다면 내부 항목은 제거한다.
    filtered = []

    for path in findings:
        inside_selected_directory = False

        for selected in filtered:
            if not os.path.isdir(selected):
                continue

            try:
                if os.path.commonpath([path, selected]) == selected:
                    inside_selected_directory = True
                    break
            except ValueError:
                continue

        if not inside_selected_directory:
            filtered.append(path)

    return filtered, errors


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
        os.makedirs(
            QUARANTINE_DIR,
            mode=0o700,
            exist_ok=True,
        )
        os.chmod(QUARANTINE_DIR, 0o700)

    except (PermissionError, OSError) as error:
        return [
            f"{QUARANTINE_DIR}: 격리 디렉터리 생성 실패({error})"
        ]

    for path in paths:
        if not os.path.lexists(path):
            continue

        try:
            relative_path = path.lstrip(os.sep)
            destination = os.path.join(
                QUARANTINE_DIR,
                relative_path,
            )

            destination_parent = os.path.dirname(destination)

            os.makedirs(
                destination_parent,
                mode=0o700,
                exist_ok=True,
            )

            destination = _unique_destination(destination)

            shutil.move(path, destination)

        except (PermissionError, OSError, shutil.Error) as error:
            errors.append(f"{path}: 격리 실패({error})")

    return errors


def _format_issues(findings, scan_errors):
    issues = [
        f"{path}: 의심스러운 숨김 항목"
        for path in findings
    ]

    issues.extend(scan_errors)
    return issues


def check():
    findings, scan_errors = _scan_suspicious_paths()
    issues = _format_issues(findings, scan_errors)

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "고위험 조건에 해당하는 숨김 파일 및 디렉터리가 없습니다.",
        )

    before = summarize(issues)
    fix_errors = _quarantine(findings)

    remaining_findings, remaining_scan_errors = _scan_suspicious_paths()
    remaining_issues = _format_issues(
        remaining_findings,
        remaining_scan_errors,
    )

    if not remaining_issues:
        detail = (
            f"의심스러운 숨김 항목 확인 후 조치 완료: {before}. "
            f"총 {len(findings)}개 항목을 "
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
