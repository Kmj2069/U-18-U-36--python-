#U-28: 접속 IP 및 포트 제한

import os
import re
import shutil
import subprocess

from .common import GOOD, VULN, result, summarize


CODE = "U-28"
TITLE = "접속 IP 및 포트 제한"


# 반드시 실습 환경에 맞게 수정한다.
#
# 형식:
#     ("허용 IP 또는 네트워크", 포트 번호, "tcp 또는 udp")
#
# VirtualBox Host-Only 네트워크 예시:
# ALLOWED_RULES = [
#     ("192.168.56.0/24", 22, "tcp"),
# ]
ALLOWED_RULES = []


# 다음 포트에서 전체 IP 허용 규칙을 발견하면 취약으로 판단한다.
MANAGED_PORTS = {
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    512,  # rexec
    513,  # rlogin
    514,  # rsh
}


def _run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _current_ssh_rule():
    """
    SSH로 이 코드를 실행 중이라면 현재 접속자의 IP와
    서버 측 SSH 포트를 자동으로 보존한다.

    SSH_CONNECTION 형식:
        client_ip client_port server_ip server_port
    """
    value = os.environ.get("SSH_CONNECTION", "").strip()
    tokens = value.split()

    if len(tokens) != 4:
        return None

    client_ip = tokens[0]

    try:
        server_port = int(tokens[3])
    except ValueError:
        return None

    return client_ip, server_port, "tcp"


def _desired_rules():
    rules = list(ALLOWED_RULES)
    ssh_rule = _current_ssh_rule()

    if ssh_rule is not None and ssh_rule not in rules:
        rules.append(ssh_rule)

    return rules


def _ufw_verbose_status():
    completed = _run(["ufw", "status", "verbose"])

    if completed is None:
        return None, "ufw 명령 실행 실패"

    output = f"{completed.stdout}\n{completed.stderr}".strip()

    if completed.returncode != 0:
        return output, f"ufw 상태 확인 실패: {output}"

    return output, None


def _ufw_numbered_status():
    completed = _run(["ufw", "status", "numbered"])

    if completed is None:
        return None, "ufw 규칙 확인 실패"

    output = f"{completed.stdout}\n{completed.stderr}".strip()

    if completed.returncode != 0:
        return output, f"ufw 규칙 확인 실패: {output}"

    return output, None


def _broad_allow_rules(numbered_status):
    """
    관리 포트에 대해 Anywhere에서 접근 가능한 ALLOW IN 규칙을 찾는다.

    반환:
        [(규칙 번호, 원문), ...]
    """
    broad_rules = []

    for line in numbered_status.splitlines():
        match = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())

        if not match:
            continue

        rule_number = int(match.group(1))
        rule_text = match.group(2)

        if "ALLOW IN" not in rule_text:
            continue

        if not re.search(r"\bAnywhere\b|0\.0\.0\.0/0|::/0", rule_text):
            continue

        if "OpenSSH" in rule_text:
            broad_rules.append((rule_number, rule_text))
            continue

        port_match = re.match(r"^(\d+)(?:/(tcp|udp))?", rule_text)

        if not port_match:
            continue

        port = int(port_match.group(1))

        if port in MANAGED_PORTS:
            broad_rules.append((rule_number, rule_text))

    return broad_rules


def _rule_present(numbered_status, source, port, protocol):
    target = f"{port}/{protocol}"

    for line in numbered_status.splitlines():
        if "ALLOW IN" not in line:
            continue

        if target in line and source in line:
            return True

    return False


def _get_issues():
    issues = []

    if shutil.which("ufw") is None:
        return ["ufw가 설치되어 있지 않음"]

    verbose_status, verbose_error = _ufw_verbose_status()

    if verbose_error:
        return [verbose_error]

    if not re.search(r"Status:\s+active\b", verbose_status, re.I):
        issues.append("UFW 비활성화")

    if not re.search(
        r"Default:\s+deny\s+\(incoming\)",
        verbose_status,
        re.I,
    ):
        issues.append("기본 인바운드 정책이 deny가 아님")

    numbered_status, numbered_error = _ufw_numbered_status()

    if numbered_error:
        issues.append(numbered_error)
        return issues

    for _, rule_text in _broad_allow_rules(numbered_status):
        issues.append(f"전체 IP 허용 규칙: {rule_text}")

    for source, port, protocol in _desired_rules():
        if not _rule_present(
            numbered_status,
            source,
            port,
            protocol,
        ):
            issues.append(
                f"허용 규칙 없음: {source} -> {port}/{protocol}"
            )

    return issues


def _fix():
    errors = []

    if os.geteuid() != 0:
        return ["root 권한이 없어 자동 조치를 수행할 수 없음"]

    if shutil.which("ufw") is None:
        return ["ufw가 설치되어 있지 않아 자동 조치할 수 없음"]

    desired_rules = _desired_rules()

    if not desired_rules:
        return [
            "허용 IP가 설정되지 않았습니다. "
            "ALLOWED_RULES에 허용할 IP와 포트를 입력해야 합니다."
        ]

    numbered_status, numbered_error = _ufw_numbered_status()

    if numbered_error:
        return [numbered_error]

    broad_rules = _broad_allow_rules(numbered_status)

    # 번호가 뒤에서부터 삭제되어야 앞쪽 규칙 번호가 바뀌지 않는다.
    for rule_number, rule_text in sorted(
        broad_rules,
        reverse=True,
    ):
        completed = _run(
            ["ufw", "--force", "delete", str(rule_number)]
        )

        if completed is None or completed.returncode != 0:
            errors.append(f"규칙 삭제 실패: {rule_text}")

    commands = [
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "allow", "outgoing"],
    ]

    for source, port, protocol in desired_rules:
        commands.append(
            [
                "ufw",
                "allow",
                "from",
                source,
                "to",
                "any",
                "port",
                str(port),
                "proto",
                protocol,
            ]
        )

    commands.append(["ufw", "--force", "enable"])

    for command in commands:
        completed = _run(command)

        if completed is None or completed.returncode != 0:
            command_text = " ".join(command)
            message = ""

            if completed is not None:
                message = (
                    completed.stderr.strip()
                    or completed.stdout.strip()
                )

            errors.append(
                f"{command_text}: 실행 실패"
                + (f"({message})" if message else "")
            )

    return errors


def check():
    issues = _get_issues()

    if not issues:
        return result(
            CODE,
            TITLE,
            GOOD,
            "UFW가 활성화되어 있고 허용 IP 및 포트 제한이 적용되어 있습니다.",
        )

    before = summarize(issues)
    fix_errors = _fix()

    remaining_issues = _get_issues()

    if not remaining_issues:
        detail = (
            f"접근 제한 미설정 확인 후 조치 완료: {before}. "
            f"기본 인바운드 정책을 deny로 설정하고 "
            f"허용 IP·포트 규칙을 적용했습니다."
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
