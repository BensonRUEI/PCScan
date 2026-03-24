# -*- coding: utf-8 -*-
"""
collector/base.py
跨平台（Windows / Linux）共用的工具函式與資料結構定義。
"""
import platform
import socket
import subprocess


# ---------------------------------------------------------------------------
# 執行 Shell 指令
# ---------------------------------------------------------------------------

def run_cmd(args: list[str], encoding: str = "utf-8") -> str:
    """執行外部指令，回傳 stdout 字串；失敗時回傳空字串。"""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, encoding=encoding, errors="replace"
        )
        return proc.stdout or ""
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------
# 取得基本網路資訊
# ---------------------------------------------------------------------------

def get_local_ip_address() -> str:
    """只抓第一個 IPv4（排除 127.x.x.x），用於資料夾/ZIP 命名。"""
    hostName = socket.gethostname()
    for addrInfo in socket.getaddrinfo(hostName, None):
        ip = addrInfo[4][0]
        if ":" not in ip and not ip.startswith("127."):
            return ip
    return "Unknown"


def get_all_local_ip_addresses() -> str:
    """回傳所有非 127.x / 169.254.x IPv4，以逗號分隔；用於系統資訊顯示。"""
    hostName = socket.gethostname()
    ips = []
    seen = set()
    for addrInfo in socket.getaddrinfo(hostName, None):
        ip = addrInfo[4][0]
        if (
            ":" not in ip
            and not ip.startswith("127.")
            and not ip.startswith("169.254.")
            and ip not in seen
        ):
            ips.append(ip)
            seen.add(ip)
    return ", ".join(ips) if ips else "未知 / Unknown"


# ---------------------------------------------------------------------------
# 系統基本資訊（共用）
# ---------------------------------------------------------------------------

def get_system_info() -> list[dict]:
    """回傳主機名稱、IP、OS 版本，Windows / Linux 通用。"""
    return [
        {"項目 / Item": "主機名稱 / Hostname",  "內容 / Content": platform.node()},
        {"項目 / Item": "區網 IP / Local IP",    "內容 / Content": get_all_local_ip_addresses()},
        {"項目 / Item": "作業系統 / OS",          "內容 / Content": platform.platform()},
        {"項目 / Item": "架構 / Architecture",    "內容 / Content": platform.machine()},
        {"項目 / Item": "Python 版本 / Python",   "內容 / Content": platform.python_version()},
    ]
