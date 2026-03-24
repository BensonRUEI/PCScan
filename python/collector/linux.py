# -*- coding: utf-8 -*-
"""
collector/linux.py
Linux 專用的資訊蒐集函式，透過 shell 指令與 /proc /etc 檔案取得各項資料。
"""
import os
import re

from .base import run_cmd


# ---------------------------------------------------------------------------
# 內部工具
# ---------------------------------------------------------------------------

def _read_file(path: str) -> str:
    """安全讀取檔案內容，失敗時回傳空字串。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _run(args: list[str]) -> str:
    return run_cmd(args, encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. 防毒資訊（ClamAV）
# ---------------------------------------------------------------------------

def get_defender_info() -> list[dict]:
    """
    嘗試以 ClamAV 取得版本資訊。
    若未安裝則回傳提示。
    """
    clam_ver = _run(["clamscan", "--version"])
    freshclam_ver = _run(["freshclam", "--version"])
    return [{
        "防毒軟體 / Antivirus":          "ClamAV" if clam_ver else "未安裝 / Not Installed",
        "版本 / Version":                clam_ver.splitlines()[0] if clam_ver else "N/A",
        "病毒碼版本 / Signature Version": freshclam_ver.splitlines()[0] if freshclam_ver else "N/A",
    }]


# ---------------------------------------------------------------------------
# 2. 已安裝更新 / 套件（dpkg / rpm）
# ---------------------------------------------------------------------------

def get_installed_updates() -> list[dict]:
    """
    嘗試以 dpkg（Debian/Ubuntu）或 rpm（RHEL/CentOS）取得近期更新的套件清單。
    """
    # Debian / Ubuntu：/var/log/dpkg.log 中 upgrade 記錄
    dpkgLog = _read_file("/var/log/dpkg.log")
    if dpkgLog:
        entries = []
        for line in dpkgLog.splitlines():
            if " upgrade " in line or " install " in line:
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "日期 / Date":        parts[0],
                        "時間 / Time":        parts[1],
                        "動作 / Action":      parts[2],
                        "套件 / Package":     parts[3],
                    })
        return entries or [{"日期 / Date": "無記錄 / No records", "時間 / Time": "",
                            "動作 / Action": "", "套件 / Package": ""}]

    # RHEL / CentOS：yum history list
    yumOut = _run(["yum", "history", "list"])
    if yumOut:
        lines = [l for l in yumOut.splitlines() if re.match(r"^\s*\d+", l)]
        entries = []
        for line in lines[:50]:   # 最多取 50 筆
            parts = line.split("|")
            if len(parts) >= 4:
                entries.append({
                    "ID":                 parts[0].strip(),
                    "指令 / Command":     parts[1].strip(),
                    "日期時間 / DateTime": parts[2].strip(),
                    "動作 / Action":      parts[3].strip(),
                })
        return entries or []

    return [{"資訊 / Info": "無法取得（需要 dpkg 或 yum）/ Cannot retrieve (requires dpkg or yum)"}]


# ---------------------------------------------------------------------------
# 3. 已安裝程式（dpkg / rpm -qa）
# ---------------------------------------------------------------------------

def get_installed_programs() -> list[dict]:
    """列出已安裝的套件，支援 dpkg 與 rpm。"""
    # dpkg
    dpkgOut = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"])
    if dpkgOut:
        data = []
        for line in dpkgOut.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                data.append({
                    "名稱 / Name":        parts[0],
                    "版本 / Version":     parts[1] if len(parts) > 1 else "",
                    "發行者 / Publisher":  parts[2] if len(parts) > 2 else "",
                })
        return data

    # rpm
    rpmOut = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"])
    if rpmOut:
        data = []
        for line in rpmOut.splitlines():
            parts = line.split("\t")
            data.append({
                "名稱 / Name":        parts[0],
                "版本 / Version":     parts[1] if len(parts) > 1 else "",
                "發行者 / Publisher":  parts[2] if len(parts) > 2 else "",
            })
        return data

    return [{"名稱 / Name": "無法取得 / N/A", "版本 / Version": "", "發行者 / Publisher": ""}]


# ---------------------------------------------------------------------------
# 4. 本機使用者帳號（/etc/passwd）
# ---------------------------------------------------------------------------

def get_local_user_accounts() -> list[dict]:
    """解析 /etc/passwd，回傳非系統帳號清單（UID >= 1000）。"""
    content = _read_file("/etc/passwd")
    data = []
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        uid = int(parts[2]) if parts[2].isdigit() else -1
        if uid < 1000 and parts[0] not in ("root",):
            continue
        # 確認帳號是否被鎖定（/etc/shadow 的密碼欄位以 ! 或 * 開頭）
        data.append({
            "帳號名稱 / Username": parts[0],
            "UID":                 parts[2],
            "群組 / Group (GID)":  parts[3],
            "描述 / Description":  parts[4],
            "Shell":               parts[6].strip(),
        })
    return data


# ---------------------------------------------------------------------------
# 5. 密碼原則（/etc/login.defs）
# ---------------------------------------------------------------------------

def get_password_policy() -> list[dict]:
    """解析 /etc/login.defs 的密碼相關設定。"""
    content = _read_file("/etc/login.defs")
    keywords = {
        "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE",
        "LOGIN_RETRIES", "LOGIN_TIMEOUT", "ENCRYPT_METHOD",
    }
    data = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in keywords:
            data.append({"設定 / Setting": parts[0], "值 / Value": parts[1].strip()})
    return data or [{"設定 / Setting": "N/A", "值 / Value": "無法取得 / Cannot retrieve"}]


# ---------------------------------------------------------------------------
# 6. 網路設定（ip addr / ip route）
# ---------------------------------------------------------------------------

def get_network_settings() -> list[dict]:
    """使用 `ip addr` 與 `ip route` 取得網路介面資訊。"""
    addrOut  = _run(["ip", "-j", "addr"])
    routeOut = _run(["ip", "-j", "route"])

    import json as _json

    # DNS servers（/etc/resolv.conf）
    resolv = _read_file("/etc/resolv.conf")
    dnsServers = [
        line.split()[1] for line in resolv.splitlines()
        if line.startswith("nameserver") and len(line.split()) == 2
    ]
    dnsStr = ", ".join(dnsServers) if dnsServers else "N/A"

    # 預設閘道
    gateways: dict[str, str] = {}
    try:
        routes = _json.loads(routeOut)
        for r in routes:
            if r.get("dst") == "default" and "gateway" in r:
                gateways[r.get("dev", "")] = r["gateway"]
    except (_json.JSONDecodeError, TypeError):
        pass

    try:
        ifaces = _json.loads(addrOut)
    except (_json.JSONDecodeError, TypeError):
        return [{"介面名稱 / Interface": "無法取得 / N/A", "IP 位址 / IP Address": "",
                 "子網遮罩 / Subnet Mask": "", "DNS 伺服器 / DNS Server": dnsStr,
                 "預設閘道 / Gateway": ""}]

    result = []
    for iface in ifaces:
        name = iface.get("ifname", "")
        ipv4 = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") == "inet"
        ]
        result.append({
            "介面名稱 / Interface":   name,
            "IP 位址 / IP Address":   ", ".join(ipv4) or "N/A",
            "子網遮罩 / Subnet Mask":  "",   # 已含在 CIDR 格式中
            "DNS 伺服器 / DNS Server": dnsStr,
            "預設閘道 / Gateway":      gateways.get(name, ""),
        })
    return result or [{"介面名稱 / Interface": "無 / None", "IP 位址 / IP Address": "",
                       "子網遮罩 / Subnet Mask": "", "DNS 伺服器 / DNS Server": dnsStr,
                       "預設閘道 / Gateway": ""}]


# ---------------------------------------------------------------------------
# 7. 作業系統資訊（Linux 版）
# ---------------------------------------------------------------------------

def get_os_info() -> list[dict]:
    """讀取 /etc/os-release 取得 Linux 發行版資訊。"""
    content = _read_file("/etc/os-release")
    keep = {"NAME", "VERSION", "ID", "VERSION_ID", "PRETTY_NAME", "HOME_URL"}
    data = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("=", 1)
        if len(parts) == 2 and parts[0] in keep:
            data.append({
                "設定 / Key":  parts[0],
                "值 / Value":  parts[1].strip('"'),
            })

    # 核心版本
    kernel = _run(["uname", "-r"]).strip()
    if kernel:
        data.append({"設定 / Key": "KERNEL", "值 / Value": kernel})

    return data or [{"設定 / Key": "N/A", "值 / Value": "無法取得 / Cannot retrieve"}]
