# -*- coding: utf-8 -*-
"""
collector/windows.py
Windows 專用的資訊蒐集函式，透過 PowerShell / winreg 取得各項資料。
"""
import json
import winreg

from .base import run_cmd


# ---------------------------------------------------------------------------
# 內部工具
# ---------------------------------------------------------------------------

def _run_powershell(command: str) -> str:
    """呼叫 PowerShell 並強制 UTF-8 輸出。"""
    utf8_prefix = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
    )
    return run_cmd(["powershell", "-Command", utf8_prefix + command], encoding="utf-8")


def _parse_ps_json(raw: str, fallback: list) -> list[dict]:
    """將 PowerShell ConvertTo-Json 輸出解析為 list[dict]。"""
    try:
        data = json.loads(raw)
        return [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        return fallback


def _get_reg_value(key, value_name: str):
    """讀取單一登錄值，失敗時回傳 None。"""
    try:
        return winreg.QueryValueEx(key, value_name)[0]
    except OSError:
        return None


# ---------------------------------------------------------------------------
# 1. Windows Defender
# ---------------------------------------------------------------------------

def get_defender_info() -> list[dict]:
    """取得 Defender 版本資訊，回傳 list[dict]。"""
    psCmd = r"""
Get-MpComputerStatus |
Select-Object AMProductVersion,AMServiceVersion,AntispywareSignatureVersion,AntivirusSignatureVersion |
ConvertTo-Json
"""
    _KEY_MAP = {
        "AMProductVersion":            "產品版本 / AMProductVersion",
        "AMServiceVersion":            "服務版本 / AMServiceVersion",
        "AntispywareSignatureVersion": "防間諜簽章版本 / AntispywareSignatureVersion",
        "AntivirusSignatureVersion":   "防毒簽章版本 / AntivirusSignatureVersion",
    }
    fallback = [{
        "產品版本 / AMProductVersion":            "無法取得 / N/A",
        "服務版本 / AMServiceVersion":            "",
        "防間諜簽章版本 / AntispywareSignatureVersion": "",
        "防毒簽章版本 / AntivirusSignatureVersion":   "",
    }]
    data = _parse_ps_json(_run_powershell(psCmd), fallback)
    return [{_KEY_MAP.get(k, k): v for k, v in item.items()} for item in data]


# ---------------------------------------------------------------------------
# 2. 已安裝更新
# ---------------------------------------------------------------------------

def get_installed_updates() -> list[dict]:
    """取得 Windows 已安裝 Hotfix 清單，回傳 list[dict]。"""
    psCmd = r"""
Get-WmiObject Win32_QuickFixEngineering |
Select-Object HotFixID,Description,InstalledOn |
ConvertTo-Json
"""
    _KEY_MAP = {
        "HotFixID":    "更新編號 / HotFixID",
        "Description": "描述 / Description",
        "InstalledOn": "安裝日期 / InstalledOn",
    }
    data = _parse_ps_json(_run_powershell(psCmd), [])
    return [{_KEY_MAP.get(k, k): v for k, v in item.items()} for item in data]


# ---------------------------------------------------------------------------
# 3. 已安裝程式（Registry）
# ---------------------------------------------------------------------------

def get_installed_programs() -> list[dict]:
    """從 HKLM / HKCU Uninstall 登錄路徑讀取已安裝程式，回傳 list[dict]。"""
    registryPaths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    data = []
    for hive in hives:
        for path in registryPaths:
            try:
                with winreg.OpenKey(hive, path) as regKey:
                    for i in range(winreg.QueryInfoKey(regKey)[0]):
                        try:
                            with winreg.OpenKey(regKey, winreg.EnumKey(regKey, i)) as subkey:
                                name = _get_reg_value(subkey, "DisplayName")
                                if not name:
                                    continue
                                data.append({
                                    "名稱 / Name":        name,
                                    "版本 / Version":     _get_reg_value(subkey, "DisplayVersion") or "",
                                    "發行者 / Publisher":  _get_reg_value(subkey, "Publisher") or "",
                                })
                        except OSError:
                            pass
            except OSError:
                pass
    return data


# ---------------------------------------------------------------------------
# 4. 本機使用者帳號
# ---------------------------------------------------------------------------

def get_local_user_accounts() -> list[dict]:
    """取得本機帳號清單，回傳 list[dict]。"""
    ps_cmd = r"""
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" |
Select-Object Name,Domain,Description,Disabled |
ConvertTo-Json
"""
    data = _parse_ps_json(_run_powershell(ps_cmd), [])
    return [
        {
            "帳號名稱 / Username": item.get("Name", ""),
            "網域 / Domain":       item.get("Domain", ""),
            "描述 / Description":  item.get("Description", ""),
            "是否啟用 / Enabled":   "停用 / Disabled" if item.get("Disabled", False) else "啟用 / Enabled",
        }
        for item in data
    ]


# ---------------------------------------------------------------------------
# 5. 密碼原則
# ---------------------------------------------------------------------------

def get_password_policy() -> list[dict]:
    """執行 net accounts，解析輸出為 list[dict]。"""
    raw = _run_powershell("net accounts")
    data = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            data.append({"設定 / Setting": parts[0].strip(), "值 / Value": parts[1].strip()})
    return data


# ---------------------------------------------------------------------------
# 6. 網路設定
# ---------------------------------------------------------------------------

def get_network_settings() -> list[dict]:
    """取得 IPEnabled 網路介面資訊，回傳 list[dict]。"""
    psCmd = r"""
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
Select-Object Description, IPAddress, IPSubnet, DNSServerSearchOrder |
ConvertTo-Json
"""
    data = _parse_ps_json(_run_powershell(psCmd), [])

    def joinList(v):
        return ", ".join(v) if isinstance(v, list) else (str(v) if v else "")

    result = []
    for item in data:
        result.append({
            "介面名稱 / Interface":    item.get("Description", ""),
            "IP 位址 / IP Address":    joinList(item.get("IPAddress", [])),
            "子網遮罩 / Subnet Mask":   joinList(item.get("IPSubnet", [])),
            "DNS 伺服器 / DNS Server":  joinList(item.get("DNSServerSearchOrder") or []),
        })
    return result or [{"介面名稱 / Interface": "無 / None", "IP 位址 / IP Address": "",
                       "子網遮罩 / Subnet Mask": "", "DNS 伺服器 / DNS Server": "無法取得 / N/A"}]


# ---------------------------------------------------------------------------
# 7. 作業系統資訊（Windows 版）
# ---------------------------------------------------------------------------

def get_os_info() -> list[dict]:
    """取得 Windows 版本號、Build 等詳細資訊。"""
    psCmd = r"""
Get-WmiObject Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime |
ConvertTo-Json
"""
    _KEY_MAP = {
        "Caption":        "作業系統名稱 / OS Name",
        "Version":        "版本號 / Version",
        "BuildNumber":    "建置編號 / Build Number",
        "OSArchitecture": "架構 / Architecture",
        "LastBootUpTime": "最後開機時間 / Last Boot",
    }
    data = _parse_ps_json(_run_powershell(psCmd), [])
    return [{_KEY_MAP.get(k, k): v for k, v in item.items()} for item in data]
