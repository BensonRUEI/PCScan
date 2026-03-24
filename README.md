# PCScan — 系統資訊蒐集工具

自動蒐集本機系統資訊，輸出 **HTML 報告** 與 **XLSX / CSV 表格**，並打包成 ZIP。  
支援 Windows 與 Linux，提供 **Python**、**PowerShell**、**Bash** 三種語言版本。

---

## 資料夾結構

```
PCScan/
├── python/                  # Python 版本（跨平台）
│   ├── getPcInfo.py         # Entry point: generates HTML + XLSX/CSV + ZIP
│   ├── pc_collector.py      # 平台分發中介層
│   ├── requirements.txt
│   └── collector/
│       ├── base.py          # 跨平台共用工具
│       ├── windows.py       # Windows 資料蒐集器
│       └── linux.py         # Linux 資料蒐集器
├── powershell/
│   └── getPcInfo.ps1        # PowerShell 版本（Windows PS 5.1+ / Linux PS Core 7+）
└── shell/
    └── getPcInfo.sh         # Bash Shell Script 版本（Linux）
```

---

## 蒐集資訊項目

| 項目 | Windows | Linux |
|------|:-------:|:-----:|
| 系統基本資訊（主機名稱、所有區網 IP、OS、架構） | ✅ | ✅ |
| 作業系統詳細資訊 | ✅ | ✅ |
| 防毒資訊（Windows Defender / ClamAV） | ✅ | ✅ |
| 已安裝更新 | ✅ | ✅ |
| 已安裝程式 | ✅ | ✅ |
| 本機使用者帳號 | ✅ | ✅ |
| 密碼原則 | ✅ | ✅ |
| 網路設定（介面、IP、DNS、閘道） | ✅ | ✅ |

---

## 輸出格式

每次執行於當前目錄產生 `{主機名稱}_{IP}/` 資料夾與 ZIP 壓縮檔：

```
DESKTOP-XXXX_192.168.1.100/
├── DESKTOP-XXXX_192.168.1.100.html          # HTML 報告（Bootstrap 5，可按欄位排序）
├── DESKTOP-XXXX_192.168.1.100.xlsx          # Excel 工作表（Python 版，需 xlsxwriter）
├── DESKTOP-XXXX_192.168.1.100_SystemInfo.csv
├── DESKTOP-XXXX_192.168.1.100_OSDetails.csv
├── DESKTOP-XXXX_192.168.1.100_Antivirus.csv
├── DESKTOP-XXXX_192.168.1.100_Updates.csv
├── DESKTOP-XXXX_192.168.1.100_Programs.csv
├── DESKTOP-XXXX_192.168.1.100_UserAccounts.csv
├── DESKTOP-XXXX_192.168.1.100_PasswordPolicy.csv
└── DESKTOP-XXXX_192.168.1.100_NetworkSettings.csv
DESKTOP-XXXX_192.168.1.100.zip              # 以上所有檔案的壓縮包
```

> 所有輸出檔案皆使用 **UTF-8 BOM** 編碼，在 Windows 用 Excel 或瀏覽器直接開啟中文不亂碼。

---

## 使用方式

### Python 版本

**需求**
- Python 3.9+
- （選用）`xlsxwriter`：有安裝時輸出 `.xlsx`，否則自動改輸出多個 `.csv`

```bash
cd python

# Install optional dependency
pip install -r requirements.txt

# Generate HTML + XLSX/CSV + ZIP
python getPcInfo.py
```

### PowerShell 版本

支援 **Windows PowerShell 5.1+** 與 **PowerShell Core 7+（含 Linux）**。

```powershell
cd powershell

# Windows
powershell -ExecutionPolicy Bypass -File .\getPcInfo.ps1

# 指定輸出目錄（可選）
powershell -ExecutionPolicy Bypass -File .\getPcInfo.ps1 -OutputDir "C:\Reports"
```

### Bash Shell Script 版本

支援 Debian/Ubuntu（dpkg/apt）與 RHEL/CentOS/Fedora（rpm/yum/dnf）。

```bash
cd shell

chmod +x getPcInfo.sh
./getPcInfo.sh

# 指定輸出目錄（可選）
./getPcInfo.sh -o /tmp/reports
```

---

## 注意事項

- **執行權限**：部分資料（如 Windows Defender 狀態、本機使用者）需以**系統管理員**身份執行才能完整蒐集。
- **PowerShell 執行原則**：Windows 預設限制腳本執行，請使用 `-ExecutionPolicy Bypass` 或在執行前調整原則。
- **Linux 套件工具**：Bash 與 PowerShell Linux 版需系統已安裝 `ip`（iproute2）；更新紀錄蒐集需要 `dpkg` 或 `yum`。
