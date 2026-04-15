# PCScan — 系統資訊蒐集與 CVE 風險掃描工具

自動蒐集本機系統資訊並進行 **CVE 離線風險掃描**，輸出 **HTML 報告** 與 **CSV / XLSX 表格**，並打包成 ZIP。  
支援 Windows 與 Linux，提供 **Python** 與 **PowerShell** 兩種語言版本。

---

## 資料夾結構

```
PCScan/
├── .gitignore
├── README.md
├── python/                      # Python 版本（跨平台）
│   ├── getPcInfo.py             # 主程式：蒐集系統資訊，輸出 HTML + XLSX/CSV + ZIP
│   ├── scanCve.py               # 獨立 CVE 掃描工具，輸出 CVE CSV + HTML
│   ├── requirements.txt
│   ├── collector/
│   │   ├── base.py              # 跨平台共用工具
│   │   ├── windows.py           # Windows 資料蒐集器
│   │   └── linux.py             # Linux 資料蒐集器
│   └── cveScanner/              # CVE 離線風險掃描套件
│       ├── scanner.py           # NVD 查詢核心
│       ├── nvdIndexer.py        # CLI：建立 / 更新 SQLite 索引
│       ├── downloader.py        # NVD ZIP 下載工具
│       ├── repology.py          # Repology 最新版本查詢
│       └── nvd_cache.db         # ⚙ SQLite 索引（執行後自動產生）
└── powershell/                  # PowerShell 版本（Windows PS 5.1+ / PS Core 7+）
    ├── getPcInfo.ps1            # 主程式：蒐集系統資訊 + CVE 掃描，輸出 HTML + CSV + ZIP
    ├── NvdLib.ps1               # 共用函式庫（SQLite、NVD 下載/索引、CVE 比對、報告輸出）
    └── lib/                     # ⚙ SQLite 組件（首次執行時自動下載）
        ├── System.Data.SQLite.dll
        └── SQLite.Interop.dll
```

> ⚙ 標記的檔案為自動產生，不需納入版本控制（已列入 `.gitignore`）。

---

## 蒐集資訊項目

| 項目 | Python | PowerShell |
|------|:------:|:----------:|
| 系統基本資訊（主機名稱、區網 IP、OS、架構） | ✅ | ✅ |
| 作業系統詳細資訊 | ✅ | ✅ |
| 防毒資訊（Windows Defender / ClamAV） | ✅ | ✅ |
| 已安裝更新（最新 10 筆） | ✅ | ✅ |
| 已安裝程式 | ✅ | ✅ |
| 本機使用者帳號 | ✅ | ✅ |
| 密碼原則 | ✅ | ✅ |
| 網路設定（介面、IP、DNS、閘道） | ✅ | ✅ |
| CVE 離線風險掃描（NVD 資料庫） | ✅ | ✅ |
| 最新版本查詢（Repology） | ✅ | ✅ |
| CPE 2.3 清單（VANS 合規） | ✅ | ✅ |

---

## 輸出格式

### PowerShell 版本（`getPcInfo.ps1`）

執行後在 `powershell/output/{主機名稱}_{IP}/` 產生：

```
powershell/output/
├── DESKTOP-XXXX_192.168.1.100.zip                         # 所有檔案的壓縮包
└── DESKTOP-XXXX_192.168.1.100/
    ├── DESKTOP-XXXX_192.168.1.100.html                   # 系統資訊 HTML 報告（含 CVE 摘要）
    ├── DESKTOP-XXXX_192.168.1.100_SystemInfo.csv
    ├── DESKTOP-XXXX_192.168.1.100_OSDetails.csv
    ├── DESKTOP-XXXX_192.168.1.100_Antivirus.csv
    ├── DESKTOP-XXXX_192.168.1.100_Updates.csv
    ├── DESKTOP-XXXX_192.168.1.100_Programs.csv
    ├── DESKTOP-XXXX_192.168.1.100_UserAccounts.csv
    ├── DESKTOP-XXXX_192.168.1.100_PasswordPolicy.csv
    ├── DESKTOP-XXXX_192.168.1.100_NetworkSettings.csv
    ├── DESKTOP-XXXX_192.168.1.100_CVERisk.csv            # CVE 風險清單
    ├── DESKTOP-XXXX_192.168.1.100_CVE.html               # 獨立 CVE 風險報告（可篩選/排序）
    └── DESKTOP-XXXX_192.168.1.100_CPE23.txt              # CPE 2.3 清單（符合 VANS 需求）
```

### Python 版本（`getPcInfo.py`）

執行後在 `python/output/{主機名稱}_{IP}/` 產生：

```
python/output/
├── DESKTOP-XXXX_192.168.1.100.zip                         # 所有檔案的壓縮包
└── DESKTOP-XXXX_192.168.1.100/
    ├── DESKTOP-XXXX_192.168.1.100.html                   # 系統資訊 HTML 報告（含 CVE 摘要）
    ├── DESKTOP-XXXX_192.168.1.100.xlsx                   # 所有資料（需安裝 xlsxwriter）
    │   ── 或各分類 CSV                                   # 未安裝 xlsxwriter 時改輸出 CSV
    └── DESKTOP-XXXX_192.168.1.100_CPE23.txt              # CPE 2.3 清單（符合 VANS 需求）
```

> 所有輸出檔案皆使用 **UTF-8 / UTF-8 BOM** 編碼，在 Windows 以 Excel 或瀏覽器開啟中文不亂碼。

---

## 使用方式

### PowerShell 版本

**需求**：Windows PowerShell 5.1+ 或 PowerShell Core 7+  
首次執行時會**自動下載** SQLite 組件（`lib/`）與當年度 NVD CVE 資料庫。

```powershell
cd powershell

# 標準執行
powershell -ExecutionPolicy Bypass -File .\getPcInfo.ps1

# 指定輸出目錄（可選）
powershell -ExecutionPolicy Bypass -File .\getPcInfo.ps1 -OutputDir "C:\Reports"
```

執行流程：
1. 蒐集系統各項資訊 + 查詢 Repology 最新版本
2. 自動下載 / 更新當年度 NVD 資料庫
3. 對已安裝程式執行 CVE 比對（僅保留 Windows 平台相關 CVE）
4. 輸出系統資訊 HTML、各分類 CSV、獨立 CVE HTML、CPE 2.3 清單，並打包 ZIP

---

### Python 版本

**需求**：Python 3.9+

```bash
cd python

# 安裝依賴
pip install -r requirements.txt

# 蒐集系統資訊（主程式）
python getPcInfo.py

# 獨立 CVE 掃描工具
python scanCve.py               # 互動式選單，輸出 CVE CSV + HTML
python -m cveScanner            # 同上

# 手動建立 / 更新 NVD 索引
python -m cveScanner.nvdIndexer --download --years 2024 2025
```

---

## CVE 風險掃描說明

- **資料來源**：[NIST NVD](https://nvd.nist.gov/) CVE JSON Feed（離線 SQLite，不需要 API Key）
- **掃描邏輯**：將已安裝程式名稱正規化後比對 CPE `product_norm`，並過濾 `target_sw` 僅保留 Windows 相關 CVE
- **版本比對**：支援精確版本（`= x.y.z`）與範圍版本（`>= x.y.z 且 < a.b.c`）
- **CVSS 分數**：優先使用 CVSSv3.1，次選 v3.0，最後回退至 v2

## CPE 2.3 清單說明（VANS）

每筆已安裝程式輸出格式：

```
cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
```

範例：
```
cpe:2.3:a:mozilla:firefox:125.0:*:*:*:*:*:*:*
cpe:2.3:a:google:chrome:124.0.6367.82:*:*:*:*:*:*:*
cpe:2.3:a:microsoft:visual_studio_code:1.89.0:*:*:*:*:*:*:*
```

---

## 注意事項

- **執行權限**：部分資料（Windows Defender 狀態、本機使用者）需以**系統管理員**身份執行才能完整蒐集。
- **PowerShell 執行原則**：Windows 預設限制腳本執行，請使用 `-ExecutionPolicy Bypass` 或事先調整原則。
- **NVD 資料庫大小**：僅下載當年度約 4–10 MB；完整歷史（2002 至今）約 0.5–1 GB。
- **Linux 套件工具**：PowerShell Linux 版需系統已安裝 `ip`（iproute2）；更新紀錄蒐集需要 `dpkg` 或 `yum`。
