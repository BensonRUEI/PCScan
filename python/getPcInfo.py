# -*- coding: utf-8 -*-
import csv
import html as html_mod
import os
import platform
import sys
import zipfile

# 確保在任何語系的終端（含 Windows CP1252/English）都不因中文輸出而崩潰
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    import xlsxwriter
    HAS_XLSXWRITER = True
except ImportError:
    HAS_XLSXWRITER = False

from collector import (
    get_local_ip_address,
    get_system_info,
    get_defender_info,
    get_installed_updates,
    get_installed_programs,
    get_local_user_accounts,
    get_password_policy,
    get_network_settings,
)

def _normalize(value) -> str:
    if isinstance(value, dict):
        return value.get("DateTime", str(value))
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else ""

def exportXlsx(sheets, filename):
    wb = xlsxwriter.Workbook(filename)
    headerFmt = wb.add_format({"bold": True, "bg_color": "#D9E1F2", "border": 1})
    cellFmt   = wb.add_format({"border": 1})
    for sheetName, data, fieldOrder in sheets:
        ws = wb.add_worksheet(sheetName)
        for col, header in enumerate(fieldOrder):
            ws.write(0, col, header, headerFmt)
        if not data:
            ws.write(1, 0, "無資料", cellFmt)
            continue
        for rowIdx, item in enumerate(data, start=1):
            for col, field in enumerate(fieldOrder):
                ws.write(rowIdx, col, _normalize(item.get(field, "")), cellFmt)
    wb.close()

def exportCsv(sheets, baseName, outDir):
    filenames = []
    for sheetName, data, fieldOrder in sheets:
        safeName = sheetName.replace("/", "_").replace("\\", "_")
        fname = os.path.join(outDir, f"{baseName}_{safeName}.csv")
        with open(fname, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(fieldOrder)
            if not data:
                writer.writerow(["無資料"])
            else:
                for item in data:
                    writer.writerow([_normalize(item.get(field, "")) for field in fieldOrder])
        filenames.append(fname)
    return filenames

def main():
    computerName = platform.node()  # 電腦名稱
    localIp = get_local_ip_address()  # 第一個區網 IPv4
    baseName = f"{computerName}_{localIp}"

    # 集中存放到腳本同層的 output/ 子目錄
    scriptDir   = os.path.dirname(os.path.abspath(__file__))
    outputRoot  = os.path.join(scriptDir, "output")
    os.makedirs(outputRoot, exist_ok=True)

    outDir   = os.path.join(outputRoot, baseName)
    zipPath  = os.path.join(outputRoot, f"{baseName}.zip")

    # 建立輸出資料夾
    os.makedirs(outDir, exist_ok=True)

    # 各項資料
    systemInfo      = get_system_info()
    defenderInfo    = get_defender_info()
    updates         = get_installed_updates()
    programs        = get_installed_programs()
    userAccounts    = get_local_user_accounts()
    passwordPolicy  = get_password_policy()
    networkSettings = get_network_settings()

    # 產生 HTML 內容
    htmlContent = generateHtml(
        computerName, localIp,
        systemInfo, defenderInfo, updates,
        programs, userAccounts, passwordPolicy, networkSettings
    )

    # 寫入 HTML 檔案
    filename = os.path.join(outDir, f"{baseName}.html")
    if os.path.exists(filename):
        response = input(f"檔案 {filename} 已存在，是否覆蓋? (Y/N): ")
        if response.strip().lower() != 'y':
            print("取消覆蓋，程式終止。")
            return

    with open(filename, "w", encoding="utf-8-sig") as f:
        f.write(htmlContent)
    print(f"系統資訊已匯出至 {filename}")

    # 也匯出 XLSX / CSV（重用已收集資料，不重複呼叫）
    sheets = [
        ("系統資訊",         systemInfo,      ["項目 / Item", "內容 / Content"]),
        ("Windows Defender", defenderInfo,    ["產品版本 / AMProductVersion", "服務版本 / AMServiceVersion",
                                                "防間諜簽章版本 / AntispywareSignatureVersion", "防毒簽章版本 / AntivirusSignatureVersion"]),
        ("已安裝更新",       updates,          ["更新編號 / HotFixID", "描述 / Description", "安裝日期 / InstalledOn"]),
        ("已安裝程式",       programs,         ["名稱 / Name", "版本 / Version", "發行者 / Publisher"]),
        ("使用者帳號",       userAccounts,    ["帳號名稱 / Username", "網域 / Domain", "描述 / Description", "是否啟用 / Enabled"]),
        ("密碼原則",         passwordPolicy,  ["設定 / Setting", "值 / Value"]),
        ("網路設定",         networkSettings, ["介面名稱 / Interface", "IP 位址 / IP Address", "子網遮罩 / Subnet Mask", "DNS 伺服器 / DNS Server"]),
    ]
    if HAS_XLSXWRITER:
        xlsxFile = os.path.join(outDir, f"{baseName}.xlsx")
        exportXlsx(sheets, xlsxFile)
        print(f"系統資訊已匯出至 {xlsxFile}（xlsxwriter）")
    else:
        csvFiles = exportCsv(sheets, baseName, outDir)
        print("系統資訊已匯出至以下 CSV 檔案：")
        for f in csvFiles:
            print(f"  {f}")

    # 打包成 zip
    with zipfile.ZipFile(zipPath, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(outDir):
            fpath = os.path.join(outDir, fname)
            if os.path.isfile(fpath):
                zf.write(fpath, arcname=os.path.join(baseName, fname))
    print(f"已壓縮至 {zipPath}")

def generateHtml(computerName, localIp, systemInfo, defenderInfo, updates,
                  programs, userAccounts, passwordPolicy, networkSettings):
    """
    產生 HTML 格式的報告 (使用 Bootstrap 5)
    並在頁面上方加入導覽列 (Navbar)，可快速跳轉到各區段。
    """
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html lang='zh-Hant'>")
    html.append("<head>")
    html.append("<meta charset='UTF-8'>")
    html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html.append(f"<title>系統資訊報告 - {computerName} ({localIp})</title>")
    # 引入 Bootstrap 5 CSS
    html.append("<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>")
    # 自訂 CSS (可根據需求調整)
    html.append("<style>")
    html.append("body { padding-top: 4.5rem; }")  # 留出 Navbar 高度
    html.append(".section { margin-bottom: 40px; }")
    html.append("h2 { margin-top: 20px; }")
    html.append("table { width: 100%; margin-bottom: 20px; }")
    html.append("th { cursor: pointer; }")
    html.append("</style>")
    html.append("</head>")
    html.append("<body>")

    # 導覽列 (Navbar) - Bootstrap 5
    # 可依需求調整樣式，如 navbar-dark bg-dark / navbar-light bg-light
    html.append("""
<nav class="navbar navbar-expand-lg navbar-light bg-light fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">系統資訊報告</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent"
      aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="切換導覽列">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarSupportedContent">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="#system_info">系統資訊</a></li>
        <li class="nav-item"><a class="nav-link" href="#defender">Windows Defender</a></li>
        <li class="nav-item"><a class="nav-link" href="#updates">已安裝更新</a></li>
        <li class="nav-item"><a class="nav-link" href="#programs">已安裝程式</a></li>
        <li class="nav-item"><a class="nav-link" href="#users">使用者帳號</a></li>
        <li class="nav-item"><a class="nav-link" href="#policy">密碼原則</a></li>
        <li class="nav-item"><a class="nav-link" href="#network">網路設定</a></li>
      </ul>
    </div>
  </div>
</nav>
""")

    html.append("<div class='container'>")
    html.append("<div class='row'>")
    html.append("<div class='col'>")
    html.append("<h1 class='mb-4'>系統資訊報告</h1>")
    html.append(f"<p><strong>電腦名稱：</strong>{computerName}<br>")
    html.append(f"<strong>區網 IP：</strong>{localIp}</p>")

    # 依序產生各區段表格
    # table_id 與導覽列對應
    html.append(generateHtmlSection("系統資訊", systemInfo, "system_info"))
    html.append(generateHtmlSection("Windows Defender", defenderInfo, "defender"))
    html.append(generateHtmlSection("已安裝更新", updates, "updates"))
    html.append(generateHtmlSection("已安裝程式", programs, "programs"))
    html.append(generateHtmlSection("使用者帳號", userAccounts, "users"))
    html.append(generateHtmlSection("密碼原則", passwordPolicy, "policy"))
    html.append(generateHtmlSection("網路設定", networkSettings, "network"))

    html.append("</div></div></div>")  # end of container, row, col

    # 簡易版排序函式 (在點擊表頭時觸發)
    html.append("""
<script>
function sortTable(tableId, columnIndex) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var switching = true;
    var dir = "asc"; 
    var switchcount = 0;

    while (switching) {
        switching = false;
        var rows = table.getElementsByTagName("TR");
        for (var i = 1; i < rows.length - 1; i++) {
            var shouldSwitch = false;
            var x = rows[i].getElementsByTagName("TD")[columnIndex];
            var y = rows[i + 1].getElementsByTagName("TD")[columnIndex];
            if (!x || !y) continue;

            // 用 localeCompare 進行比較 (數字也能大致排序)
            var cmp = x.innerHTML.localeCompare(y.innerHTML, 'zh-Hant', { numeric: true, sensitivity: 'base' });
            if (dir === "asc" && cmp > 0) {
                shouldSwitch = true;
                break;
            } else if (dir === "desc" && cmp < 0) {
                shouldSwitch = true;
                break;
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount === 0 && dir === "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}
</script>
""")

    # Bootstrap 5 JS (不依賴 jQuery)
    html.append("<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>")
    html.append("</body>")
    html.append("</html>")
    return "\n".join(html)


def generateHtmlSection(title, data, tableId):
    """
    將 List[Dict] 資料轉換為 HTML 區段。
    所有資料內容均經過 html_mod.escape() 處理，防止 XSS。
    """
    html = []
    html.append(f"<div class='section' id='{html_mod.escape(tableId)}'>")
    html.append(f"<h2>{html_mod.escape(title)}</h2>")

    if not data:
        html.append("<p>無資料</p>")
        html.append("</div>")
        return "\n".join(html)

    if isinstance(data, list) and data and isinstance(data[0], dict):
        headers = list(data[0].keys())
        safeTid = html_mod.escape(tableId)
        html.append(f"<table class='table table-bordered table-sm' id='{safeTid}_table'>")
        html.append("<thead class='table-light'><tr>")
        for i, header in enumerate(headers):
            html.append(
                f"<th onclick=\"sortTable('{safeTid}_table', {i})\">")
                f"{html_mod.escape(str(header))}</th>"
            )
        html.append("</tr></thead>")
        html.append("<tbody>")
        for item in data:
            html.append("<tr>")
            for header in headers:
                val = item.get(header, "")
                if isinstance(val, dict):
                    val = val.get("DateTime", str(val))
                elif isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                html.append(f"<td>{html_mod.escape(str(val))}</td>")
            html.append("</tr>")
        html.append("</tbody>")
        html.append("</table>")
    else:
        for item in data:
            html.append(f"<p>{html_mod.escape(str(item))}</p>")

    html.append("</div>")
    return "\n".join(html)


if __name__ == "__main__":
    main()