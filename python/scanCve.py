#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 離線風險掃描工具

Usage:
  python scanCve.py                執行完整掃描流程
  python scanCve.py --update       強制更新 NVD 資料庫後掃描
  python scanCve.py --min-score 7  只顯示 CVSS >= 7.0 的高風險 CVE

Flow:
  1. 檢查 NVD 離線資料庫 → 自動下載或詢問是否更新
  2. 蒐集本機已安裝程式清單
  3. 比對 CVE 風險
  4. 輸出 CSV + HTML 報告至 output/
"""

import argparse
import csv
import html as html_mod
import platform
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from cveScanner.scanner    import DB_DEFAULT, getDbStats, initDb, scanPrograms
from cveScanner.downloader import downloadAndIndex, selectYears
from cveScanner.repology   import fetchLatestVersions

try:
    from collector import get_installed_programs, get_local_ip_address
    HAS_COLLECTOR = True
except ImportError:
    HAS_COLLECTOR = False

# ──────────────────────────────────────────────────────────────────────────────
# 常數
# ──────────────────────────────────────────────────────────────────────────────

_FIELDS = [
    "軟體名稱 / Software",
    "已安裝版本 / Version",
    "最新版本 / Latest",
    "CVE ID",
    "CVSS 分數 / Score",
    "嚴重等級 / Severity",
    "受影響版本範圍 / Range",
    "描述 / Description",
]

_SEV_ROW = {
    "CRITICAL": "table-danger",
    "HIGH":     "table-warning",
    "MEDIUM":   "table-info",
    "LOW":      "table-success",
}

_SEV_BADGE = {
    "CRITICAL": "bg-danger",
    "HIGH":     "bg-warning text-dark",
    "MEDIUM":   "bg-info text-dark",
    "LOW":      "bg-success",
}


# ──────────────────────────────────────────────────────────────────────────────
# Step 1：DB 管理
# ──────────────────────────────────────────────────────────────────────────────

def ensureDb(forceUpdate: bool = False):
    """確保 NVD 資料庫存在並視情況更新。"""
    stats = getDbStats(DB_DEFAULT)

    # 資料庫不存在 → 第一次建立
    if not stats["exists"] or stats["cveCount"] == 0:
        print("  NVD 資料庫不存在，需要下載 NVD 資料。")
        years = selectYears()
        print(f"\n  開始下載 {len(years)} 個年份的資料...")
        result = downloadAndIndex(years, DB_DEFAULT, reset=True)
        print(f"\n  資料庫建立完成：{result['cveTotal']:,} CVEs，"
              f"{result['affectedTotal']:,} 受影響記錄")
        return

    # 資料庫存在 → 顯示統計並詢問是否更新
    print(f"  現有資料庫：{stats['cveCount']:,} CVEs / "
          f"{stats['affectedCount']:,} 受影響記錄")

    if forceUpdate:
        shouldUpdate = True
    else:
        ans = input("  是否更新資料庫？[y/N] ").strip().lower()
        shouldUpdate = (ans == "y")

    if shouldUpdate:
        years = selectYears()
        print(f"\n  開始更新 {len(years)} 個年份的資料...")
        result = downloadAndIndex(years, DB_DEFAULT, reset=True)
        print(f"\n  資料庫更新完成：{result['cveTotal']:,} CVEs，"
              f"{result['affectedTotal']:,} 受影響記錄")
    else:
        print("  略過更新，使用現有資料庫。")


# ──────────────────────────────────────────────────────────────────────────────
# Step 4a：CSV 輸出
# ──────────────────────────────────────────────────────────────────────────────

def exportCsv(results: list, outPath: Path):
    with open(outPath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"  CSV  ：{outPath}")


# ──────────────────────────────────────────────────────────────────────────────
# Step 4b：HTML 輸出
# ──────────────────────────────────────────────────────────────────────────────

def exportHtml(results: list, computerName: str, localIp: str,
               dbStats: dict, outPath: Path):
    scanTime  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sevCounts = Counter(r.get("嚴重等級 / Severity", "").upper() for r in results)
    total     = len(results)

    L = []
    a = L.append

    a("<!DOCTYPE html>")
    a("<html lang='zh-Hant'><head>")
    a("<meta charset='UTF-8'>")
    a("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    a(f"<title>CVE 風險報告 — {html_mod.escape(computerName)}</title>")
    a("<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>")
    a("<style>")
    a("body { padding-top: 4.5rem; }")
    a("th   { cursor: pointer; white-space: nowrap; user-select: none; }")
    a("th:hover { background: rgba(255,255,255,.15); }")
    a(".desc-cell { max-width: 380px; font-size: .85em; word-break: break-word; }")
    a("</style></head><body>")

    # Navbar
    a("<nav class='navbar navbar-expand-lg navbar-dark bg-dark fixed-top'>")
    a("  <div class='container-fluid'>")
    a(f"  <span class='navbar-brand'>&#x1F6E1; CVE 風險報告 &mdash; "
      f"{html_mod.escape(computerName)}</span>")
    a("  </div>")
    a("</nav>")

    a("<div class='container-xl mt-4 mb-5'>")

    # 資訊卡
    a("<div class='card mb-3 border-0 shadow-sm'><div class='card-body'>")
    a("<div class='row g-3'>")
    for label, val in [
        ("主機名稱", computerName),
        ("IP 位址",  localIp),
        ("掃描時間", scanTime),
    ]:
        a(f"<div class='col-md-4'>"
          f"<small class='text-muted d-block'>{html_mod.escape(label)}</small>"
          f"<strong>{html_mod.escape(str(val))}</strong></div>")
    a(f"<div class='col-md-4'>"
      f"<small class='text-muted d-block'>NVD 資料庫</small>"
      f"{dbStats['cveCount']:,} CVEs / {dbStats['affectedCount']:,} 受影響記錄</div>")
    a("</div></div></div>")

    # 嚴重等級摘要
    a("<div class='mb-3'>")
    if not results:
        a("<div class='alert alert-success mb-0'>&#x2705; 未發現任何已知 CVE 風險。</div>")
    else:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cnt = sevCounts.get(sev, 0)
            if not cnt:
                continue
            cls = _SEV_BADGE.get(sev, "bg-secondary")
            a(f"<span class='badge {cls} fs-6 me-2 mb-1'>"
              f"{html_mod.escape(sev)}: {cnt}</span>")
        a(f"<span class='text-muted'>共 {total} 筆</span>")
    a("</div>")

    if results:
        # 搜尋 / 過濾列
        a("<div class='row g-2 mb-3 align-items-center'>")
        a("  <div class='col-auto'>")
        a("    <input id='kwFilter' class='form-control' style='min-width:220px' "
          "placeholder='搜尋軟體名稱 / CVE ID…' oninput='applyFilters()'>")
        a("  </div>")
        a("  <div class='col-auto'>")
        a("    <select id='sevFilter' class='form-select' onchange='applyFilters()'>")
        a("      <option value=''>全部嚴重等級</option>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            a(f"      <option value='{sev}'>{sev}</option>")
        a("    </select>")
        a("  </div>")
        a("  <div class='col-auto'>")
        a("    <span id='rowCount' class='text-muted small'></span>")
        a("  </div>")
        a("</div>")

        # 表格
        a("<div class='table-responsive'>")
        a("<table class='table table-bordered table-hover table-sm align-middle' "
          "id='cveTable' data-sort-col='-1' data-sort-asc='1'>")
        a("<thead class='table-dark'><tr>")
        for i, h in enumerate(_FIELDS):
            a(f"<th onclick=\"sortTable({i})\">{html_mod.escape(h)} &#x21C5;</th>")
        a("</tr></thead>")
        a("<tbody id='cveBody'>")
        for r in results:
            sev      = r.get("嚴重等級 / Severity", "").upper()
            rowClass = _SEV_ROW.get(sev, "")
            a(f"<tr class='{rowClass}'>")
            for h in _FIELDS:
                val = r.get(h, "")
                if h == "描述 / Description":
                    a(f"<td class='desc-cell'>{html_mod.escape(str(val))}</td>")
                elif h == "最新版本 / Latest":
                    latest    = str(val)
                    installed = r.get("已安裝版本 / Version", "")
                    if not latest:
                        a("<td><span class='text-muted'>—</span></td>")
                    elif installed == latest:
                        a(f"<td><span class='text-success fw-bold'>{html_mod.escape(latest)}</span></td>")
                    else:
                        a(f"<td><span class='text-warning fw-bold'>{html_mod.escape(latest)} &#x2B06;</span></td>")
                else:
                    a(f"<td>{html_mod.escape(str(val))}</td>")
            a("</tr>")
        a("</tbody></table></div>")

    # JavaScript
    a("""<script>
function sortTable(col) {
    const tbl   = document.getElementById('cveTable');
    const tbody = tbl.tBodies[0];
    const rows  = Array.from(tbody.rows);
    const asc   = (parseInt(tbl.dataset.sortCol) === col)
                  ? tbl.dataset.sortAsc !== '1'
                  : true;
    rows.sort((a, b) => {
        const x = a.cells[col]?.textContent.trim() ?? '';
        const y = b.cells[col]?.textContent.trim() ?? '';
        const n = parseFloat(x) - parseFloat(y);
        const c = isNaN(n) ? x.localeCompare(y, 'zh-Hant', {numeric: true}) : n;
        return asc ? c : -c;
    });
    rows.forEach(r => tbody.appendChild(r));
    tbl.dataset.sortCol = col;
    tbl.dataset.sortAsc = asc ? '1' : '0';
    updateCount();
}

function applyFilters() {
    const kw  = document.getElementById('kwFilter').value.toLowerCase();
    const sev = document.getElementById('sevFilter').value.toUpperCase();
    let visible = 0;
    document.querySelectorAll('#cveBody tr').forEach(row => {
        const text   = row.textContent.toLowerCase();
        const rowSev = row.cells[4]?.textContent.trim().toUpperCase() ?? '';
        const show   = text.includes(kw) && (!sev || rowSev === sev);
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    const el = document.getElementById('rowCount');
    if (el) el.textContent = `顯示 ${visible} 筆`;
}

function updateCount() {
    const visible = Array.from(document.querySelectorAll('#cveBody tr'))
                         .filter(r => r.style.display !== 'none').length;
    const el = document.getElementById('rowCount');
    if (el) el.textContent = `顯示 ${visible} 筆`;
}

document.addEventListener('DOMContentLoaded', updateCount);
</script>""")

    a("<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'>"
      "</script>")
    a("</body></html>")

    with open(outPath, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(L))
    print(f"  HTML ：{outPath}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="CVE 離線風險掃描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--update",    action="store_true",
                        help="強制更新 NVD 資料庫（略過詢問）")
    parser.add_argument("--min-score", type=float, default=0.0, metavar="N",
                        help="最低 CVSS 分數篩選，預設 0.0（全部顯示）")
    args = parser.parse_args()

    print("=" * 60)
    print("  CVE 離線風險掃描工具")
    print("=" * 60)

    # 無任何引數時，顯示互動選單讓使用者選擇執行模式
    if len(sys.argv) == 1:
        print()
        print("  請選擇執行模式：")
        print("    1. 標準掃描                  （使用現有資料庫）")
        print("    2. 強制更新資料庫後掃描       （--update）")
        print("    3. 只顯示高風險（CVSS >= 7）  （--min-score 7）")
        choice = input("  請輸入選項 [1]: ").strip() or "1"
        if choice == "2":
            args.update   = True
        elif choice == "3":
            args.min_score = 7.0
        # choice == "1" 維持預設值不變

    # ── Step 1：確保 DB ──────────────────────────────────────────────
    print("\n[1/4] 檢查 NVD 資料庫...")
    ensureDb(forceUpdate=args.update)

    # ── Step 2：蒐集程式清單 ─────────────────────────────────────────
    print("\n[2/4] 蒐集已安裝程式清單...")
    if HAS_COLLECTOR:
        programs = get_installed_programs()
        localIp  = get_local_ip_address()
        print(f"  共蒐集 {len(programs)} 個程式")
    else:
        print("  [警告] collector 模組不可用，無法蒐集程式清單。")
        programs = []
        localIp  = "127.0.0.1"

    computerName = platform.node()

    # ── Step 3：CVE 比對 ─────────────────────────────────────────────
    print(f"\n[3/4] 比對 CVE 風險（CVSS >= {args.min_score}）...")
    results = scanPrograms(programs, minScore=args.min_score)
    dbStats = getDbStats(DB_DEFAULT)

    sevCounts = Counter(r.get("嚴重等級 / Severity", "").upper() for r in results)
    print(f"  發現 {len(results)} 筆潛在 CVE 風險")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = sevCounts.get(sev, 0)
        if cnt:
            print(f"    {sev}: {cnt}")

    # ── Step 4：查詢最新版本 ─────────────────────────────────────────
    print("\n[4/4] 查詢軟體最新版本（Repology）...")
    uniqueNames = list(dict.fromkeys(r["軟體名稱 / Software"] for r in results))
    latestMap   = fetchLatestVersions(uniqueNames) if uniqueNames else {}
    for r in results:
        r["最新版本 / Latest"] = latestMap.get(r["軟體名稱 / Software"], "")

    # ── 輸出 ─────────────────────────────────────────────────────────
    baseName = f"{computerName}_{localIp}"
    outDir   = Path(__file__).parent / "output" / baseName
    outDir.mkdir(parents=True, exist_ok=True)

    csvPath  = outDir / f"{baseName}_CVE.csv"
    htmlPath = outDir / f"{baseName}_CVE.html"

    print(f"\n匯出報告至：{outDir.resolve()}")
    exportCsv(results, csvPath)
    exportHtml(results, computerName, localIp, dbStats, htmlPath)

    print(f"\n完成！HTML 報告：{htmlPath.resolve()}")


if __name__ == "__main__":
    main()
