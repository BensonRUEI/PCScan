# -*- coding: utf-8 -*-
"""
NVD CVE JSON ZIP 下載器

提供下載 NVD 年份資料並寫入 SQLite 索引的功能。
"""

import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
CURRENT_YEAR = datetime.now().year


# ──────────────────────────────────────────────────────────────────────────────
# 下載
# ──────────────────────────────────────────────────────────────────────────────

def _progressHook(blockNum, blockSize, totalSize):
    if totalSize > 0:
        pct = min(100, blockNum * blockSize * 100 // totalSize)
        mb  = blockNum * blockSize / 1_048_576
        print(f"    {pct:3d}%  {mb:6.1f} MB", end="\r", flush=True)


def downloadYear(year: int, destDir: Path) -> Path:
    """
    下載指定年份的 NVD CVE ZIP 至 destDir。
    回傳儲存路徑；HTTP 404 時拋出 FileNotFoundError。
    """
    url      = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.zip"
    destPath = destDir / f"nvdcve-2.0-{year}.json.zip"

    print(f"  下載 {year} 年資料中...")
    try:
        urllib.request.urlretrieve(url, destPath, reporthook=_progressHook)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise FileNotFoundError(f"NVD 無 {year} 年資料（HTTP 404）") from e
        raise
    except urllib.error.URLError as e:
        raise ConnectionError(f"網路連線失敗：{e.reason}") from e

    sizeMb = destPath.stat().st_size / 1_048_576
    print(f"    完成（{sizeMb:.1f} MB）                ")
    return destPath


# ──────────────────────────────────────────────────────────────────────────────
# 互動式年份選擇
# ──────────────────────────────────────────────────────────────────────────────

def selectYears() -> list:
    """互動式詢問要下載哪些年份，回傳年份整數清單。"""
    print()
    print("  請選擇 NVD 資料下載範圍：")
    print(f"    1. 僅當前年份 ({CURRENT_YEAR})              [快速，約 4–10 MB]")
    print(f"    2. 最近 3 年  ({CURRENT_YEAR-2}–{CURRENT_YEAR})         [較完整，約 15–30 MB]")
    print(f"    3. 最近 5 年  ({CURRENT_YEAR-4}–{CURRENT_YEAR})         [更完整，約 25–50 MB]")
    print(f"    4. 完整歷史   (2002–{CURRENT_YEAR})          [最完整，約 0.5–1 GB]")
    print(f"    5. 自訂年份範圍")
    choice = input("  請輸入選項 [1]: ").strip() or "1"

    if choice == "1":
        return [CURRENT_YEAR]
    elif choice == "2":
        return list(range(CURRENT_YEAR - 2, CURRENT_YEAR + 1))
    elif choice == "3":
        return list(range(CURRENT_YEAR - 4, CURRENT_YEAR + 1))
    elif choice == "4":
        return list(range(2002, CURRENT_YEAR + 1))
    elif choice == "5":
        raw = input(f"  輸入年份範圍（如 2020-{CURRENT_YEAR}）或單一年份：").strip()
        try:
            if "-" in raw:
                lo, hi = raw.split("-", 1)
                return list(range(int(lo), int(hi) + 1))
            return [int(raw)]
        except ValueError:
            print("  格式有誤，使用預設（當前年份）。")
            return [CURRENT_YEAR]
    else:
        print("  無效選項，使用預設（當前年份）。")
        return [CURRENT_YEAR]


# ──────────────────────────────────────────────────────────────────────────────
# 下載並索引
# ──────────────────────────────────────────────────────────────────────────────

def downloadAndIndex(years: list, dbPath: Path, reset: bool = False) -> dict:
    """
    下載並索引指定年份清單。
    reset=True 時先清空舊資料庫再重建。
    回傳 {"cveTotal": int, "affectedTotal": int}。
    """
    import tempfile
    from .scanner import parseAndIndex, initDb

    if reset and dbPath.exists():
        dbPath.unlink()
        print(f"  已清空舊資料庫：{dbPath.name}")

    initDb(dbPath).close()   # 確保 schema 存在

    cveTotal = affTotal = 0
    with tempfile.TemporaryDirectory() as tmpDir:
        tmpPath = Path(tmpDir)
        for year in sorted(years):
            try:
                zipPath  = downloadYear(year, tmpPath)
                t0       = time.time()
                cveCount, affCount = parseAndIndex(zipPath, dbPath)
                elapsed  = time.time() - t0
                print(f"  索引 {year}：{cveCount:,} CVEs，{affCount:,} 受影響記錄  ({elapsed:.1f}s)")
                cveTotal += cveCount
                affTotal += affCount
            except FileNotFoundError as e:
                print(f"  [略過] {e}", file=sys.stderr)
            except Exception as e:
                print(f"  [警告] {year} 年處理失敗：{e}", file=sys.stderr)

    return {"cveTotal": cveTotal, "affectedTotal": affTotal}
