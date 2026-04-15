#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD Indexer — 將 NVD JSON ZIP 批次匯入 SQLite 離線索引

Usage:
  python -m cveScanner.nvdIndexer <zip1> [zip2 ...]
  python -m cveScanner.nvdIndexer nvdcve-2.0-2026.json.zip
  python -m cveScanner.nvdIndexer nvd_feeds/nvdcve-2.0-*.json.zip
  python -m cveScanner.nvdIndexer --reset nvdcve-2.0-2026.json.zip

NVD 資料下載：https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
  建議下載（測試）：nvdcve-2.0-2026.json.zip
  完整覆蓋：nvdcve-2.0-2002.json.zip ~ nvdcve-2.0-{本年}.json.zip

選項：
  --db <path>   指定 SQLite DB 路徑（預設：nvd_cache.db）
  --reset       清空並重建資料庫（重新索引前使用）
  --min-year    只索引指定年份以後的 CVE（配合 glob 使用）
"""

import argparse
import sys
import time
from pathlib import Path

from .scanner import DB_DEFAULT, initDb, parseAndIndex, getDbStats


def main():
    parser = argparse.ArgumentParser(
        description="將 NVD CVE JSON ZIP 建立離線查詢索引",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("zips", nargs="+", metavar="ZIP",
                        help="NVD JSON ZIP 路徑（支援 shell glob，如 nvd_feeds/*.zip）")
    parser.add_argument("--db", default=str(DB_DEFAULT), metavar="PATH",
                        help=f"SQLite DB 路徑（預設：{DB_DEFAULT}）")
    parser.add_argument("--reset", action="store_true",
                        help="清空並重建資料庫")
    args = parser.parse_args()

    dbPath = Path(args.db)

    if args.reset and dbPath.exists():
        dbPath.unlink()
        print(f"已清空資料庫：{dbPath}")

    # 初始化（若不存在則建立）
    conn = initDb(dbPath)
    conn.close()

    # 展開並排序所有 ZIP 路徑
    zipPaths = []
    for pattern in args.zips:
        if "*" in pattern or "?" in pattern:
            matches = sorted(Path(".").glob(pattern))
            if not matches:
                print(f"[警告] 無符合的檔案：{pattern}", file=sys.stderr)
            zipPaths.extend(matches)
        else:
            zipPaths.append(Path(pattern))

    if not zipPaths:
        print("錯誤：未找到任何 ZIP 檔案。", file=sys.stderr)
        sys.exit(1)

    # 依序解析每個 ZIP
    totalCve = totalAff = 0
    for zipPath in zipPaths:
        if not zipPath.exists():
            print(f"[跳過] 找不到檔案：{zipPath}", file=sys.stderr)
            continue

        print(f"索引中：{zipPath.name} ...", end=" ", flush=True)
        t0 = time.time()
        try:
            cveCount, affCount = parseAndIndex(zipPath, dbPath)
        except Exception as e:
            print(f"失敗（{e}）", file=sys.stderr)
            continue
        elapsed = time.time() - t0
        print(f"{cveCount:,} CVEs，{affCount:,} 受影響記錄  ({elapsed:.1f}s)")
        totalCve += cveCount
        totalAff += affCount

    # 最終統計
    stats = getDbStats(dbPath)
    print(f"\n完成。資料庫：{dbPath.resolve()}")
    print(f"  累積 CVE       ：{stats['cveCount']:,} 筆")
    print(f"  受影響記錄     ：{stats['affectedCount']:,} 筆")
    print(f"\n下一步：執行 python getPcInfo.py 以包含 CVE 風險掃描")


if __name__ == "__main__":
    main()
