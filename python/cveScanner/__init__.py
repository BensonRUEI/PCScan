# -*- coding: utf-8 -*-
"""
cveScanner — 離線 NVD CVE 風險掃描套件

整合程式（自動判斷 DB、下載、掃描、輸出報告）：
  python -m cveScanner
  python -m cveScanner --update          # 強制更新 DB
  python -m cveScanner --min-score 7.0   # 只顯示 HIGH 以上

手動管理 DB（進階）：
  python -m cveScanner.nvdIndexer <nvdcve-2.0-YYYY.json.zip>

公共 API（供 getPcInfo.py 使用）：
  scanPrograms(programs, dbPath, minScore) → List[Dict]
  getDbStats(dbPath)                       → dict
  normalizeName(displayName)               → str
  DB_DEFAULT                               → Path
"""

from .scanner import (
    DB_DEFAULT,
    initDb,
    parseAndIndex,
    normalizeName,
    scanPrograms,
    getDbStats,
)

__all__ = [
    "DB_DEFAULT",
    "initDb",
    "parseAndIndex",
    "normalizeName",
    "scanPrograms",
    "getDbStats",
]
