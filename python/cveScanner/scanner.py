# -*- coding: utf-8 -*-
"""
CVE Scanner — 離線 NVD 資料索引與查詢模組

Flow:
  1. 使用 cveScanner/nvdIndexer.py 將 NVD JSON ZIP 建立 SQLite 索引（一次性）
  2. 呼叫 scanPrograms() 對已安裝程式清單進行 CVE 比對

NVD 資料來源：https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
"""

import json
import re
import sqlite3
import zipfile
from pathlib import Path

try:
    from packaging.version import Version, InvalidVersion
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

# 預設 DB 路徑（放在本模組同層目錄）
DB_DEFAULT = Path(__file__).parent / "nvd_cache.db"


# ──────────────────────────────────────────────────────────────────────────────
# 資料庫初始化
# ──────────────────────────────────────────────────────────────────────────────

def initDb(dbPath: Path = DB_DEFAULT) -> sqlite3.Connection:
    """建立或連接 SQLite 資料庫並確保 schema 存在。"""
    conn = sqlite3.connect(dbPath)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve (
            id          TEXT PRIMARY KEY,
            description TEXT,
            score       REAL,
            severity    TEXT
        );
        CREATE TABLE IF NOT EXISTS affected (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id        TEXT NOT NULL,
            vendor        TEXT,
            product       TEXT,
            product_norm  TEXT,
            version_exact TEXT,
            version_start TEXT,
            version_end   TEXT,
            FOREIGN KEY(cve_id) REFERENCES cve(id)
        );
        CREATE INDEX IF NOT EXISTS idx_product      ON affected(product);
        CREATE INDEX IF NOT EXISTS idx_product_norm ON affected(product_norm);
        CREATE INDEX IF NOT EXISTS idx_cve_id       ON affected(cve_id);
    """)
    conn.commit()
    return conn


# ──────────────────────────────────────────────────────────────────────────────
# 解析 NVD JSON ZIP 並寫入索引
# ──────────────────────────────────────────────────────────────────────────────

def parseAndIndex(zipPath: Path, dbPath: Path = DB_DEFAULT):
    """
    解析單一 NVD CVE JSON ZIP 並匯入 SQLite。
    回傳 (cve_count, affected_count)。
    """
    conn = initDb(dbPath)

    with zipfile.ZipFile(zipPath) as zf:
        jsonName = next(n for n in zf.namelist() if n.endswith(".json"))
        with zf.open(jsonName) as f:
            data = json.load(f)

    rowsCve, rowsAff = [], []

    for vuln in data.get("vulnerabilities", []):
        cve   = vuln["cve"]
        cveId = cve["id"]

        # CVSS 分數：優先 v3.1 → v3.0 → v2
        score, severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                cd       = metrics[0]["cvssData"]
                score    = cd.get("baseScore")
                severity = cd.get("baseSeverity")
                break

        # 英文描述
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            ""
        )
        rowsCve.append((cveId, desc, score, severity))

        # CPE 受影響版本（結構：configurations[].nodes[].cpeMatch[]）
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    parts = match.get("criteria", "").split(":")
                    # cpe:2.3:a:vendor:product:version:...
                    if len(parts) >= 6:
                        vendor  = parts[3]
                        product = parts[4]
                        ver     = parts[5] if parts[5] != "*" else None
                        rowsAff.append((
                            cveId, vendor, product,
                            _normalizeCpePart(product),
                            ver,
                            match.get("versionStartIncluding"),
                            match.get("versionEndExcluding"),
                        ))

    conn.executemany("INSERT OR IGNORE INTO cve VALUES (?,?,?,?)", rowsCve)
    conn.executemany(
        "INSERT INTO affected(cve_id,vendor,product,product_norm,version_exact,version_start,version_end)"
        " VALUES (?,?,?,?,?,?,?)",
        rowsAff,
    )
    conn.commit()
    conn.close()
    return len(rowsCve), len(rowsAff)


# ──────────────────────────────────────────────────────────────────────────────
# 名稱正規化（顯示名稱 → CPE product 關鍵字）
# ──────────────────────────────────────────────────────────────────────────────

_VER_SUFFIX = re.compile(r'\s+v?\d[\d\.\-\_]+.*$', re.IGNORECASE)
_NON_ALNUM  = re.compile(r'[^a-z0-9]+')

def normalizeName(displayName: str) -> str:
    """
    將 Windows 安裝程式顯示名稱正規化為 CPE product 風格的關鍵字。
    例如：'7-Zip 19.00 (x64)'        → '7_zip'
          'Microsoft Visual C++ 2019' → 'microsoft_visual_c'
    """
    name = displayName.lower()
    name = _VER_SUFFIX.sub("", name)    # 去除尾部版本號
    name = _NON_ALNUM.sub("_", name)    # 特殊字元 → 底線
    name = name.strip("_")
    return name


def _normalizeCpePart(cpePart: str) -> str:
    """CPE product/vendor 字串正規化（同樣轉換但不去除版本後綴）。"""
    s = cpePart.lower()
    s = _NON_ALNUM.sub("_", s)
    s = s.strip("_")
    return s


# ──────────────────────────────────────────────────────────────────────────────
# 版本比對
# ──────────────────────────────────────────────────────────────────────────────

def _parseVer(s: str):
    if not s or s in ("*", "-", "N/A", ""):
        return None
    if HAS_PACKAGING:
        try:
            return Version(s)
        except InvalidVersion:
            pass
    # fallback：轉成數字 tuple 做基本比對，例如 "2.47.1.2" → (2, 47, 1, 2)
    try:
        return tuple(int(x) for x in re.split(r'[.\-]', s) if x.isdigit())
    except Exception:
        return None


def _cmp(a, b) -> int:
    """回傳 -1 / 0 / 1，支援 Version 物件與 tuple。"""
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def _inRange(installed: str, exact, vStart, vEnd) -> bool:
    """
    判斷 installed 版本是否落在 CVE 受影響範圍內。
    若版本字串無法解析，保守地視為受影響。
    """
    iv = _parseVer(installed)
    if iv is None:
        return True  # 保守：無法解析版本時視為受影響

    # 防止不同版本命名體系造成誤判：
    # 若安裝版本主號 < 100（語意版本）而 CVE 上界主號 >= 2000（日曆版本），
    # 且無下界約束，視為不同產品，略過。
    if HAS_PACKAGING and vEnd and not vStart and exact in (None, "*", "-", ""):
        ev_check = _parseVer(vEnd)
        if (isinstance(iv, Version) and isinstance(ev_check, Version)
                and iv.major < 100 and ev_check.major >= 2000):
            return False

    # exact="-" 在 CPE 規格中表示「版本不適用」，視同所有版本受影響
    if exact and exact not in ("*", "-"):
        ev = _parseVer(exact)
        if ev is not None and type(iv) == type(ev):
            return iv == ev
        # exact 有值但無法解析 → 保守視為受影響
        if ev is None:
            return True

    result = True
    if vStart:
        sv = _parseVer(vStart)
        if sv is not None and type(iv) == type(sv):
            result = result and (iv >= sv)
    if vEnd:
        ev = _parseVer(vEnd)
        if ev is not None and type(iv) == type(ev):
            result = result and (iv < ev)
    return result


def _rangeStr(exact, vStart, vEnd) -> str:
    if exact and exact not in ("*", "-"):
        return f"= {exact}"
    parts = []
    if vStart:
        parts.append(f">= {vStart}")
    if vEnd:
        parts.append(f"< {vEnd}")
    return " 且 ".join(parts) if parts else "所有版本"


# ──────────────────────────────────────────────────────────────────────────────
# 主查詢
# ──────────────────────────────────────────────────────────────────────────────

def scanPrograms(programs: list, dbPath: Path = DB_DEFAULT, minScore: float = 0.0) -> list:
    """
    以已安裝程式清單比對 NVD 離線資料庫。

    programs 格式：[{"名稱 / Name": ..., "版本 / Version": ..., ...}, ...]
    回傳包含 CVE 資訊的 List[Dict]，依 CVSS 分數降序排列。
    若資料庫不存在則回傳空串列。
    """
    if not Path(dbPath).exists():
        return []

    conn = sqlite3.connect(dbPath)
    conn.row_factory = sqlite3.Row
    results = []

    for prog in programs:
        name    = prog.get("名稱 / Name", "")
        version = prog.get("版本 / Version", "")
        keyword = normalizeName(name)
        if len(keyword) < 3:    # 關鍵字太短會產生大量假陽性
            continue

        rows = conn.execute("""
            SELECT c.id, c.score, c.severity, c.description,
                   a.version_exact, a.version_start, a.version_end
            FROM affected a
            JOIN cve c ON a.cve_id = c.id
            WHERE a.product_norm = ?
              AND (c.score IS NULL OR c.score >= ?)
            ORDER BY c.score DESC
        """, (keyword, minScore)).fetchall()

        seen = set()
        for row in rows:
            cveId = row["id"]
            if cveId in seen:
                continue
            if not _inRange(version, row["version_exact"],
                            row["version_start"], row["version_end"]):
                continue
            seen.add(cveId)
            results.append({
                "軟體名稱 / Software":   name,
                "已安裝版本 / Version":  version,
                "CVE ID":                cveId,
                "CVSS 分數 / Score":     row["score"] if row["score"] is not None else "N/A",
                "嚴重等級 / Severity":   row["severity"] or "N/A",
                "受影響版本範圍 / Range": _rangeStr(row["version_exact"],
                                                    row["version_start"],
                                                    row["version_end"]),
                "描述 / Description":    (row["description"] or "")[:300],
            })

    conn.close()
    results.sort(
        key=lambda x: float(x["CVSS 分數 / Score"])
                      if isinstance(x["CVSS 分數 / Score"], (int, float)) else 0,
        reverse=True,
    )
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 資料庫統計
# ──────────────────────────────────────────────────────────────────────────────

def getDbStats(dbPath: Path = DB_DEFAULT) -> dict:
    """回傳資料庫基本統計資訊。"""
    if not Path(dbPath).exists():
        return {"exists": False, "cveCount": 0, "affectedCount": 0}
    conn = sqlite3.connect(dbPath)
    cveCount      = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    affectedCount = conn.execute("SELECT COUNT(*) FROM affected").fetchone()[0]
    conn.close()
    return {"exists": True, "cveCount": cveCount, "affectedCount": affectedCount}
