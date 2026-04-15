# -*- coding: utf-8 -*-
"""
Repology API 查詢 — 取得軟體最新版本

公共 API：
  fetchLatestVersions(names) → {display_name: latest_version_str}
"""

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

_REPOLOGY_URL  = "https://repology.org/api/v1/project/{name}"
_repologyCache: dict = {}


def _fetchLatestVersion(repologyName: str) -> str:
    """查詢 Repology API，回傳 newest 狀態中最大的版本號；失敗時回傳空字串。"""
    if repologyName in _repologyCache:
        return _repologyCache[repologyName]
    try:
        req = urllib.request.Request(
            _REPOLOGY_URL.format(name=repologyName),
            headers={"User-Agent": "PCScan/1.0 (https://github.com/PCScan)"},
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
        versions = sorted({p["version"] for p in data if p.get("status") == "newest"})
        result   = versions[-1] if versions else ""
    except Exception:
        result = ""
    _repologyCache[repologyName] = result
    return result


def fetchLatestVersions(softwareNames: list) -> dict:
    """
    批次查詢 Repology，回傳 {display_name: latest_version}。
    相同 Repology 名稱只查詢一次，以 8 執行緒並行加速。
    """
    from .scanner import normalizeName

    # display_name → repology_name（底線轉連字號）
    repToDisplay: dict = {}
    for name in dict.fromkeys(softwareNames):       # 保留順序去重
        rn = normalizeName(name).replace("_", "-")
        repToDisplay.setdefault(rn, []).append(name)

    results = {n: "" for n in softwareNames}
    total   = len(repToDisplay)
    done    = [0]

    def _query(repName):
        v = _fetchLatestVersion(repName)
        done[0] += 1
        print(f"\r  查詢最新版本… {done[0]}/{total}", end="", flush=True)
        return repName, v

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_query, rn): rn for rn in repToDisplay}
        for fut in as_completed(futures):
            rn, ver = fut.result()
            for dn in repToDisplay[rn]:
                results[dn] = ver

    print()
    found = sum(1 for v in results.values() if v)
    print(f"  找到 {found}/{len(repToDisplay)} 個軟體的最新版本資訊")
    return results
