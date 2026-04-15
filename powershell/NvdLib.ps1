#Requires -Version 5.1
<#
.SYNOPSIS
    NVD 共用函式庫 — 供 getPcInfo.ps1 使用

.DESCRIPTION
    包含 SQLite 載入、NVD DB schema/stats、ZIP 解析/索引、下載輔助、
    Repology/CVE 掃描比對，以及 CVE 報告輸出函式。
    請以 dot-source 載入：. (Join-Path $PSScriptRoot 'NvdLib.ps1')
#>

$ErrorActionPreference = 'Stop'

# ===========================================================================
# SQLite 組件載入（自動從 NuGet 下載）
# ===========================================================================

function Initialize-SQLiteLib {
    <#
    .SYNOPSIS 載入 System.Data.SQLite；若 DLL 不在 lib\ 則自動從 NuGet 下載。
    .OUTPUTS [bool] 成功回傳 $true。
    #>
    [OutputType([bool])]
    param()

    $loaded = [System.AppDomain]::CurrentDomain.GetAssemblies() |
              Where-Object { $_.GetName().Name -eq 'System.Data.SQLite' }
    if ($loaded) { return $true }

    $libDir  = Join-Path $PSScriptRoot 'lib'
    $dllPath = Join-Path $libDir 'System.Data.SQLite.dll'

    if (Test-Path $dllPath) {
        try { Add-Type -Path $dllPath; return $true } catch {}
    }

    Write-Host '  SQLite 組件不存在，正在從官方網站下載...' -ForegroundColor Cyan
    try {
        New-Item $libDir -ItemType Directory -Force | Out-Null
        $arch    = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
        $url     = "https://system.data.sqlite.org/blobs/1.0.119.0/sqlite-netFx46-binary-$arch-2015-1.0.119.0.zip"
        $tmp     = Join-Path ([IO.Path]::GetTempPath()) 'sqlite_precomp.zip'
        Write-Host "  下載 SQLite ($arch)..." -ForegroundColor Gray
        Invoke-WebRequest $url -OutFile $tmp -UseBasicParsing
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip         = [IO.Compression.ZipFile]::OpenRead($tmp)
        $interopDest = Join-Path $libDir 'SQLite.Interop.dll'
        foreach ($e in $zip.Entries) {
            if ($e.Name -eq 'System.Data.SQLite.dll') {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dllPath, $true)
            } elseif ($e.Name -eq 'SQLite.Interop.dll') {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $interopDest, $true)
            }
        }
        $zip.Dispose()
        Remove-Item $tmp -ErrorAction SilentlyContinue
        if (Test-Path $dllPath) {
            Add-Type -Path $dllPath
            Write-Host '  SQLite 組件下載完成' -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "  SQLite 下載失敗：$_" -ForegroundColor Red
    }
    return $false
}

# ===========================================================================
# DB Schema & Stats
# ===========================================================================

function Initialize-NvdDb {
    <#
    .SYNOPSIS 建立 NVD SQLite 資料庫 schema（若尚不存在）。
    #>
    param([Parameter(Mandatory)][string]$DbPath)

    New-Item (Split-Path $DbPath -Parent) -ItemType Directory -Force | Out-Null
    $cs  = "Data Source=$([IO.Path]::GetFullPath($DbPath))"
    $con = New-Object System.Data.SQLite.SQLiteConnection($cs)
    $con.Open()
    $cmd = $con.CreateCommand()
    $cmd.CommandText = @"
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
    target_sw     TEXT DEFAULT '*',
    FOREIGN KEY(cve_id) REFERENCES cve(id)
);
CREATE INDEX IF NOT EXISTS idx_product      ON affected(product);
CREATE INDEX IF NOT EXISTS idx_product_norm ON affected(product_norm);
CREATE INDEX IF NOT EXISTS idx_cve_id       ON affected(cve_id);
"@
    $null = $cmd.ExecuteNonQuery()
    # 升級舊版 schema（新增 target_sw 欄，忽略已存在的錯誤）
    try {
        $cmd.CommandText = "ALTER TABLE affected ADD COLUMN target_sw TEXT DEFAULT '*'"
        $null = $cmd.ExecuteNonQuery()
    } catch {}
    $con.Close()
}

function Get-NvdDbStats {
    <#
    .SYNOPSIS 回傳 NVD 資料庫的狀態統計。
    .OUTPUTS hashtable { exists, cveCount, affectedCount }
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$DbPath)

    if (-not (Test-Path $DbPath)) {
        return @{ exists = $false; cveCount = 0; affectedCount = 0 }
    }
    $cs  = "Data Source=$([IO.Path]::GetFullPath($DbPath));Read Only=True"
    $con = New-Object System.Data.SQLite.SQLiteConnection($cs)
    $con.Open()
    $cmd = $con.CreateCommand()
    $cmd.CommandText = 'SELECT COUNT(*) FROM cve'
    $cN  = [int]$cmd.ExecuteScalar()
    $cmd.CommandText = 'SELECT COUNT(*) FROM affected'
    $aN  = [int]$cmd.ExecuteScalar()
    $con.Close()
    return @{ exists = $true; cveCount = $cN; affectedCount = $aN }
}

# ===========================================================================
# ZIP 解析與索引
# ===========================================================================

function Import-NvdZip {
    <#
    .SYNOPSIS 解析 NVD CVE JSON ZIP 並寫入 SQLite DB。
    .OUTPUTS hashtable { cveCount, affectedCount }
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DbPath
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip       = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    $jsonEntry = $zip.Entries | Where-Object { $_.Name -like '*.json' } | Select-Object -First 1
    if (-not $jsonEntry) {
        $zip.Dispose()
        throw "ZIP 中找不到 JSON 檔案：$ZipPath"
    }
    $stream  = $jsonEntry.Open()
    $rdr     = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
    Write-Host '  讀取 JSON...' -NoNewline -ForegroundColor Gray
    $jsonTxt = $rdr.ReadToEnd()
    $rdr.Close(); $stream.Close(); $zip.Dispose()

    Write-Host ' 解析中...' -NoNewline -ForegroundColor Gray
    $data  = $jsonTxt | ConvertFrom-Json
    $vulns = @($data.vulnerabilities)
    Write-Host " $($vulns.Count.ToString('N0')) CVEs" -ForegroundColor Gray

    $cs  = "Data Source=$([IO.Path]::GetFullPath($DbPath))"
    $con = New-Object System.Data.SQLite.SQLiteConnection($cs)
    $con.Open()
    $tx = $con.BeginTransaction()

    $cmdCve = $con.CreateCommand(); $cmdCve.Transaction = $tx
    $cmdCve.CommandText = 'INSERT OR IGNORE INTO cve (id,description,score,severity) VALUES (@id,@desc,@score,@sev)'
    [void]$cmdCve.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@id')))
    [void]$cmdCve.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@desc')))
    [void]$cmdCve.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@score')))
    [void]$cmdCve.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@sev')))

    $cmdAff = $con.CreateCommand(); $cmdAff.Transaction = $tx
    $cmdAff.CommandText = 'INSERT INTO affected (cve_id,vendor,product,product_norm,version_exact,version_start,version_end,target_sw) VALUES (@cid,@ven,@prod,@pnorm,@vex,@vst,@vend,@tsw)'
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@cid')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@ven')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@prod')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@pnorm')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@vex')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@vst')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@vend')))
    [void]$cmdAff.Parameters.Add((New-Object System.Data.SQLite.SQLiteParameter('@tsw')))

    $cveCount = 0; $affCount = 0

    foreach ($vuln in $vulns) {
        $cve   = $vuln.cve
        $cveId = $cve.id
        if (-not $cveId) { continue }

        # CVSS 優先順序：v3.1 → v3.0 → v2
        $score = $null; $sev = $null
        foreach ($key in @('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')) {
            $m = $cve.metrics.$key
            if ($null -ne $m -and @($m).Count -gt 0) {
                $cd    = @($m)[0].cvssData
                $score = $cd.baseScore
                $sev   = $cd.baseSeverity
                break
            }
        }

        $descObj = @($cve.descriptions) | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1
        $desc    = if ($descObj) { [string]$descObj.value } else { '' }

        $cmdCve.Parameters['@id'].Value    = $cveId
        $cmdCve.Parameters['@desc'].Value  = $desc
        $cmdCve.Parameters['@score'].Value = if ($null -eq $score) { [DBNull]::Value } else { [double]$score }
        $cmdCve.Parameters['@sev'].Value   = if ($null -eq $sev)   { [DBNull]::Value } else { [string]$sev }
        $null = $cmdCve.ExecuteNonQuery()
        $cveCount++

        foreach ($cfg in @($cve.configurations)) {
            foreach ($node in @($cfg.nodes)) {
                foreach ($match in @($node.cpeMatch)) {
                    if (-not $match.vulnerable) { continue }
                    $parts = ([string]$match.criteria) -split ':'
                    if ($parts.Count -lt 6) { continue }
                    $pnorm = [regex]::Replace($parts[4].ToLower(), '[^a-z0-9]+', '_').Trim('_')
                    $tsw = if ($parts.Count -gt 10 -and $parts[10] -notin @('', '*')) { $parts[10].ToLower() } else { '*' }
                    $cmdAff.Parameters['@cid'].Value   = $cveId
                    $cmdAff.Parameters['@ven'].Value   = $parts[3]
                    $cmdAff.Parameters['@prod'].Value  = $parts[4]
                    $cmdAff.Parameters['@pnorm'].Value = $pnorm
                    $cmdAff.Parameters['@vex'].Value   = if ($parts[5] -ne '*') { $parts[5] } else { [DBNull]::Value }
                    $cmdAff.Parameters['@vst'].Value   = if ($null -eq $match.versionStartIncluding) { [DBNull]::Value } else { [string]$match.versionStartIncluding }
                    $cmdAff.Parameters['@vend'].Value  = if ($null -eq $match.versionEndExcluding)   { [DBNull]::Value } else { [string]$match.versionEndExcluding }
                    $cmdAff.Parameters['@tsw'].Value   = $tsw
                    $null = $cmdAff.ExecuteNonQuery()
                    $affCount++
                }
            }
        }
    }

    $tx.Commit()
    $con.Close()
    return @{ cveCount = $cveCount; affectedCount = $affCount }
}

# ===========================================================================
# 下載互動選年份
# ===========================================================================

function Select-NvdYears {
    <#
    .SYNOPSIS 互動式選單，讓使用者選擇要下載的 NVD 年份範圍。
    .OUTPUTS int[] 選定的年份陣列。
    #>
    [OutputType([int[]])]
    param()

    $cur = (Get-Date).Year
    Write-Host ''
    Write-Host '  請選擇 NVD 資料下載範圍：'
    Write-Host "    1. 僅當前年份 ($cur)              [快速，約 4–10 MB]"
    Write-Host "    2. 最近 3 年  ($($cur-2)–$cur)         [較完整，約 15–30 MB]"
    Write-Host "    3. 最近 5 年  ($($cur-4)–$cur)         [更完整，約 25–50 MB]"
    Write-Host "    4. 完整歷史   (2002–$cur)          [最完整，約 0.5–1 GB]"
    Write-Host '    5. 自訂年份範圍'
    $ch = (Read-Host '  請輸入選項 [1]').Trim()
    if (-not $ch) { $ch = '1' }
    switch ($ch) {
        '2' { return @(($cur - 2)..$cur) }
        '3' { return @(($cur - 4)..$cur) }
        '4' { return @(2002..$cur) }
        '5' {
            $raw = (Read-Host "  輸入年份範圍（如 2020-$cur 或單一年份）").Trim()
            if ($raw -match '^(\d{4})-(\d{4})$') { return @([int]$Matches[1]..[int]$Matches[2]) }
            if ($raw -match '^\d{4}$')            { return @([int]$raw) }
            Write-Host '  格式有誤，使用當前年份'
            return @($cur)
        }
        default { return @($cur) }
    }
}

function Invoke-NvdDownload {
    <#
    .SYNOPSIS 從 NIST 下載指定年份的 NVD ZIP 並索引進 SQLite。
    .OUTPUTS hashtable { cveTotal, affectedTotal }
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][int[]]$DownloadYears,
        [Parameter(Mandatory)][string]$DbPath,
        [bool]$DoReset = $false
    )

    if ($DoReset -and (Test-Path $DbPath)) {
        Remove-Item $DbPath -Force
        Write-Host '  已清空舊資料庫'
    }
    Initialize-NvdDb $DbPath

    $tmpDir   = [IO.Path]::GetTempPath()
    $totalCve = 0; $totalAff = 0

    foreach ($yr in ($DownloadYears | Sort-Object)) {
        $url  = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$yr.json.zip"
        $dest = Join-Path $tmpDir "nvdcve-2.0-$yr.json.zip"
        Write-Host "  下載 $yr 年資料..." -NoNewline
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add('User-Agent', 'pcscan-ps1/1.0')
            $wc.DownloadFile($url, $dest)
            $mb = [math]::Round((Get-Item $dest).Length / 1MB, 1)
            Write-Host " ($mb MB)"
            $t0 = Get-Date
            $r  = Import-NvdZip -ZipPath $dest -DbPath $DbPath
            $el = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
            Write-Host "  索引 $yr：$($r.cveCount.ToString('N0')) CVEs，$($r.affectedCount.ToString('N0')) 受影響記錄  ($el s)"
            $totalCve += $r.cveCount
            $totalAff += $r.affectedCount
        } catch {
            Write-Warning "  $yr 年処理失敗：$_"
        } finally {
            Remove-Item $dest -ErrorAction SilentlyContinue
        }
    }
    return @{ cveTotal = $totalCve; affectedTotal = $totalAff }
}

function Invoke-EnsureDb {
    <#
    .SYNOPSIS 確保 NVD 資料庫存在且有資料；視需要下載或更新。
    #>
    param(
        [Parameter(Mandatory)][string]$DbPath,
        [bool]$ForceUpdate = $false
    )

    $stats = Get-NvdDbStats $DbPath
    if (-not $stats.exists -or $stats.cveCount -eq 0) {
        Write-Host '  NVD 資料庫不存在，需要下載 NVD 資料。'
        $years = Select-NvdYears
        Write-Host "  開始下載 $($years.Count) 個年份的資料..."
        Invoke-NvdDownload -DownloadYears $years -DbPath $DbPath -DoReset $true
        return
    }
    Write-Host "  現有資料庫：$($stats.cveCount.ToString('N0')) CVEs / $($stats.affectedCount.ToString('N0')) 受影響記錄"
    if ($ForceUpdate) {
        $update = $true
    } else {
        $ans    = (Read-Host '  是否更新資料庫？[y/N]').Trim().ToLower()
        $update = ($ans -eq 'y')
    }
    if ($update) {
        $years = Select-NvdYears
        Write-Host "  開始更新 $($years.Count) 個年份的資料..."
        Invoke-NvdDownload -DownloadYears $years -DbPath $DbPath -DoReset $true
    } else {
        Write-Host '  略過更新，使用現有資料庫。'
    }
}

# ===========================================================================
# CPE / 版本比對（CVE 掃描用）
# ===========================================================================

function _Normalize-CpeName {
    <#
    .SYNOPSIS 將程式顯示名稱正規化為 CPE product_norm 格式。
    #>
    param([Parameter(Mandatory)][string]$DisplayName)

    $n = $DisplayName.ToLower()
    $n = [regex]::Replace($n, '\s+v?\d[\d._-]+.*$', '')
    $n = [regex]::Replace($n, '[^a-z0-9]+', '_')
    return $n.Trim('_')
}

function _Parse-CveVersion {
    <#
    .SYNOPSIS 將版本字串解析為 [System.Version]；無法解析則回傳 $null。
    #>
    [OutputType([System.Version])]
    param([string]$s)

    if (-not $s -or $s -in @('*', '-', 'N/A', '')) { return $null }
    $c = ($s -replace '^[vV]', '' -replace '[^0-9\.].*$', '' -replace '\.+$', '').Trim()
    if (-not $c -or $c -notmatch '\d') { return $null }
    $parts = ($c -split '\.') | Where-Object { $_ -match '^\d+$' } | Select-Object -First 4
    if (-not $parts) { return $null }
    $arr = @($parts)
    while ($arr.Count -lt 2) { $arr += '0' }
    try { return [System.Version]($arr -join '.') } catch { return $null }
}

function _Test-CveVersionInRange {
    <#
    .SYNOPSIS 檢查已安裝版本是否落在 CVE 受影響版本範圍內。
    .OUTPUTS [bool]
    #>
    [OutputType([bool])]
    param(
        [string]$Installed,
        [string]$Exact,
        [string]$VStart,
        [string]$VEnd
    )

    $iv = _Parse-CveVersion $Installed
    if ($null -eq $iv) { return $true }   # 無法比對則保守地視為受影響

    if ($Exact -and $Exact -notin @('*', '-', '')) {
        $ev = _Parse-CveVersion $Exact
        if ($null -ne $ev) { return ($iv -eq $ev) }
        return $true
    }
    $ok = $true
    if ($VStart) { $sv = _Parse-CveVersion $VStart; if ($sv) { $ok = $ok -and ($iv -ge $sv) } }
    if ($VEnd)   { $ev = _Parse-CveVersion $VEnd;   if ($ev) { $ok = $ok -and ($iv -lt $ev) } }
    return $ok
}

# ===========================================================================
# Repology 最新版本查詢（8 執行緒並行）
# ===========================================================================

function _Normalize-RepologyName {
    <#
    .SYNOPSIS 將程式顯示名稱正規化為 Repology 查詢格式。
    #>
    param([Parameter(Mandatory)][string]$DisplayName)

    $n = $DisplayName.ToLower()
    $n = $n -replace '\s+[\d].*$', ''
    $n = $n -replace '[^a-z0-9\-]', '-'
    $n = $n -replace '-+', '-'
    $n = $n -replace '^-|-$', ''
    return $n
}

function Get-LatestVersions {
    <#
    .SYNOPSIS 並行查詢 Repology，回傳各程式的最新版本。
    .OUTPUTS hashtable { displayName -> latestVersion }
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object[]]$Programs,
        [int]$Threads = 8
    )

    $repToDisp = @{}; $dispToRep = @{}
    foreach ($p in $Programs) {
        $dn = if ($p.'名稱 / Name') { [string]$p.'名稱 / Name' }
              else                  { [string]$p.'軟體名稱 / Software' }
        $rn = _Normalize-RepologyName $dn
        if ($rn -and -not $repToDisp.ContainsKey($rn)) { $repToDisp[$rn] = $dn }
        $dispToRep[$dn] = $rn
    }
    $uniqueRep = @($repToDisp.Keys)
    if ($uniqueRep.Count -eq 0) { return @{} }

    Write-Host "  查詢最新版本（Repology）$($uniqueRep.Count) 個軟體..." -ForegroundColor Cyan

    $fetchScript = {
        param([string]$rn)
        try {
            $res = Invoke-RestMethod -Uri "https://repology.org/api/v1/project/$rn" `
                   -TimeoutSec 6 -Headers @{ 'User-Agent' = 'pcscan/1.0' } -ErrorAction Stop
            $v   = @($res | Where-Object { $_.status -eq 'newest' }) |
                   Select-Object -ExpandProperty version -First 1
            if ($v) { return [string]$v } else { return '' }
        } catch { return '' }
    }

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()
    $jobs = foreach ($rn in $uniqueRep) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($fetchScript).AddArgument($rn)
        @{ PS = $ps; Handle = $ps.BeginInvoke(); RepName = $rn }
    }

    $repVersions = @{}; $done = 0
    foreach ($job in $jobs) {
        $raw = $job.PS.EndInvoke($job.Handle)
        $repVersions[$job.RepName] = if ($raw.Count -gt 0) { [string]$raw[0] } else { '' }
        $job.PS.Dispose(); $done++
        if ($done % 50 -eq 0) { Write-Host "    $done / $($uniqueRep.Count)" -ForegroundColor Gray }
    }
    $pool.Close(); $pool.Dispose()

    $result = @{}
    foreach ($p in $Programs) {
        $dn = if ($p.'名稱 / Name') { [string]$p.'名稱 / Name' }
              else                  { [string]$p.'軟體名稱 / Software' }
        $rn = $dispToRep[$dn]
        $result[$dn] = if ($rn -and $repVersions.ContainsKey($rn)) { $repVersions[$rn] } else { '' }
    }
    return $result
}

# ===========================================================================
# 程式清單與網路（共用）
# ===========================================================================

function Get-InstalledPrograms {
    if ($IsWin) {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        return $paths | ForEach-Object {
            Get-ItemProperty $_ -ErrorAction SilentlyContinue
        } | Where-Object { $_.DisplayName } |
          Sort-Object DisplayName -Unique |
          ForEach-Object {
            [PSCustomObject]@{
                '名稱 / Name'        = $_.DisplayName
                '版本 / Version'     = if ($_.DisplayVersion) { $_.DisplayVersion } else { '' }
                '發行者 / Publisher'  = if ($_.Publisher) { $_.Publisher } else { '' }
            }
        }
    } else {
        $dq = (& dpkg-query -W '-f=${Package}\t${Version}\t${Maintainer}\n' 2>$null)
        if ($dq) {
            return $dq | ForEach-Object {
                $p = $_ -split '\t'
                [PSCustomObject]@{
                    '名稱 / Name'        = if ($p.Count -gt 0) { $p[0] } else { '' }
                    '版本 / Version'     = if ($p.Count -gt 1) { $p[1] } else { '' }
                    '發行者 / Publisher'  = if ($p.Count -gt 2) { $p[2] } else { '' }
                }
            }
        }
        $rq = (& rpm -qa '--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>$null)
        if ($rq) {
            return $rq | ForEach-Object {
                $p = $_ -split '\t'
                [PSCustomObject]@{
                    '名稱 / Name'        = if ($p.Count -gt 0) { $p[0] } else { '' }
                    '版本 / Version'     = if ($p.Count -gt 1) { $p[1] } else { '' }
                    '發行者 / Publisher'  = if ($p.Count -gt 2) { $p[2] } else { '' }
                }
            }
        }
        return @([PSCustomObject]@{ '名稱 / Name' = 'N/A'; '版本 / Version' = ''; '發行者 / Publisher' = '' })
    }
}

function Get-LocalIPv4 {
    $hn = [System.Net.Dns]::GetHostName()
    foreach ($a in [System.Net.Dns]::GetHostAddresses($hn)) {
        if ($a.AddressFamily -eq 'InterNetwork' -and -not $a.ToString().StartsWith('127.')) {
            return $a.ToString()
        }
    }
    return 'Unknown'
}

# ===========================================================================
# CVE 詳細報告輸出（共用）
# ===========================================================================

function Invoke-CveScan {
    <#
    .SYNOPSIS 對已安裝程式執行 CVE 比對，回傳結果清單。
    #>
    param(
        [Parameter(Mandatory)][object[]]$Programs,
        [Parameter(Mandatory)][string]$DbPath,
        [double]$MinScore = 0.0
    )

    $cs  = "Data Source=$([IO.Path]::GetFullPath($DbPath));Read Only=True"
    $con = New-Object System.Data.SQLite.SQLiteConnection($cs)
    $con.Open()
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($prog in $Programs) {
        $name    = [string]$prog.'名稱 / Name'
        $version = [string]$prog.'版本 / Version'
        $kw      = _Normalize-CpeName $name
        if ($kw.Length -lt 3) { continue }

        $cmd = $con.CreateCommand()
        $cmd.CommandText = @"
SELECT c.id, c.score, c.severity, c.description,
       a.version_exact, a.version_start, a.version_end
FROM   affected a
JOIN   cve c ON a.cve_id = c.id
WHERE  a.product_norm = @kw
  AND  (c.score IS NULL OR c.score >= @ms)
  AND  (a.target_sw IS NULL OR a.target_sw IN ('*', '-', '') OR a.target_sw LIKE 'windows%')
ORDER  BY c.score DESC
"@
        $null = $cmd.Parameters.AddWithValue('@kw', $kw)
        $null = $cmd.Parameters.AddWithValue('@ms', $MinScore)
        $rdr  = $cmd.ExecuteReader()
        $seen = [System.Collections.Generic.HashSet[string]]::new()

        while ($rdr.Read()) {
            $cid = $rdr.GetString(0)
            if ($seen.Contains($cid)) { continue }
            $ex  = if ($rdr.IsDBNull(4)) { '' } else { $rdr.GetString(4) }
            $vs  = if ($rdr.IsDBNull(5)) { '' } else { $rdr.GetString(5) }
            $ve  = if ($rdr.IsDBNull(6)) { '' } else { $rdr.GetString(6) }
            if (-not (_Test-CveVersionInRange -Installed $version -Exact $ex -VStart $vs -VEnd $ve)) { continue }
            $null = $seen.Add($cid)

            $score = if ($rdr.IsDBNull(1)) { 'N/A' } else { $rdr.GetDouble(1) }
            $sev   = if ($rdr.IsDBNull(2)) { 'N/A' } else { $rdr.GetString(2) }
            $desc  = if ($rdr.IsDBNull(3)) { '' }    else { $rdr.GetString(3) }
            if ($desc.Length -gt 300) { $desc = $desc.Substring(0, 300) }

            $p = @()
            if ($vs) { $p += ">= $vs" }
            if ($ve) { $p += "< $ve" }
            $range = if ($ex -and $ex -notin @('*', '-', '')) { "= $ex" }
                     elseif ($p) { $p -join ' 且 ' }
                     else { '所有版本' }

            $results.Add([PSCustomObject]@{
                '軟體名稱 / Software'    = $name
                '已安裝版本 / Version'   = $version
                '最新版本 / Latest'      = ''
                'CVE ID'                 = $cid
                'CVSS 分數 / Score'      = $score
                '嚴重等級 / Severity'    = $sev
                '受影響版本範圍 / Range' = $range
                '描述 / Description'     = $desc
            })
        }
        $rdr.Close()
    }
    $con.Close()

    return @($results | Sort-Object {
        $s = $_.'CVSS 分數 / Score'
        if ($s -is [double]) { $s } else { 0.0 }
    } -Descending)
}

$_CVE_FIELDS   = @(
    '軟體名稱 / Software', '已安裝版本 / Version', '最新版本 / Latest',
    'CVE ID', 'CVSS 分數 / Score', '嚴重等級 / Severity',
    '受影響版本範圍 / Range', '描述 / Description'
)
$_CVE_SEV_ROW   = @{ CRITICAL='table-danger'; HIGH='table-warning'; MEDIUM='table-info'; LOW='table-success' }
$_CVE_SEV_BADGE = @{ CRITICAL='bg-danger'; HIGH='bg-warning text-dark'; MEDIUM='bg-info text-dark'; LOW='bg-success' }

function Export-CveCsv {
    <#
    .SYNOPSIS 將 CVE 掃描結果匯出為 CSV 檔。
    #>
    param([Parameter(Mandatory)][object[]]$Results, [Parameter(Mandatory)][string]$OutPath)
    $enc = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    $Results | Select-Object -Property $_CVE_FIELDS | Export-Csv -Path $OutPath -NoTypeInformation -Encoding $enc
    Write-Host "  CSV  ：$OutPath"
}

function Export-CveHtml {
    <#
    .SYNOPSIS 將 CVE 掃描結果匯出為獨立 HTML 報告。
    #>
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$LocalIp,
        [Parameter(Mandatory)][hashtable]$DbStats,
        [Parameter(Mandatory)][string]$OutPath
    )

    Add-Type -AssemblyName System.Web
    $scanTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $counts   = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($r in $Results) {
        $s = ([string]$r.'嚴重等級 / Severity').ToUpper()
        if ($counts.ContainsKey($s)) { $counts[$s]++ }
    }
    $total = $Results.Count

    $L = [System.Collections.Generic.List[string]]::new()
    function _Ha([string]$line) { $L.Add($line) }
    function _He([string]$s) { [System.Web.HttpUtility]::HtmlEncode($s) }

    _Ha "<!DOCTYPE html>"
    _Ha "<html lang='zh-Hant'><head>"
    _Ha "<meta charset='UTF-8'>"
    _Ha "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    _Ha "<title>CVE 風險報告 — $(_He $ComputerName)</title>"
    _Ha "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>"
    _Ha "<style>"
    _Ha "body { padding-top: 4.5rem; }"
    _Ha "th   { cursor: pointer; white-space: nowrap; user-select: none; }"
    _Ha "th:hover { background: rgba(255,255,255,.15); }"
    _Ha ".desc-cell { max-width: 380px; font-size: .85em; word-break: break-word; }"
    _Ha "</style></head><body>"

    _Ha "<nav class='navbar navbar-expand-lg navbar-dark bg-dark fixed-top'>"
    _Ha "  <div class='container-fluid'>"
    _Ha "  <span class='navbar-brand'>&#x1F6E1; CVE 風險報告 &mdash; $(_He $ComputerName)</span>"
    _Ha "  </div></nav>"

    _Ha "<div class='container-xl mt-4 mb-5'>"

    # Info card
    _Ha "<div class='card mb-3 border-0 shadow-sm'><div class='card-body'><div class='row g-3'>"
    foreach ($kv in @(@('主機名稱', $ComputerName), @('IP 位址', $LocalIp), @('掃描時間', $scanTime))) {
        _Ha "<div class='col-md-3'><small class='text-muted d-block'>$(_He $kv[0])</small><strong>$(_He $kv[1])</strong></div>"
    }
    _Ha "<div class='col-md-3'><small class='text-muted d-block'>NVD 資料庫</small>$($DbStats['cveCount'].ToString('N0')) CVEs / $($DbStats['affectedCount'].ToString('N0')) 受影響記錄</div>"
    _Ha "</div></div></div>"

    # Severity summary
    _Ha "<div class='mb-3'>"
    if ($total -eq 0) {
        _Ha "<div class='alert alert-success mb-0'>&#x2705; 未發現任何已知 CVE 風險。</div>"
    } else {
        foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
            $cnt = $counts[$sev]
            if ($cnt -gt 0) { _Ha "<span class='badge $($_CVE_SEV_BADGE[$sev]) fs-6 me-2 mb-1'>${sev}: $cnt</span>" }
        }
        _Ha "<span class='text-muted'>共 $total 筆</span>"
    }
    _Ha "</div>"

    if ($total -gt 0) {
        # Filter controls
        _Ha "<div class='row g-2 mb-3 align-items-center'>"
        _Ha "  <div class='col-auto'><input id='kwFilter' class='form-control' style='min-width:220px' placeholder='搜尋軟體名稱 / CVE ID…' oninput='applyFilters()'></div>"
        _Ha "  <div class='col-auto'><select id='sevFilter' class='form-select' onchange='applyFilters()'>"
        _Ha "    <option value=''>全部嚴重等級</option>"
        foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) { _Ha "    <option value='$sev'>$sev</option>" }
        _Ha "  </select></div>"
        _Ha "  <div class='col-auto'><span id='rowCount' class='text-muted small'></span></div>"
        _Ha "</div>"

        # Table
        _Ha "<div class='table-responsive'>"
        _Ha "<table class='table table-bordered table-hover table-sm align-middle' id='cveTable' data-sort-col='-1' data-sort-asc='1'>"
        _Ha "<thead class='table-dark'><tr>"
        for ($i = 0; $i -lt $_CVE_FIELDS.Count; $i++) {
            _Ha "<th onclick='sortTable($i)'>$(_He $_CVE_FIELDS[$i]) &#x21C5;</th>"
        }
        _Ha "</tr></thead><tbody id='cveBody'>"
        foreach ($r in $Results) {
            $sev      = ([string]$r.'嚴重等級 / Severity').ToUpper()
            $rowClass = if ($_CVE_SEV_ROW.ContainsKey($sev)) { $_CVE_SEV_ROW[$sev] } else { '' }
            _Ha "<tr class='$rowClass'>"
            foreach ($fld in $_CVE_FIELDS) {
                $val = [string]$r.$fld
                if ($fld -eq '描述 / Description') {
                    _Ha "<td class='desc-cell'>$(_He $val)</td>"
                } elseif ($fld -eq '最新版本 / Latest') {
                    $inst = [string]$r.'已安裝版本 / Version'
                    if (-not $val)         { _Ha "<td><span class='text-muted'>—</span></td>" }
                    elseif ($inst -eq $val){ _Ha "<td><span class='text-success fw-bold'>$(_He $val)</span></td>" }
                    else                   { _Ha "<td><span class='text-warning fw-bold'>$(_He $val) &#x2B06;</span></td>" }
                } else {
                    _Ha "<td>$(_He $val)</td>"
                }
            }
            _Ha "</tr>"
        }
        _Ha "</tbody></table></div>"
    }

    _Ha @"
<script>
function sortTable(col) {
    const tbl=document.getElementById('cveTable'), tbody=tbl.tBodies[0];
    const rows=Array.from(tbody.rows);
    const asc=(parseInt(tbl.dataset.sortCol)===col)?tbl.dataset.sortAsc!=='1':true;
    rows.sort((a,b)=>{
        const x=a.cells[col]?.textContent.trim()??'';
        const y=b.cells[col]?.textContent.trim()??'';
        const n=parseFloat(x)-parseFloat(y);
        const c=isNaN(n)?x.localeCompare(y,'zh-Hant',{numeric:true}):n;
        return asc?c:-c;
    });
    rows.forEach(r=>tbody.appendChild(r));
    tbl.dataset.sortCol=col; tbl.dataset.sortAsc=asc?'1':'0';
    updateCount();
}
function applyFilters() {
    const kw=document.getElementById('kwFilter').value.toLowerCase();
    const sev=document.getElementById('sevFilter').value.toUpperCase();
    let visible=0;
    document.querySelectorAll('#cveBody tr').forEach(row=>{
        const rowSev=row.cells[5]?.textContent.trim().toUpperCase()??'';
        const show=row.textContent.toLowerCase().includes(kw)&&(!sev||rowSev===sev);
        row.style.display=show?'':'none';
        if(show)visible++;
    });
    const el=document.getElementById('rowCount');
    if(el)el.textContent='顯示 '+visible+' 筆';
}
function updateCount(){
    const visible=Array.from(document.querySelectorAll('#cveBody tr')).filter(r=>r.style.display!=='none').length;
    const el=document.getElementById('rowCount');
    if(el)el.textContent='顯示 '+visible+' 筆';
}
document.addEventListener('DOMContentLoaded',updateCount);
</script>
"@
    _Ha "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>"
    _Ha "</body></html>"

    [System.IO.File]::WriteAllText($OutPath, ($L -join "`n"), [System.Text.Encoding]::UTF8)
    Write-Host "  HTML ：$OutPath"
}

# ===========================================================================
# CPE 2.3 輸出（VANS 需求）
# ===========================================================================

function _Normalize-CpeComponent {
    param([string]$Value)
    if (-not $Value -or -not $Value.Trim()) { return '*' }
    $v = $Value.ToLower().Trim()
    $v = [regex]::Replace($v, '[^a-z0-9._\-]+', '_')
    $v = [regex]::Replace($v, '_+', '_').Trim('_')
    return $(if ($v) { $v } else { '*' })
}

function _Normalize-CpeProduct {
    param([string]$Name)
    if (-not $Name -or -not $Name.Trim()) { return '*' }
    $n = $Name.ToLower().Trim()
    # 去除結尾版本號（如 "Firefox 125.0" 中的 " 125.0"）
    $n = [regex]::Replace($n, '\s+v?\d[\d.\-_]*\s*$', '').Trim()
    $n = [regex]::Replace($n, '[^a-z0-9._\-]+', '_')
    $n = [regex]::Replace($n, '_+', '_').Trim('_')
    return $(if ($n) { $n } else { '*' })
}

function _Normalize-CpeVersion {
    param([string]$Value)
    if (-not $Value -or -not $Value.Trim()) { return '*' }
    $v = [regex]::Replace($Value.Trim(), '[^a-zA-Z0-9._\-]+', '_').Trim('_')
    return $(if ($v) { $v } else { '*' })
}

function New-Cpe23String {
    <#
    .SYNOPSIS 將一筆已安裝程式轉換為 CPE 2.3 格式字串。
    #>
    param(
        [string]$Name,
        [string]$Version,
        [string]$Publisher
    )
    $vendor  = _Normalize-CpeComponent $Publisher
    $product = _Normalize-CpeProduct   $Name
    $ver     = _Normalize-CpeVersion   $Version
    return "cpe:2.3:a:${vendor}:${product}:${ver}:*:*:*:*:*:*:*"
}

function Export-Cpe23 {
    <#
    .SYNOPSIS 將已安裝程式清單匯出為 CPE 2.3 格式文字檔（VANS 需求）。
    .DESCRIPTION 每行一筆 CPE 2.3 字串，可直接匯入 VANS 平台。
    #>
    param(
        [Parameter(Mandatory)][object[]]$Programs,
        [Parameter(Mandatory)][string]$OutPath
    )
    $lines = foreach ($p in $Programs) {
        New-Cpe23String `
            -Name      ([string]$p.'名稱 / Name') `
            -Version   ([string]$p.'版本 / Version') `
            -Publisher ([string]$p.'發行者 / Publisher')
    }
    [System.IO.File]::WriteAllLines($OutPath, $lines, [System.Text.Encoding]::UTF8)
    Write-Host "  CPE23：$OutPath"
}
