#Requires -Version 5.1
<#
.SYNOPSIS
    PC Info Scanner - PowerShell version
    Supports Windows PowerShell 5.1+ and PowerShell Core 7+ (including Linux)
.EXAMPLE
    .\getPcInfo.ps1
    .\getPcInfo.ps1 -OutputDir "C:\Reports"
#>
[CmdletBinding()]
param([string]$OutputDir = "")

# UTF-8 output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Platform detection (PS 5.1 compatible)
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $IsWin = ($IsWindows -eq $true)
} else {
    $IsWin = $true
}

Add-Type -AssemblyName System.Web

# ===========================================================================
# Helper functions
# ===========================================================================

function Get-LocalIPv4 {
    # 回傳第一個非 127.x IPv4（用於資料夾/ZIP 命名）
    $hn = [System.Net.Dns]::GetHostName()
    foreach ($a in [System.Net.Dns]::GetHostAddresses($hn)) {
        if ($a.AddressFamily -eq 'InterNetwork' -and -not $a.ToString().StartsWith('127.')) {
            return $a.ToString()
        }
    }
    return 'Unknown'
}

function Get-AllLocalIPv4 {
    # 回傳所有非 127.x / 169.254.x IPv4，以逗號分隔
    $ips = @()
    $hn = [System.Net.Dns]::GetHostName()
    foreach ($a in [System.Net.Dns]::GetHostAddresses($hn)) {
        $s = $a.ToString()
        if ($a.AddressFamily -eq 'InterNetwork' -and
            -not $s.StartsWith('127.') -and
            -not $s.StartsWith('169.254.')) {
            $ips += $s
        }
    }
    if ($ips.Count -eq 0) { return 'Unknown' }
    return $ips -join ', '
}

function Esc([string]$s) {
    return [System.Web.HttpUtility]::HtmlEncode($s)
}

function Nz([object]$v) {
    if ($null -eq $v) { return '' }
    return $v.ToString()
}

# Build HTML table from PSObject array
function To-HtmlTable {
    param([object[]]$Data, [string]$Id)
    if (-not $Data -or $Data.Count -eq 0) { return '<p>No data</p>' }
    $cols = $Data[0].PSObject.Properties.Name
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<div class="table-responsive"><table id="')
    $null = $sb.Append($Id)
    $null = $sb.Append('" class="table table-bordered table-striped table-hover table-sm"><thead class="table-dark"><tr>')
    $ci = 0
    foreach ($c in $cols) {
        $null = $sb.Append('<th onclick="sortTable(''')
        $null = $sb.Append($Id)
        $null = $sb.Append(''',')
        $null = $sb.Append($ci)
        $null = $sb.Append(')">')
        $null = $sb.Append((Esc $c))
        $null = $sb.Append('</th>')
        $ci++
    }
    $null = $sb.Append('</tr></thead><tbody>')
    foreach ($row in $Data) {
        $null = $sb.Append('<tr>')
        foreach ($c in $cols) {
            $null = $sb.Append('<td>')
            $null = $sb.Append((Esc (Nz $row.$c)))
            $null = $sb.Append('</td>')
        }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function To-HtmlSection {
    param([string]$Title, [object[]]$Data, [string]$Id)
    $tbl = To-HtmlTable -Data $Data -Id $Id
    $t = Esc $Title
    return "<div class=`"section`" id=`"$Id`"><h2>$t</h2>$tbl</div>"
}

# ===========================================================================
# Data collectors
# ===========================================================================

function Get-SysInfo {
    if ($IsWin) {
        $osStr = [System.Environment]::OSVersion.VersionString
    } else {
        $osStr = (& uname -sr 2>$null) -join ' '
    }
    $hn = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    return @(
        [PSCustomObject]@{ 'Item' = 'Hostname / Zhu-ji-mingcheng';   'Content' = $hn }
        [PSCustomObject]@{ 'Item' = 'Local IP';                       'Content' = (Get-AllLocalIPv4) }
        [PSCustomObject]@{ 'Item' = 'OS';                             'Content' = $osStr }
        [PSCustomObject]@{ 'Item' = 'Architecture';                   'Content' = $arch }
        [PSCustomObject]@{ 'Item' = 'PowerShell Version';             'Content' = $PSVersionTable.PSVersion.ToString() }
    )
}

# Chinese bilingual wrappers
function Get-SystemInfo {
    $raw = Get-SysInfo
    return $raw | ForEach-Object {
        $map = @{
            'Hostname / Zhu-ji-mingcheng' = '主機名稱 / Hostname'
            'Local IP'                     = '區網 IP / Local IP'
            'OS'                           = '作業系統 / OS'
            'Architecture'                 = '架構 / Architecture'
            'PowerShell Version'           = 'PowerShell 版本'
        }
        [PSCustomObject]@{
            '項目 / Item'   = if ($map.ContainsKey($_.Item)) { $map[$_.Item] } else { $_.Item }
            '內容 / Content' = $_.Content
        }
    }
}

function Get-AntivirusInfo {
    if ($IsWin) {
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            return @([PSCustomObject]@{
                '產品版本 / AMProductVersion'                 = Nz $s.AMProductVersion
                '服務版本 / AMServiceVersion'                 = Nz $s.AMServiceVersion
                '防間諜簽章版本 / AntispywareSignatureVersion' = Nz $s.AntispywareSignatureVersion
                '防毒簽章版本 / AntivirusSignatureVersion'     = Nz $s.AntivirusSignatureVersion
            })
        } catch {
            return @([PSCustomObject]@{
                '產品版本 / AMProductVersion'                 = 'N/A'
                '服務版本 / AMServiceVersion'                 = ''
                '防間諜簽章版本 / AntispywareSignatureVersion' = ''
                '防毒簽章版本 / AntivirusSignatureVersion'     = ''
            })
        }
    } else {
        $cv = (& clamscan --version 2>$null | Select-Object -First 1)
        $fv = (& freshclam --version 2>$null | Select-Object -First 1)
        return @([PSCustomObject]@{
            '防毒軟體 / Antivirus'           = if ($cv) { 'ClamAV' } else { '未安裝 / Not Installed' }
            '版本 / Version'                 = if ($cv) { $cv } else { 'N/A' }
            '病毒碼版本 / Signature Version'  = if ($fv) { $fv } else { 'N/A' }
        })
    }
}

function Get-InstalledUpdates {
    if ($IsWin) {
        try {
            return Get-HotFix -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    '更新編號 / HotFixID'    = Nz $_.HotFixID
                    '描述 / Description'     = Nz $_.Description
                    '安裝日期 / InstalledOn'  = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
                }
            }
        } catch {
            return @([PSCustomObject]@{ '更新編號 / HotFixID' = 'N/A'; '描述 / Description' = ''; '安裝日期 / InstalledOn' = '' })
        }
    } else {
        if (Test-Path '/var/log/dpkg.log') {
            $lines = Get-Content '/var/log/dpkg.log' -ErrorAction SilentlyContinue |
                     Where-Object { $_ -match ' upgrade | install ' } |
                     Select-Object -Last 100
            if ($lines) {
                return $lines | ForEach-Object {
                    $p = $_ -split '\s+', 4
                    [PSCustomObject]@{
                        '日期 / Date'    = if ($p.Count -gt 0) { $p[0] } else { '' }
                        '時間 / Time'    = if ($p.Count -gt 1) { $p[1] } else { '' }
                        '動作 / Action'  = if ($p.Count -gt 2) { $p[2] } else { '' }
                        '套件 / Package' = if ($p.Count -gt 3) { $p[3] } else { '' }
                    }
                }
            }
        }
        $yo = (& yum history list 2>$null)
        if ($yo) {
            return $yo | Where-Object { $_ -match '^\s*\d+' } | Select-Object -First 50 | ForEach-Object {
                $cols = $_ -split '\|'
                [PSCustomObject]@{
                    'ID'                   = $cols[0].Trim()
                    '指令 / Command'        = if ($cols.Count -gt 1) { $cols[1].Trim() } else { '' }
                    '日期時間 / DateTime'   = if ($cols.Count -gt 2) { $cols[2].Trim() } else { '' }
                    '動作 / Action'         = if ($cols.Count -gt 3) { $cols[3].Trim() } else { '' }
                }
            }
        }
        return @([PSCustomObject]@{ '資訊 / Info' = 'Cannot retrieve (requires dpkg or yum)' })
    }
}

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

function Get-LocalUserAccounts {
    if ($IsWin) {
        try {
            return Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    '帳號名稱 / Username' = $_.Name
                    '全名 / FullName'     = if ($_.FullName) { $_.FullName } else { '' }
                    '描述 / Description'  = if ($_.Description) { $_.Description } else { '' }
                    '是否啟用 / Enabled'   = if ($_.Enabled) { '啟用 / Enabled' } else { '停用 / Disabled' }
                    '最後登入 / LastLogon' = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '從未 / Never' }
                }
            }
        } catch {
            return Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
                [PSCustomObject]@{
                    '帳號名稱 / Username' = Nz $_.Name
                    '全名 / FullName'     = ''
                    '描述 / Description'  = Nz $_.Description
                    '是否啟用 / Enabled'   = if ($_.Disabled) { '停用 / Disabled' } else { '啟用 / Enabled' }
                    '最後登入 / LastLogon' = ''
                }
            }
        }
    } else {
        $pw = Get-Content '/etc/passwd' -ErrorAction SilentlyContinue
        if (-not $pw) {
            return @([PSCustomObject]@{ '帳號名稱 / Username' = 'N/A'; 'UID' = ''; '描述 / Description' = ''; 'Shell' = '' })
        }
        return $pw | ForEach-Object {
            $p = $_ -split ':'
            if ($p.Count -lt 7) { return }
            $uid = if ($p[2] -match '^\d+$') { [int]$p[2] } else { -1 }
            if ($uid -ge 1000 -or $p[0] -eq 'root') {
                [PSCustomObject]@{
                    '帳號名稱 / Username' = $p[0]
                    'UID'                 = $p[2]
                    '群組 / GID'          = $p[3]
                    '描述 / Description'  = $p[4]
                    'Shell'               = $p[6].Trim()
                }
            }
        } | Where-Object { $null -ne $_ }
    }
}

function Get-PasswordPolicy {
    if ($IsWin) {
        $raw = (& net accounts 2>&1)
        return $raw | Where-Object { $_ -match ':' } | ForEach-Object {
            $p = $_ -split ':', 2
            if ($p.Count -eq 2) {
                [PSCustomObject]@{ '設定 / Setting' = $p[0].Trim(); '值 / Value' = $p[1].Trim() }
            }
        } | Where-Object { $null -ne $_ }
    } else {
        $ld = Get-Content '/etc/login.defs' -ErrorAction SilentlyContinue
        if (-not $ld) {
            return @([PSCustomObject]@{ '設定 / Setting' = 'N/A'; '值 / Value' = 'Cannot retrieve' })
        }
        $kw = 'PASS_MAX_DAYS','PASS_MIN_DAYS','PASS_MIN_LEN','PASS_WARN_AGE',
              'LOGIN_RETRIES','LOGIN_TIMEOUT','ENCRYPT_METHOD'
        return $ld | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } | ForEach-Object {
            $p = $_ -split '\s+', 2
            if ($p.Count -eq 2 -and $kw -contains $p[0]) {
                [PSCustomObject]@{ '設定 / Setting' = $p[0].Trim(); '值 / Value' = $p[1].Trim() }
            }
        } | Where-Object { $null -ne $_ }
    }
}

function Get-NetworkSettings {
    if ($IsWin) {
        try {
            return Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                $dns = ($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                        ForEach-Object { $_.ServerAddresses }) -join ', '
                $gw  = ($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
                $ip  = ($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', '
                # Prefix length to subnet mask
                $mask = ($_.IPv4Address | ForEach-Object {
                    $pl = $_.PrefixLength
                    (0..3 | ForEach-Object {
                        $b = [Math]::Min(8, [Math]::Max(0, $pl - $_ * 8))
                        [int]([Math]::Pow(2,8) - [Math]::Pow(2, 8-$b))
                    }) -join '.'
                }) -join ', '
                [PSCustomObject]@{
                    '介面名稱 / Interface'    = $_.InterfaceAlias
                    'IP 位址 / IP Address'    = $ip
                    '子網遮罩 / Subnet Mask'   = $mask
                    'DNS 伺服器 / DNS Server'  = if ($dns) { $dns } else { 'N/A' }
                    '預設閘道 / Gateway'       = $gw
                }
            }
        } catch {
            return Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
                [PSCustomObject]@{
                    '介面名稱 / Interface'    = Nz $_.Description
                    'IP 位址 / IP Address'    = ($_.IPAddress -join ', ')
                    '子網遮罩 / Subnet Mask'   = ($_.IPSubnet -join ', ')
                    'DNS 伺服器 / DNS Server'  = if ($_.DNSServerSearchOrder) { $_.DNSServerSearchOrder -join ', ' } else { 'N/A' }
                    '預設閘道 / Gateway'       = ($_.DefaultIPGateway -join ', ')
                }
            }
        }
    } else {
        $aj = (& ip -j addr 2>$null) -join ''
        $rj = (& ip -j route 2>$null) -join ''
        $rv = Get-Content '/etc/resolv.conf' -ErrorAction SilentlyContinue
        $dns = ($rv | Where-Object { $_ -match '^nameserver\s' } |
                ForEach-Object { ($_ -split '\s+')[1] }) -join ', '
        if (-not $dns) { $dns = 'N/A' }
        $gw = @{}
        try {
            $routes = $rj | ConvertFrom-Json
            foreach ($r in $routes) {
                if ($r.dst -eq 'default' -and $r.gateway) { $gw[$r.dev] = $r.gateway }
            }
        } catch {}
        try {
            return ($aj | ConvertFrom-Json) | ForEach-Object {
                $nm = $_.ifname
                $ipv4 = ($_.addr_info | Where-Object { $_.family -eq 'inet' } |
                         ForEach-Object { "$($_.local)/$($_.prefixlen)" }) -join ', '
                [PSCustomObject]@{
                    '介面名稱 / Interface'    = $nm
                    'IP 位址 / IP Address'    = if ($ipv4) { $ipv4 } else { 'N/A' }
                    '子網遮罩 / Subnet Mask'   = '(See CIDR)'
                    'DNS 伺服器 / DNS Server'  = $dns
                    '預設閘道 / Gateway'       = if ($gw.ContainsKey($nm)) { $gw[$nm] } else { '' }
                }
            }
        } catch {
            return @([PSCustomObject]@{
                '介面名稱 / Interface'    = 'N/A'
                'IP 位址 / IP Address'    = ''
                '子網遮罩 / Subnet Mask'   = ''
                'DNS 伺服器 / DNS Server'  = $dns
                '預設閘道 / Gateway'       = ''
            })
        }
    }
}

function Get-OsDetails {
    if ($IsWin) {
        try {
            $o = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
            return @([PSCustomObject]@{
                '作業系統名稱 / OS Name'   = Nz $o.Caption
                '版本號 / Version'         = Nz $o.Version
                '建置編號 / Build Number'  = Nz $o.BuildNumber
                '架構 / Architecture'      = Nz $o.OSArchitecture
                '最後開機 / Last Boot'     = $o.ConvertToDateTime($o.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss')
            })
        } catch {
            return @([PSCustomObject]@{ '作業系統名稱 / OS Name' = 'N/A'; '版本號 / Version' = ''; '建置編號 / Build Number' = ''; '架構 / Architecture' = ''; '最後開機 / Last Boot' = '' })
        }
    } else {
        $or = Get-Content '/etc/os-release' -ErrorAction SilentlyContinue
        $d  = [ordered]@{}
        if ($or) {
            foreach ($k in @('NAME','VERSION','ID','VERSION_ID','PRETTY_NAME')) {
                $ln = $or | Where-Object { $_ -match "^${k}=" } | Select-Object -First 1
                if ($ln) { $d[$k] = ($ln -replace "^${k}=", '').Trim('"') }
            }
        }
        $kr = (& uname -r 2>$null | Select-Object -First 1)
        if ($kr) { $d['KERNEL'] = $kr.Trim() }
        return ($d.Keys | ForEach-Object { [PSCustomObject]@{ '設定 / Key' = $_; '值 / Value' = $d[$_] } })
    }
}

# ===========================================================================
# HTML Report Builder
# ===========================================================================
function New-HtmlReport {
    param(
        [string]$ComputerName,
        [string]$LocalIP,
        [object[]]$SysInfo,
        [object[]]$OsInfo,
        [object[]]$AV,
        [object[]]$Updates,
        [object[]]$Programs,
        [object[]]$Users,
        [object[]]$Policy,
        [object[]]$Network
    )

    $scanTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $platform = if ($IsWin) { 'Windows' } else { 'Linux' }
    $avLabel  = if ($IsWin) { 'Windows Defender' } else { '防毒資訊 / Antivirus' }

    $s1 = To-HtmlSection -Title '系統基本資訊 / System Info'  -Data $SysInfo   -Id 'sysinfo'
    $s2 = To-HtmlSection -Title '作業系統詳細 / OS Details'   -Data $OsInfo    -Id 'osdetail'
    $s3 = To-HtmlSection -Title $avLabel                       -Data $AV        -Id 'antivirus'
    $s4 = To-HtmlSection -Title '已安裝更新 / Updates'        -Data $Updates   -Id 'updates'
    $s5 = To-HtmlSection -Title '已安裝程式 / Programs'       -Data $Programs  -Id 'programs'
    $s6 = To-HtmlSection -Title '使用者帳號 / Users'          -Data $Users     -Id 'users'
    $s7 = To-HtmlSection -Title '密碼原則 / Password Policy'  -Data $Policy    -Id 'policy'
    $s8 = To-HtmlSection -Title '網路設定 / Network'          -Data $Network   -Id 'network'

    $titleEsc = Esc "$ComputerName ($LocalIP)"

    $lines = @(
        '<!DOCTYPE html>'
        '<html lang="zh-Hant">'
        '<head>'
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        "<title>System Report - $titleEsc</title>"
        '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">'
        '<style>'
        'body { padding-top: 4.5rem; }'
        '.section { margin-bottom: 40px; }'
        'th { cursor: pointer; user-select: none; }'
        '</style>'
        '</head>'
        '<body>'
        '<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">'
        '  <div class="container-fluid">'
        '    <a class="navbar-brand" href="#">System Info Report</a>'
        '    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMenu"><span class="navbar-toggler-icon"></span></button>'
        '    <div class="collapse navbar-collapse" id="navMenu">'
        '      <ul class="navbar-nav me-auto">'
        '        <li class="nav-item"><a class="nav-link" href="#sysinfo">System</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#osdetail">OS</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#antivirus">Antivirus</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#updates">Updates</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#programs">Programs</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#users">Users</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#policy">Password Policy</a></li>'
        '        <li class="nav-item"><a class="nav-link" href="#network">Network</a></li>'
        '      </ul>'
        '    </div>'
        '  </div>'
        '</nav>'
        '<div class="container">'
        '<h1 class="mb-2 mt-4">System Info Report</h1>'
        "<p class=`"text-muted`">Host: <strong>$(Esc $ComputerName)</strong> | IP: <strong>$(Esc $LocalIP)</strong> | Scanned: $scanTime | Platform: $platform</p>"
        $s1
        $s2
        $s3
        $s4
        $s5
        $s6
        $s7
        $s8
        '</div>'
        '<script>'
        'function sortTable(id,ci){'
        '  var t=document.getElementById(id);if(!t)return;'
        '  var tb=t.tBodies[0];var rows=Array.from(tb.rows);'
        '  var asc=t.dataset.sc==ci&&t.dataset.sd!=="asc";'
        '  rows.sort(function(a,b){'
        '    var x=a.cells[ci]?a.cells[ci].innerText:"";'
        '    var y=b.cells[ci]?b.cells[ci].innerText:"";'
        '    return asc?x.localeCompare(y,"zh-Hant",{numeric:true}):y.localeCompare(x,"zh-Hant",{numeric:true});'
        '  });'
        '  rows.forEach(function(r){tb.appendChild(r);});'
        '  t.dataset.sc=ci;t.dataset.sd=asc?"asc":"desc";'
        '}'
        '</script>'
        '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>'
        '</body>'
        '</html>'
    )
    return $lines -join "`n"
}

# ===========================================================================
# Main
# ===========================================================================
$computerName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
$localIP      = Get-LocalIPv4
$baseName     = "${computerName}_${localIP}"

# 集中存放到腳本同層的 output\ 子目錄
$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputRoot  = Join-Path $scriptDir "output"
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

$outDir  = if ($OutputDir) { $OutputDir } else { Join-Path $outputRoot $baseName }
$zipPath = Join-Path $outputRoot "${baseName}.zip"

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Collecting system info... [$computerName / $localIP]" -ForegroundColor Cyan

$sysInfo  = Get-SystemInfo
$osInfo   = Get-OsDetails
$avInfo   = Get-AntivirusInfo
$updates  = Get-InstalledUpdates
Write-Host "  Done: Updates"
$programs = Get-InstalledPrograms
Write-Host "  Done: Programs"
$users    = Get-LocalUserAccounts
$policy   = Get-PasswordPolicy
$network  = Get-NetworkSettings
Write-Host "  Done: Network"

$html = New-HtmlReport `
    -ComputerName $computerName `
    -LocalIP      $localIP `
    -SysInfo      $sysInfo `
    -OsInfo       $osInfo `
    -AV           $avInfo `
    -Updates      $updates `
    -Programs     $programs `
    -Users        $users `
    -Policy       $policy `
    -Network      $network

$htmlFile = Join-Path $outDir "${baseName}.html"
[System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.Encoding]::UTF8)
Write-Host "Exported to $htmlFile" -ForegroundColor Green

# CSV Export
Write-Host "  Exporting CSV..." -ForegroundColor Cyan
$csvEnc = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$noData = @([PSCustomObject]@{ 'Info' = 'No data' })
$csvSets = @(
    @{ Name = 'SystemInfo';      Data = $sysInfo  }
    @{ Name = 'OSDetails';       Data = $osInfo   }
    @{ Name = 'Antivirus';       Data = $avInfo   }
    @{ Name = 'Updates';         Data = $updates  }
    @{ Name = 'Programs';        Data = $programs }
    @{ Name = 'UserAccounts';    Data = $users    }
    @{ Name = 'PasswordPolicy';  Data = $policy   }
    @{ Name = 'NetworkSettings'; Data = $network  }
)
foreach ($ds in $csvSets) {
    $csvFile = Join-Path $outDir "${baseName}_$($ds.Name).csv"
    $rows = if ($ds.Data -and @($ds.Data).Count -gt 0) { $ds.Data } else { $noData }
    $rows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding $csvEnc
}
Write-Host "  Done: CSV exported" -ForegroundColor Green

# ZIP
Compress-Archive -Path "$outDir\*" -DestinationPath $zipPath -Force
Write-Host "Zipped to $zipPath" -ForegroundColor Green
