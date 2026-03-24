#!/usr/bin/env bash
# ===========================================================================
# getPcInfo.sh  —  PC Info Collection Tool (Bash / Linux)
# Supports Debian/Ubuntu (dpkg/apt) and RHEL/CentOS/Fedora (rpm/yum/dnf)
# Output: HTML report + CSV files, packaged as {hostname}_{IP}.zip
#
# Usage:
#   chmod +x getPcInfo.sh
#   ./getPcInfo.sh
#   ./getPcInfo.sh -o /tmp/reports
# ===========================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Force UTF-8 locale so CJK characters display correctly on any system locale
# Try C.UTF-8 first (most universal); fall back to en_US.UTF-8; keep as-is if none found
# ---------------------------------------------------------------------------
_force_utf8() {
    local loc
    for loc in C.UTF-8 en_US.UTF-8 UTF-8; do
        if locale -a 2>/dev/null | grep -qi "^${loc}$"; then
            export LC_ALL="$loc"
            export LANG="$loc"
            return
        fi
    done
}
_force_utf8
unset -f _force_utf8

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
OUTPUT_DIR=""
while getopts "o:h" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        h)
            echo "用法: $0 [-o 輸出目錄]"
            exit 0
            ;;
        *) echo "未知參數: -$OPTARG" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

# Run a command; return empty string if not found or fails
runCmd() {
    command -v "$1" &>/dev/null && "$@" 2>/dev/null || echo ""
}

# Read a file; return empty string if not readable
readFile() {
    [ -r "$1" ] && cat "$1" 2>/dev/null || echo ""
}

# HTML-escape a string (XSS prevention)
htmlEscape() {
    local str="$1"
    str="${str//&/&amp;}"
    str="${str//</&lt;}"
    str="${str//>/&gt;}"
    str="${str//\"/&quot;}"
    str="${str//\'/&#39;}"
    echo "$str"
}

# Get the first non-127.x IPv4 (used for folder/ZIP naming)
getLocalIp() {
    # Prefer 'ip' command (modern Linux)
    local ip
    ip=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [ -n "$ip" ]; then
        echo "$ip"
        return
    fi
    # Fallback: hostname -I
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$ip" ] && echo "$ip" || echo "未知 / Unknown"
}

# Get all non-127.x / non-169.254.x IPv4s, comma-separated (used for display in report)
getAllLocalIps() {
    local allIps result=""
    allIps=$(hostname -I 2>/dev/null)
    for ip in $allIps; do
        if [[ "$ip" != 127.* && "$ip" != 169.254.* && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            result="${result:+$result, }$ip"
        fi
    done
    [ -n "$result" ] && echo "$result" || echo "未知 / Unknown"
}

# Detect package manager
detectPkgManager() {
    if command -v dpkg-query &>/dev/null; then echo "dpkg"
    elif command -v rpm &>/dev/null; then echo "rpm"
    else echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# CSV Export
# writeTsvAsCsv <file> <header_tsv> <body_tsv>
# Write UTF-8 BOM + CSV (each field double-quoted; internal quotes escaped as "")
# ---------------------------------------------------------------------------
writeTsvAsCsv() {
    local file="$1" header="$2" body="$3"
    printf '\xEF\xBB\xBF' > "$file"
    { printf '%s\n' "$header"; [ -n "$body" ] && printf '%s\n' "$body"; } | \
    awk -F'\t' 'BEGIN{ORS=""} {
        for(i=1;i<=NF;i++){
            v=$i; gsub(/"/,"\"\"",v)
            printf "%s\"%s\"", (i>1?",":""), v
        }
        printf "\r\n"
    }' >> "$file"
}

exportAllCsv() {
    local outDir="$1" base="$2"
    local body

    # 1. System Info
    body="主機名稱 / Hostname	$(hostname 2>/dev/null || echo N/A)"
    body+=$'\n'"區網 IP / Local IP	$(getAllLocalIps)"
    body+=$'\n'"作業系統 / OS	$(uname -sr 2>/dev/null || echo N/A)"
    body+=$'\n'"架構 / Architecture	$(uname -m 2>/dev/null || echo N/A)"
    body+=$'\n'"Bash 版本 / Bash Version	${BASH_VERSION:-N/A}"
    writeTsvAsCsv "${outDir}/${base}_SystemInfo.csv" "項目 / Item	內容 / Content" "$body"

    # 2. OS Details
    body=""
    if [ -r /etc/os-release ]; then
        for key in NAME VERSION ID VERSION_ID PRETTY_NAME; do
            local val
            val=$(grep "^${key}=" /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
            [ -n "$val" ] && body+="${body:+$'\n'}${key}	${val}"
        done
    fi
    local kv
    kv=$(uname -r 2>/dev/null)
    [ -n "$kv" ] && body+="${body:+$'\n'}KERNEL	${kv}"
    [ -z "$body" ] && body="N/A	無法取得"
    writeTsvAsCsv "${outDir}/${base}_OSDetails.csv" "設定 / Key	值 / Value" "$body"

    # 3. Antivirus
    if command -v clamscan &>/dev/null; then
        local avVer sigVer
        avVer=$(clamscan --version 2>/dev/null | head -1)
        sigVer=$(freshclam --version 2>/dev/null | head -1)
        body="防毒軟體 / Antivirus	ClamAV"
        body+=$'\n'"版本 / Version	${avVer:-N/A}"
        body+=$'\n'"病毒碼版本 / Signature Version	${sigVer:-N/A}"
    else
        body="防毒軟體 / Antivirus	未安裝 / Not Installed"
        body+=$'\n'"版本 / Version	N/A"
    fi
    writeTsvAsCsv "${outDir}/${base}_Antivirus.csv" "項目 / Item	值 / Value" "$body"

    # 4. Updates
    body=""
    if [ -r /var/log/dpkg.log ]; then
        body=$(grep -E ' upgrade | install ' /var/log/dpkg.log 2>/dev/null | tail -100 | \
            awk '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4}')
    fi
    if [ -z "$body" ] && command -v yum &>/dev/null; then
        body=$(yum history list 2>/dev/null | grep -E '^\s*[0-9]+' | head -50 | \
            awk -F'|' '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4}')
    fi
    [ -z "$body" ] && body="N/A	無法取得	"
    writeTsvAsCsv "${outDir}/${base}_Updates.csv" "日期 / Date	時間 / Time	動作 / Action	套件 / Package" "$body"

    # 5. Programs
    local pkgMgr
    pkgMgr=$(detectPkgManager)
    body=""
    if [ "$pkgMgr" = "dpkg" ]; then
        body=$(dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null)
    elif [ "$pkgMgr" = "rpm" ]; then
        body=$(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null)
    fi
    [ -z "$body" ] && body="N/A		"
    writeTsvAsCsv "${outDir}/${base}_Programs.csv" "名稱 / Name	版本 / Version	發行者 / Publisher" "$body"

    # 6. User Accounts
    body=""
    if [ -r /etc/passwd ]; then
        body=$(awk -F: '{uid=$3+0; if(uid>=1000||$1=="root") printf "%s\t%s\t%s\t%s\t%s\n",$1,$3,$4,$5,$7}' /etc/passwd 2>/dev/null)
    fi
    [ -z "$body" ] && body="N/A					"
    writeTsvAsCsv "${outDir}/${base}_UserAccounts.csv" "帳號名稱 / Username	UID	群組 / GID	描述 / Description	Shell" "$body"

    # 7. Password Policy
    body=""
    if [ -r /etc/login.defs ]; then
        body=$(grep -v '^\s*#' /etc/login.defs 2>/dev/null | \
            grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|LOGIN_RETRIES|LOGIN_TIMEOUT|ENCRYPT_METHOD' | \
            awk '{printf "%s\t%s\n", $1, $2}')
    fi
    [ -z "$body" ] && body="N/A	無法取得"
    writeTsvAsCsv "${outDir}/${base}_PasswordPolicy.csv" "設定 / Setting	值 / Value" "$body"

    # 8. Network Settings
    body=""
    if command -v ip &>/dev/null; then
        local dnsServers defaultGw
        dnsServers=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd,)
        defaultGw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
        while IFS= read -r iface; do
            [ "$iface" = "lo" ] && continue
            local inet
            inet=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet / {print $2; exit}')
            [ -n "$inet" ] && body+="${body:+$'\n'}${iface}	${inet}		${dnsServers:-N/A}	${defaultGw:-}"
        done < <(ip -4 addr show 2>/dev/null | awk '/^[0-9]+:/ {sub(/:$/,"",$2); print $2}')
    fi
    [ -z "$body" ] && body="N/A					"
    writeTsvAsCsv "${outDir}/${base}_NetworkSettings.csv" "介面名稱 / Interface	IP 位址 / IP Address	子網遮罩 / Subnet Mask	DNS 伺服器 / DNS Server	預設閘道 / Gateway" "$body"
}

# ---------------------------------------------------------------------------
# HTML fragment: table
# htmlTable <section_id> <header_row(tab-separated)> <body_tsv_lines>
# ---------------------------------------------------------------------------
htmlTable() {
    local tblId="$1"
    local header="$2"
    local body="$3"

    echo "<div class=\"table-responsive\">"
    echo "<table id=\"${tblId}\" class=\"table table-bordered table-striped table-hover table-sm\">"
    echo "<thead class=\"table-dark\"><tr>"
    local colIdx=0
    IFS=$'\t' read -ra cols <<< "$header"
    for col in "${cols[@]}"; do
        echo "<th onclick=\"sortTable('${tblId}',$colIdx)\">$(htmlEscape "$col")</th>"
        ((colIdx++)) || true
    done
    echo "</tr></thead>"
    echo "<tbody>"
    if [ -z "$body" ]; then
        echo "<tr><td colspan=\"${#cols[@]}\">無資料 / No data</td></tr>"
    else
        echo "$body" | while IFS='' read -r line; do
            echo "<tr>"
            IFS=$'\t' read -ra cells <<< "$line"
            for cell in "${cells[@]}"; do
                echo "<td>$(htmlEscape "$cell")</td>"
            done
            echo "</tr>"
        done
    fi
    echo "</tbody></table></div>"
}

# htmlSection <section_id> <title> <table_html>
htmlSection() {
    local secId="$1"
    local title="$2"
    local content="$3"
    cat <<EOF
<div class="section" id="${secId}">
  <h2>$(htmlEscape "$title")</h2>
  ${content}
</div>
EOF
}

# ---------------------------------------------------------------------------
# 1. System Info
# ---------------------------------------------------------------------------
collectSystemInfo() {
    local hostname os_ver arch ip allIps
    hostname=$(hostname 2>/dev/null || echo "未知")
    os_ver=$(uname -sr 2>/dev/null || echo "未知")
    arch=$(uname -m 2>/dev/null || echo "未知")
    ip=$(getLocalIp)
    allIps=$(getAllLocalIps)

    local body
    body=$(printf "主機名稱 / Hostname\t%s\n" "$(htmlEscape "$hostname")")
    body+=$(printf "\n區網 IP / Local IP\t%s\n" "$(htmlEscape "$allIps")")
    body+=$(printf "\n\u4f5c\u696d\u7cfb\u7d71 / OS\t%s\n" "$(htmlEscape "$os_ver")")
    body+=$(printf "\n\u67b6\u69cb / Architecture\t%s\n" "$(htmlEscape "$arch")")
    body+=$(printf "\nBash \u7248\u672c / Bash Version\t%s\n" "$(htmlEscape "${BASH_VERSION:-N/A}")")

    htmlTable "sysinfo" "項目 / Item	內容 / Content" "$body"
}

# ---------------------------------------------------------------------------
# 2. OS Details
# ---------------------------------------------------------------------------
collectOsDetails() {
    local body=""
    if [ -r /etc/os-release ]; then
        for key in NAME VERSION ID VERSION_ID PRETTY_NAME; do
            local val
            val=$(grep "^${key}=" /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
            [ -n "$val" ] && body+=$(printf "%s\t%s\n" "$key" "$(htmlEscape "$val")")
        done
    fi
    local kernel
    kernel=$(runCmd uname -r)
    [ -n "$kernel" ] && body+=$(printf "KERNEL\t%s\n" "$(htmlEscape "$kernel")")

    [ -z "$body" ] && body="N/A	無法取得 / Cannot retrieve"
    htmlTable "osdetail" "設定 / Key	值 / Value" "$body"
}

# ---------------------------------------------------------------------------
# 3. Antivirus (ClamAV)
# ---------------------------------------------------------------------------
collectAntivirusInfo() {
    local avName avVer sigVer
    if command -v clamscan &>/dev/null; then
        avName="ClamAV"
        avVer=$(clamscan --version 2>/dev/null | head -1)
        sigVer=$(runCmd freshclam --version | head -1)
    else
        avName="未安裝 / Not Installed"
        avVer="N/A"
        sigVer="N/A"
    fi

    local body
    body=$(printf "防毒軟體 / Antivirus\t%s\n" "$(htmlEscape "$avName")")
    body+=$(printf "\n版本 / Version\t%s\n" "$(htmlEscape "$avVer")")
    body+=$(printf "\n病毒碼版本 / Signature Version\t%s\n" "$(htmlEscape "$sigVer")")

    htmlTable "antivirus" "項目 / Item	值 / Value" "$body"
}

# ---------------------------------------------------------------------------
# 4. Installed Updates
# ---------------------------------------------------------------------------
collectUpdates() {
    local body=""
    if [ -r /var/log/dpkg.log ]; then
        # Debian/Ubuntu
        body=$(grep -E ' upgrade | install ' /var/log/dpkg.log 2>/dev/null | tail -100 | \
            awk '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4}')
        if [ -n "$body" ]; then
            htmlTable "updates" "日期 / Date	時間 / Time	動作 / Action	套件 / Package" "$body"
            return
        fi
    fi

    if command -v yum &>/dev/null; then
        body=$(yum history list 2>/dev/null | grep -E '^\s*[0-9]+' | head -50 | \
            awk -F'|' '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4}')
        if [ -n "$body" ]; then
            htmlTable "updates" "ID	指令 / Command	日期時間 / DateTime	動作 / Action" "$body"
            return
        fi
    fi

    htmlTable "updates" "資訊 / Info" "無法取得（需要 dpkg 或 yum）/ Cannot retrieve (requires dpkg or yum)	"
}

# ---------------------------------------------------------------------------
# 5. Installed Programs
# ---------------------------------------------------------------------------
collectPrograms() {
    local body=""
    local pkgMgr
    pkgMgr=$(detectPkgManager)

    if [ "$pkgMgr" = "dpkg" ]; then
        body=$(dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null | \
            awk -F'\t' '{printf "%s\t%s\t%s\n", $1, $2, $3}')
    elif [ "$pkgMgr" = "rpm" ]; then
        body=$(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null)
    fi

    [ -z "$body" ] && body="無法取得 / N/A		"
    htmlTable "programs" "名稱 / Name	版本 / Version	發行者 / Publisher" "$body"
}

# ---------------------------------------------------------------------------
# 6. Local User Accounts
# ---------------------------------------------------------------------------
collectUserAccounts() {
    local body=""
    if [ -r /etc/passwd ]; then
        body=$(awk -F: '{
            uid=$3+0
            if (uid >= 1000 || $1 == "root") {
                printf "%s\t%s\t%s\t%s\t%s\n", $1, $3, $4, $5, $7
            }
        }' /etc/passwd 2>/dev/null)
    fi
    [ -z "$body" ] && body="無法取得 / N/A					"
    htmlTable "users" "帳號名稱 / Username	UID	群組 / GID	描述 / Description	Shell" "$body"
}

# ---------------------------------------------------------------------------
# 7. Password Policy
# ---------------------------------------------------------------------------
collectPasswordPolicy() {
    local body=""
    if [ -r /etc/login.defs ]; then
        body=$(grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|LOGIN_RETRIES|LOGIN_TIMEOUT|ENCRYPT_METHOD)\s' \
            /etc/login.defs 2>/dev/null | \
            awk '{printf "%s\t%s\n", $1, $2}')
    fi
    [ -z "$body" ] && body="N/A	無法取得 / Cannot retrieve"
    htmlTable "policy" "設定 / Setting	值 / Value" "$body"
}

# ---------------------------------------------------------------------------
# 8. Network Settings
# ---------------------------------------------------------------------------
collectNetworkSettings() {
    local body=""

    # DNS servers
    local dnsServers
    dnsServers=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
    [ -z "$dnsServers" ] && dnsServers="N/A"

    # Default gateway
    local defaultGw
    defaultGw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
    [ -z "$defaultGw" ] && defaultGw=""

    # Per-interface IPv4
    local ifaceData
    ifaceData=$(ip -4 addr show 2>/dev/null | awk '
        /^[0-9]+:/ {
            iface = $2
            gsub(/:$/, "", iface)
        }
        /inet / {
            cidr = $2
            split(cidr, a, "/")
            ip    = a[1]
            plen  = a[2]
            # Calculate subnet mask
            mask=""
            n=plen+0
            for(i=1;i<=4;i++){
                bits = (n >= 8) ? 8 : (n < 0 ? 0 : n)
                n -= bits
                val = 256 - 2^(8-bits)
                mask = mask (i>1 ? "." : "") int(val)
            }
            printf "%s\t%s\t%s\n", iface, cidr, mask
        }
    ')

    if [ -n "$ifaceData" ]; then
        while IFS=$'\t' read -r iface cidr subnetMask; do
            # Show gateway only on the primary egress interface
            local gwForIface=""
            local defaultIface
            defaultIface=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
            [ "$iface" = "$defaultIface" ] && gwForIface="$defaultGw"

            body+=$(printf "%s\t%s\t%s\t%s\t%s\n" \
                "$(htmlEscape "$iface")" \
                "$(htmlEscape "$cidr")" \
                "$(htmlEscape "$subnetMask")" \
                "$(htmlEscape "$dnsServers")" \
                "$(htmlEscape "$gwForIface")")
            body+=$'\n'
        done <<< "$ifaceData"
    else
        body="無法取得 / N/A				"
    fi

    htmlTable "network" "介面名稱 / Interface	IP 位址 / IP Address	子網遮罩 / Subnet Mask	DNS 伺服器 / DNS Server	預設閘道 / Gateway" "$body"
}

# ---------------------------------------------------------------------------
# HTML Report Assembly
# ---------------------------------------------------------------------------
generateHtmlReport() {
    local hostname="$1"
    local localIp="$2"
    local scanTime
    scanTime=$(date '+%Y-%m-%d %H:%M:%S')

    # Collect each section
    echo "  蒐集系統資訊..." >&2
    local sSysinfo;    sSysinfo=$(collectSystemInfo)
    local sOsdetail;   sOsdetail=$(collectOsDetails)
    echo "  蒐集防毒資訊..." >&2
    local sAntivirus;  sAntivirus=$(collectAntivirusInfo)
    echo "  蒐集已安裝更新..." >&2
    local sUpdates;    sUpdates=$(collectUpdates)
    echo "  蒐集已安裝程式..." >&2
    local sPrograms;   sPrograms=$(collectPrograms)
    echo "  蒐集使用者帳號..." >&2
    local sUsers;      sUsers=$(collectUserAccounts)
    local sPolicy;     sPolicy=$(collectPasswordPolicy)
    echo "  蒐集網路設定..." >&2
    local sNetwork;    sNetwork=$(collectNetworkSettings)

    cat <<HTML
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>系統資訊報告 - $(htmlEscape "$hostname") ($(htmlEscape "$localIp"))</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 4.5rem; }
    .section { margin-bottom: 40px; }
    th { cursor: pointer; user-select: none; }
    th::after { content: ' ↕'; font-size: .75em; color: #aaa; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">系統資訊報告 / PC Info Report</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMenu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navMenu">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="#sysinfo">系統資訊</a></li>
        <li class="nav-item"><a class="nav-link" href="#osdetail">OS 詳細</a></li>
        <li class="nav-item"><a class="nav-link" href="#antivirus">防毒</a></li>
        <li class="nav-item"><a class="nav-link" href="#updates">更新</a></li>
        <li class="nav-item"><a class="nav-link" href="#programs">程式</a></li>
        <li class="nav-item"><a class="nav-link" href="#users">帳號</a></li>
        <li class="nav-item"><a class="nav-link" href="#policy">密碼原則</a></li>
        <li class="nav-item"><a class="nav-link" href="#network">網路</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  <h1 class="mb-2 mt-4">系統資訊報告</h1>
  <p class="text-muted">
    電腦名稱：<strong>$(htmlEscape "$hostname")</strong> &nbsp;|&nbsp;
    IP：<strong>$(htmlEscape "$localIp")</strong> &nbsp;|&nbsp;
    掃描時間：$(htmlEscape "$scanTime") &nbsp;|&nbsp;
    平台：Linux (Bash)
  </p>

  $(htmlSection "sysinfo"   "系統基本資訊 / System Info"   "$sSysinfo")
  $(htmlSection "osdetail"  "作業系統詳細 / OS Details"    "$sOsdetail")
  $(htmlSection "antivirus" "防毒資訊 / Antivirus"         "$sAntivirus")
  $(htmlSection "updates"   "已安裝更新 / Updates"         "$sUpdates")
  $(htmlSection "programs"  "已安裝程式 / Programs"        "$sPrograms")
  $(htmlSection "users"     "使用者帳號 / User Accounts"   "$sUsers")
  $(htmlSection "policy"    "密碼原則 / Password Policy"   "$sPolicy")
  $(htmlSection "network"   "網路設定 / Network Settings"  "$sNetwork")
</div>

<script>
function sortTable(tblId, colIdx) {
  var tbl = document.getElementById(tblId);
  if (!tbl) return;
  var tbody = tbl.tBodies[0];
  var rows = Array.from(tbody.rows);
  var asc = tbl.dataset.sortCol == colIdx && tbl.dataset.sortDir !== 'asc';
  rows.sort(function(a, b) {
    var x = a.cells[colIdx] ? a.cells[colIdx].innerText : '';
    var y = b.cells[colIdx] ? b.cells[colIdx].innerText : '';
    return asc ? x.localeCompare(y, 'zh-Hant', {numeric: true})
               : y.localeCompare(x, 'zh-Hant', {numeric: true});
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
  tbl.dataset.sortCol = colIdx;
  tbl.dataset.sortDir = asc ? 'asc' : 'desc';
}
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTML
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
LOCAL_IP=$(getLocalIp)
BASE_NAME="${HOSTNAME}_${LOCAL_IP}"

# Store all output under output/ next to the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_ROOT="${SCRIPT_DIR}/output"
mkdir -p "$OUTPUT_ROOT"

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="${OUTPUT_ROOT}/${BASE_NAME}"
fi

ZIP_PATH="${OUTPUT_ROOT}/${BASE_NAME}.zip"

mkdir -p "$OUTPUT_DIR"

echo "正在蒐集系統資訊... [${HOSTNAME} / ${LOCAL_IP}]"
HTML_FILE="${OUTPUT_DIR}/${BASE_NAME}.html"

# Write UTF-8 BOM so the HTML displays correctly when opened on Windows
printf '\xEF\xBB\xBF' > "$HTML_FILE"
generateHtmlReport "$HOSTNAME" "$LOCAL_IP" >> "$HTML_FILE"
echo "系統資訊已匯出至 ${HTML_FILE}"

# CSV Export
echo "  匯出 CSV 檔案..."
exportAllCsv "$OUTPUT_DIR" "$BASE_NAME"
echo "  完成：CSV 已匯出至 ${OUTPUT_DIR}/"

# Package output into ZIP (prefer zip; fall back to python3)
if command -v zip &>/dev/null; then
    zip -qr "${ZIP_PATH}" "${OUTPUT_DIR}/"
    echo "已壓縮至 ${ZIP_PATH}"
elif command -v python3 &>/dev/null; then
    python3 -c "
import zipfile, os, sys
zp, od = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as zf:
    for fn in os.listdir(od):
        fp = os.path.join(od, fn)
        if os.path.isfile(fp):
            zf.write(fp, arcname=os.path.join(os.path.basename(od), fn))
print('已壓縮至 ' + zp)
" "$ZIP_PATH" "$OUTPUT_DIR"
else
    echo "警告：找不到 zip 或 python3，略過壓縮。" >&2
fi
