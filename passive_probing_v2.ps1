<#
Discover_CrossSubnet_WithGraph.ps1 (Passive, with inline exclusions)
Collects per-host network info and builds a nodes/edges JSON (passive).
- Adds exePath + exeSha256 for listening processes
- Adds neighbor cache with lastSeen timestamp
- Adds firewall rule checks for inbound allow to ports
- Normalizes results into nodes/edges and computes a confidence score per edge
- Built-in ignore lists to drop noisy/unwanted data (no external blocklist file required)

Usage (elevated PowerShell):
 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
 .\Discover_CrossSubnet_WithGraph.ps1 -OutputPath .\csam_snapshot_graph.json
 Optional: add -IncludeExternalDNS to keep external/public IPs in DNS cache (default: excluded)
#>

param(
    [string]$OutputPath = ".\csam_snapshot_graph.json",
    [switch]$IncludeExternalDNS
)

# ---------- built-in ignore lists ----------
$ignoreRoutes = @(
    "127.*", "169.254.*", "224.*", "255.*",
    "172.29.128.1/32", "172.29.143.255/32","*.255/32","*/32"
)
$IgnoreNeighborIPs = @(
    "224.*", "239.*",        # multicast
    "255.*", "169.254.*" )
$IgnoreNeighborMACs  = @("01-00-5E-*", "FF-FF-FF-FF-FF-FF", "00-00-00-00-00-00")
$IgnoreDNSIPs = @(
        "127.*",        # loopback
        "169.254.*",    # APIPA
        "224.*", "239.*", # multicast
        "255.*"         # broadcast
    )
$ignoreListeningPorts = @(135, 137, 138, 139, 445,          # SMB, RPC, NetBIOS
    5353, 5355,                       # mDNS, LLMNR
    1900, 3702,                       # SSDP, WS-Discovery
    500, 4500,                        # IPSec
    49664, 49665, 49666, 49667, 49668) # RPC dynamic ports
$ignoreProcesses = @("svchost", "System", "wininit", "services", # Windows core services
    "chrome", "OUTLOOK", "EXCEL", "WINWORD", "Teams", "ms-teams" )
$dropReverseDnsNull = $true
$deduplicateListeners = $true

# ---------- helpers ----------
function Get-NetmaskFromPrefix($prefixLength) {
    $mask = [uint32]0
    for ($i=0; $i -lt $prefixLength; $i++) {
        $mask = $mask -bor (1 -shl (31 - $i))
    }
    $bytes = [BitConverter]::GetBytes([uint32]$mask)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function NowIso { (Get-Date).ToString("o") }

function Get-AllowingFirewallRulesForPort([int]$port) {
    $rules = @()
    try {
        $allRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        foreach ($r in $allRules) {
            if ($r.Enabled -ne "True") { continue }
            if ($r.Direction -ne "Inbound") { continue }
            if ($r.Action -ne "Allow") { continue }
            $pf = $null
            try { $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue } catch {}
            if ($pf) {
                foreach ($p in $pf) {
                    $lp = $p.LocalPort
                    if ($lp -eq "Any") { $rules += $r }
                    else {
                        $tokens = $lp -split ","
                        foreach ($tok in $tokens) {
                            $tok = $tok.Trim()
                            if ($tok -match "^\d+$" -and [int]$tok -eq $port) { $rules += $r }
                            elseif ($tok -match "^\d+-\d+$") {
                                $parts = $tok -split "-"
                                if ($port -ge [int]$parts[0] -and $port -le [int]$parts[1]) { $rules += $r }
                            }
                        }
                    }
                }
            } else { $rules += $r }
        }
    } catch {}
    return $rules
}

function Get-BaseAndPrefix($cidr) {
    if (-not $cidr) { return $null }
    $parts = $cidr -split "/"
    if ($parts.Count -lt 2) { return $null }
    return @{ base = $parts[0]; prefix = [int]$parts[1] }
}

function IpInCidr_Simple($ip, $cidr) {
    if (-not $ip -or -not $cidr) { return $false }
    $bp = Get-BaseAndPrefix $cidr
    if (-not $bp) { return $false }
    $prefix = $bp.prefix
    $base = $bp.base
    if ($prefix -eq 32) { return ($ip -eq $base) }
    if ($prefix -ge 24 -and $prefix -le 32) {
        $ip3 = ($ip -split "\.")[0..2] -join "."
        $base3 = ($base -split "\.")[0..2] -join "."
        return ($ip3 -eq $base3)
    } elseif ($prefix -ge 16 -and $prefix -lt 24) {
        $ip2 = ($ip -split "\.")[0..1] -join "."
        $base2 = ($base -split "\.")[0..1] -join "."
        return ($ip2 -eq $base2)
    } else {
        $ip1 = ($ip -split "\.")[0]
        $base1 = ($base -split "\.")[0]
        return ($ip1 -eq $base1)
    }
}

function Is-PrivateIP($ip) {
    if (-not $ip) { return $false }
    if ($ip -match '^10\.' -or
        $ip -match '^192\.168\.' -or
        $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($ip -match '^127\.' -or $ip -eq '::1') { return $true }
    return $false
}

# ---------- collection ----------
$collectedAt = NowIso

Write-Host "Collecting host/asset info..." -ForegroundColor Cyan
$comp = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue
$fqdnSuffixes = @()
if ($dnsGlobal -and $dnsGlobal.SuffixSearchList) { $fqdnSuffixes = $dnsGlobal.SuffixSearchList }
$assetObj = @{
    hostName   = if ($comp -and $comp.Name) { $comp.Name } else { $env:COMPUTERNAME }
    fqdn       = ($env:COMPUTERNAME) + "." + ($fqdnSuffixes -join ",")
    domain     = if ($comp -and $comp.Domain) { $comp.Domain } else { $null }
    domainRole = if ($comp -and $comp.DomainRole) { $comp.DomainRole } else { $null }
}

Write-Host "Collecting interfaces..." -ForegroundColor Cyan
$ifaces = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" } |
  ForEach-Object {
    [PSCustomObject]@{
        interfaceName   = $_.InterfaceAlias
        ip              = $_.IPAddress
        prefixLength    = $_.PrefixLength
        netmask         = (Get-NetmaskFromPrefix $_.PrefixLength)
        cidr            = "$($_.IPAddress)/$($_.PrefixLength)"
        interfaceIndex  = $_.InterfaceIndex
    }
}

Write-Host "Collecting routes..." -ForegroundColor Cyan
$routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        destination   = $_.DestinationPrefix
        nextHop       = $_.NextHop
        iface         = $_.InterfaceAlias
        metric        = $_.RouteMetric
        routeProtocol = $_.RouteProtocol
    }
}

# --- Apply route filters ---
$routes = $routes | Where-Object {
    $keep = $true
    foreach ($pat in $ignoreRoutes) { if ($_.destination -like $pat) { $keep = $false; break } }
    $keep
}

$defaultRoutes = $routes | Where-Object { $_.destination -eq '0.0.0.0/0' }
$gateways = $defaultRoutes | Select-Object -ExpandProperty nextHop -Unique
$candidatePrefixes = $routes | Select-Object -ExpandProperty destination -Unique

# Listening sockets (with exePath + exeSha256 enrichment)
Write-Host "Collecting listening sockets (with exe metadata)..." -ForegroundColor Cyan
$listening = @()
try {
    $tcp = Get-NetTCPConnection -State Listen -AddressFamily IPv4 -ErrorAction Stop
    foreach ($c in $tcp) {
        $procName = $null; $exePath = $null; $exeSha256 = $null
        try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.Path) {
                $exePath = $proc.Path
                try {
                    $exeSha256 = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                } catch {}
            }
            if ($proc) { $procName = $proc.ProcessName }
        } catch {}
        $listening += [PSCustomObject]@{
            localAddress  = $c.LocalAddress
            localPort     = $c.LocalPort
            protocol      = "TCP"
            state         = $c.State
            owningProcess = $c.OwningProcess
            processName   = $procName
            exePath       = $exePath
            exeSha256     = $exeSha256
            interface     = $c.InterfaceAlias
            source        = "Get-NetTCPConnection"
        }
    }
} catch {
    Write-Host "Get-NetTCPConnection not available or failed, using netstat fallback..." -ForegroundColor Yellow
    # TCP LISTENERS
    $netstatTcp = netstat -ano -p tcp | Select-String "LISTENING"
    foreach ($line in $netstatTcp) {
        $parts = $line.ToString().Trim() -split "\s+"
        if ($parts.Count -ge 5) {
            $local = $parts[1]
            $owningPid = $parts[4]
            if ($local -match "^\[.*\]:\d+$") {
                $addr = $local.Substring(1, $local.LastIndexOf("]")-1)
                $port = $local.Substring($local.LastIndexOf("]:")+2)
            } else {
                $addr, $port = $local -split ":",2
            }
            $procName = $null; $exePath = $null; $exeSha256 = $null
            try {
                $proc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
                if ($proc -and $proc.Path) {
                    $exePath = $proc.Path
                    try { $exeSha256 = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch {}
                }
                if ($proc) { $procName = $proc.ProcessName }
            } catch {}
            $listening += [PSCustomObject]@{
                localAddress  = $addr
                localPort     = [int]$port
                protocol      = "TCP"
                state         = "LISTEN"
                owningProcess = $owningPid
                processName   = $procName
                exePath       = $exePath
                exeSha256     = $exeSha256
                interface     = $null
                source        = "netstat"
            }
        }
    }
    # UDP LISTENERS
    $netstatUdp = netstat -ano -p udp
    foreach ($line in $netstatUdp) {
        $parts = $line.ToString().Trim() -split "\s+"
        if ($parts.Count -ge 4 -and $parts[1] -match ":") {
            $local = $parts[1]
            $owningPid = $parts[3]
            if ($local -match "^\[.*\]:\d+$") {
                $addr = $local.Substring(1, $local.LastIndexOf("]")-1)
                $port = $local.Substring($local.LastIndexOf("]:")+2)
            } else {
                $addr, $port = $local -split ":",2
            }
            $procName = $null; $exePath = $null; $exeSha256 = $null
            try {
                $proc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
                if ($proc -and $proc.Path) {
                    $exePath = $proc.Path
                    try { $exeSha256 = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch {}
                }
                if ($proc) { $procName = $proc.ProcessName }
            } catch {}
            $listening += [PSCustomObject]@{
                localAddress  = $addr
                localPort     = [int]$port
                protocol      = "UDP"
                state         = "LISTEN"
                owningProcess = $owningPid
                processName   = $procName
                exePath       = $exePath
                exeSha256     = $exeSha256
                interface     = $null
                source        = "netstat"
            }
        }
    }
}


$listening = $listening | Where-Object {
    -not ($IgnorePorts -contains [int]$_.localPort) -and
    -not ($IgnoreProcesses -contains $_.processName)
}
# Reverse DNS
function DoReverseDns($ip) { try { ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { $null } }
$reverseDns = @()
foreach ($i in ($ifaces.ip + $gateways | Where-Object { $_ -ne $null })) {
    $ptr = DoReverseDns $i
    $reverseDns += [PSCustomObject]@{ ip=$i; ptr=$ptr; lastChecked=$collectedAt }
}
if ($dropReverseDnsNull) { $reverseDns = $reverseDns | Where-Object { $_.ptr -and $_.ptr.Trim() -ne "" } }

# Candidate subnets from route table
$candidatePrefixes = $routes | Where-Object {
    ($_.destination -and $_.destination -ne '0.0.0.0/0') -and
    ($_.destination -notlike '127.*') -and ($_.destination -notlike '169.254.*')
} | Select-Object -ExpandProperty destination -Unique


# Neighbors
Write-Host "Collecting neighbor cache..." -ForegroundColor Cyan
$neighbors = @()
try {
    $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            ipAddress  = $_.IPAddress
            macAddress = $_.LinkLayerAddress
            interface  = $_.InterfaceAlias
            state      = $_.State
            lastSeen   = $collectedAt
        }
    }
} catch {}
$neighbors = $neighbors | Where-Object {
    $_.ipAddress  -notlike "224.*"     -and
    $_.ipAddress  -notlike "239.*"     -and
    $_.ipAddress  -notlike "255.*"     -and
    $_.ipAddress  -notlike "169.254.*" -and
    $_.macAddress -notlike "01-00-5E-*" -and
    $_.macAddress -ne "FF-FF-FF-FF-FF-FF" -and
    $_.macAddress -ne "00-00-00-00-00-00"
}
# DNS cache
Write-Host "Collecting DNS cache..." -ForegroundColor Cyan
$dnsCache = @()
try {
    $dnsRaw = ipconfig /displaydns
    $record = $null

    foreach ($line in $dnsRaw) {
        if ($line -match "Record Name") {
            $record = @{
                name      = ($line -split ":",2)[1].Trim()
                addresses = @()
            }
        }
        elseif ($line -match "A \(Host\)") {
            $addr = ($line -split ":",2)[1].Trim()

            # Apply filters: keep only if NOT matching ignore IPs
            if (
                ($IncludeExternalDNS -or (Is-PrivateIP $addr)) -and
                -not ($IgnoreDNSIPs | Where-Object { $addr -like $_ })
            ) {
                $record.addresses += $addr
            }
        }
        elseif ($line -eq "" -and $record) {
            if ($record.addresses.Count -gt 0) {
                $dnsCache += $record
            }
            $record = $null
        }
    }
} catch {}

# ---------- Optimized normalization & scoring ----------
Write-Host "Normalizing to node/edge graph and scoring (optimized)..." -ForegroundColor Cyan

# Build caches (prefix keys, neighbor/dns maps, firewall cache)
$prefixKeyMap=@{}; foreach ($pfx in $candidatePrefixes) {
    if ($pfx -match "/") {
        $parts=$pfx -split "/"; $base=$parts[0]; $pre=[int]$parts[1]
        if ($pre -ge 24) { $key=($base -split '\.')[0..2] -join "." + "." }
        elseif ($pre -ge 16) { $key=($base -split '\.')[0..1] -join "." + "." }
        else { $key=($base -split '\.')[0] + "." }
        $prefixKeyMap[$pfx]=@{base=$base;prefix=$pre;key=$key}
    } else { $prefixKeyMap[$pfx]=@{base=$pfx;prefix=32;key=$pfx} }
}
$neighborsByPrefix=@{}; $dnsByPrefix=@{}; foreach ($pfx in $candidatePrefixes) { $neighborsByPrefix[$pfx]=@(); $dnsByPrefix[$pfx]=@() }
foreach ($n in $neighbors) { foreach ($pfx in $candidatePrefixes) { if ($n.ipAddress -like "$($prefixKeyMap[$pfx].key)*") { $neighborsByPrefix[$pfx]+=$n } } }
foreach ($d in $dnsCache) { foreach ($a in $d.addresses) { foreach ($pfx in $candidatePrefixes) { if ($a -like "$($prefixKeyMap[$pfx].key)*") { $dnsByPrefix[$pfx]+=$a } } } }
$fwCache=@{}; function FirewallAllowsPortCached([int]$port){ if($fwCache.ContainsKey($port)){return $fwCache[$port]} $allowed=$false; try{if((Get-AllowingFirewallRulesForPort -port $port).Count -gt 0){$allowed=$true}}catch{} $fwCache[$port]=$allowed; return $allowed }

$nodes=@();$edges=@()
$hostId="host:$($assetObj.hostName)"
$nodes+=[PSCustomObject]@{
    id=$hostId;type="host";name=$assetObj.hostName;
    fqdn=$assetObj.fqdn;domain=$assetObj.domain;collectedAt=$collectedAt
}

# 1. host_has_interface
foreach($iface in $ifaces){
    $ifaceId="iface:$($iface.ip)"
    $nodes+=[PSCustomObject]@{id=$ifaceId;type="interface";ip=$iface.ip;cidr=$iface.cidr}
    $edges+=[PSCustomObject]@{
        from=$hostId;to=$ifaceId;
        type="host_has_interface";
        evidence=@("interface-list");score=1
    }
}

# 3. interface_discovers_neighbor
foreach($n in $neighbors){
    $nId="neighbor:$($n.ipAddress)"
    # Create neighbor node
    $nodes+=[PSCustomObject]@{
        id=$nId
        type="neighbor"
        ip=$n.ipAddress
        mac=$n.macAddress
        interface=$n.interface
        lastSeen=$n.lastSeen
    }

    # Link interface → neighbor (interface_discovers_neighbor)
    foreach($iface in $ifaces){
        if($iface.interfaceName -eq $n.interface){
            $ifaceId="iface:$($iface.ip)"
            $edges+=[PSCustomObject]@{
                from=$ifaceId
                to=$nId
                type="interface_discovers_neighbor"
                evidence=@("neighbor-cache")
                score=2
            }
        }
    }
}

# 4. neighbor_on_subnet
foreach($pfx in $candidatePrefixes){
    $subId="subnet:$pfx"
    foreach($n in $neighborsByPrefix[$pfx]){
        $nId="neighbor:$($n.ipAddress)"
        $edges+=[PSCustomObject]@{
            from=$nId
            to=$subId
            type="neighbor_on_subnet"
            evidence=@("neighbor-cache")
            score=2
        }
    }
}
# 4. host_exposes_service + 5. service_binds_to_interface
$svcMap=@{}
foreach($s in $listening){
    if ($IgnorePorts -contains [int]$s.localPort) { continue }
    if ($IgnoreProcesses -contains $s.processName) { continue }

    $svcKey="$($s.protocol):$([int]$s.localPort)"
    if(-not $svcMap.ContainsKey($svcKey)){
        $svcMap[$svcKey]="service:$svcKey"
        $nodes+=[PSCustomObject]@{
            id=$svcMap[$svcKey];type="service";
            protocol=$s.protocol;port=[int]$s.localPort
        }
    }
    $svcId=$svcMap[$svcKey]
    $ev=@("listening")
    if($s.exePath){$ev+="exe:$($s.exePath)"}
    if($s.exeSha256){$ev+="hash:$($s.exeSha256)"}

    # host_exposes_service
    $edges+=[PSCustomObject]@{
        from=$hostId;to=$svcId;
        type="host_exposes_service";
        evidence=$ev;score=3
    }

    # service_binds_to_interface (if localAddress not 0.0.0.0/127.0.0.1)
    if($s.localAddress -and $s.localAddress -notin @("0.0.0.0","127.0.0.1")){
        $edges+=[PSCustomObject]@{
            from=$svcId;to="iface:$($s.localAddress)";
            type="service_binds_to_interface";
            evidence=@("socket-bind");score=2
        }
    }

    # subnet_can_reach_service
    foreach($pfx in $candidatePrefixes){
        $score=3
        $evid=@("listening","route-known")
        if($neighborsByPrefix[$pfx].Count -gt 0){$score+=2;$evid+="neighbor-seen"}
        if($dnsByPrefix[$pfx].Count -gt 0){$score+=1;$evid+="dns-resolves"}
        if(FirewallAllowsPortCached -port ([int]$s.localPort)){$score+=2;$evid+="firewall-allow"}
        $edges+=[PSCustomObject]@{
            from="subnet:$pfx";to=$svcId;
            type="subnet_can_reach_service";
            evidence=$evid;score=$score
        }
    }
}

# 6. dns_name_resolves_to_ip + 7. dns_name_resolves_to_subnet
foreach($d in $dnsCache){
    $dnId="dnsname:$($d.name)"
    $nodes+=[PSCustomObject]@{
        id=$dnId;type="dnsname";name=$d.name;addresses=$d.addresses
    }
    foreach($a in $d.addresses){
        # direct DNS → IP edge
        $edges+=[PSCustomObject]@{
            from=$dnId;to="iface:$a";
            type="dns_name_resolves_to_ip";
            evidence=@("dns-cache");score=1
        }
        foreach($pfx in $candidatePrefixes){
            if($a -like "$($prefixKeyMap[$pfx].key)*"){
                $edges+=[PSCustomObject]@{
                    from=$dnId;to="subnet:$pfx";
                    type="dns_name_resolves_to_subnet";
                    evidence=@("dns-cache");score=1
                }
            }
        }
    }
}

# 8. host_has_route + 9. route_points_to_gateway
foreach($r in $routes){
    $edges+=[PSCustomObject]@{
        from=$hostId;to="subnet:$($r.destination)";
        type="host_has_route";
        evidence=@("route-table");score=2
    }
    if($r.nextHop -and $r.nextHop -ne "0.0.0.0"){
        $edges+=[PSCustomObject]@{
            from="subnet:$($r.destination)";to="gateway:$($r.nextHop)";
            type="route_points_to_gateway";
            evidence=@("route-table");score=2
        }
    }
}

# 10. interface_connected_gateway
foreach($g in $gateways){
    $gwId="gateway:$g"
    $nodes+=[PSCustomObject]@{id=$gwId;type="gateway";ip=$g}
    foreach($iface in $ifaces){
        $edges+=[PSCustomObject]@{
            from="iface:$($iface.ip)";to=$gwId;
            type="interface_connected_gateway";
            evidence=@("routes","neighbors");score=3
        }
    }
}


# ---------- Deduplication of edges ----------
Write-Host "Deduplicating edges..." -ForegroundColor Cyan

$dedupedEdges = @{}
foreach($e in $edges){
    $key = "$($e.from)|$($e.to)|$($e.type)"
    if(-not $dedupedEdges.ContainsKey($key)){
        # First time seeing this edge
        $dedupedEdges[$key] = @{
            from=$e.from;to=$e.to;type=$e.type;
            evidence=@($e.evidence);score=$e.score
        }
    } else {
        # Merge evidence + keep max score
        $dedupedEdges[$key].evidence += $e.evidence
        $dedupedEdges[$key].evidence = $dedupedEdges[$key].evidence | Sort-Object -Unique
        if($e.score -gt $dedupedEdges[$key].score){
            $dedupedEdges[$key].score = $e.score
        }
    }
}

# Replace original edges with deduped
$edges = @()
foreach($val in $dedupedEdges.Values){
    $edges += [PSCustomObject]@{
        from=$val.from;to=$val.to;type=$val.type;
        evidence=$val.evidence;score=$val.score
    }
}

# ---------- Group edges by "to" ----------
$groupedEdges = @{}
foreach($e in $edges){
    if(-not $groupedEdges.ContainsKey($e.to)){
        $groupedEdges[$e.to] = @()
    }
    $groupedEdges[$e.to] += [PSCustomObject]@{
        from     = $e.from
        type     = $e.type
        evidence = $e.evidence
        score    = $e.score
    }
}

# Convert grouped dictionary into array of { to, reachable[] }
$edgesGrouped = @()
foreach($key in $groupedEdges.Keys){
    $edgesGrouped += [PSCustomObject]@{
        to        = $key
        reachable = $groupedEdges[$key]
    }
}

# ---------- Final JSON ----------
$final = [PSCustomObject]@{
    metadata = @{
        collectedAt = $collectedAt
        tool        = "Discover_CrossSubnet_WithGraph.ps1 (passive, optimized)"
    }
    asset = $assetObj
    raw   = @{
        interfaces        = $ifaces
        routes            = $routes
        gateways          = $gateways
        listening         = $listening
        reverseDns        = $reverseDns
        neighbors         = $neighbors
        dnsCache          = $dnsCache
        candidatePrefixes = $candidatePrefixes
    }
    graph = @{
        nodes = $nodes
        edges = $edgesGrouped
    }
}

Write-Host "Writing output to ${OutputPath} ..." -ForegroundColor Green
$final | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Done. Review ${OutputPath} for details." -ForegroundColor Green