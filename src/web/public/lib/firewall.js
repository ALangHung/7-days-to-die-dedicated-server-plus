const { execFile } = require("child_process");

/**
 * 依名稱 + 方向(入/出/兩者) + 協定，若同方向下「沒有完全符合 opts」，
 * 就刪除該方向下同名且同協定的所有規則，接著依 opts 建立新規則。
 *
 * @param {string} displayName  GUI 看到的規則名稱
 * @param {{
 *   programPath?: string | null,                 // 綁定程式（可選）
 *   action?: 'Allow'|'Block',                    // 預設 Allow
 *   direction?: 'Inbound'|'Outbound'|'Both',     // 預設 Both
 *   protocol?: 'TCP'|'UDP',                      // 預設 TCP
 *   ports?: string,                              // "8080" | "80,443" | "5000-6000" | "8080,5000-6000"
 *   profiles?: Array<'Domain'|'Private'|'Public'>// 預設 ['Domain','Private','Public']
 * }} opts
 * @returns {Promise<any>} JSON 摘要（每個方向一筆）
 */
function checkAndUpdateFirewallRule(displayName, opts = {}) {
    const {
        programPath = null,
        action = "Allow",
        direction = "Both",
        protocol = "TCP",
        ports = "",
        profiles = ["Domain", "Private", "Public"],
    } = opts;

    // 轉義
    const safeName = String(displayName).replace(/'/g, "''");
    const safePorts = String(ports).replace(/'/g, "''");
    const safeProtocol = String(protocol).toUpperCase() === "UDP" ? "UDP" : "TCP";
    const safeAction = action === "Block" ? "Block" : "Allow";
    const safeEnabled = '"True"'; // 以字串 True/False（非 $true/$false）
    const dirs =
        direction === "Outbound"
            ? ["Outbound"]
            : direction === "Inbound"
                ? ["Inbound"]
                : ["Inbound", "Outbound"];

    // Profile bitmask
    const bit = (p) => (p === "Domain" ? 1 : p === "Private" ? 2 : p === "Public" ? 4 : 0);
    const profileMask = profiles.reduce((m, p) => m | bit(p), 0) || 0; // 0 = All

    const safeProgram = programPath ? String(programPath).replace(/'/g, "''") : "";

    const ps = `
        $ErrorActionPreference = 'Stop'
        $targetName   = '${safeName}'
        $newPortsRaw  = '${safePorts}'
        $protocol     = '${safeProtocol}'
        $action       = '${safeAction}'
        $enabledText  = ${safeEnabled}     # "True" or "False"（字串）
        $profileMask  = ${profileMask}
        $programPath  = '${safeProgram}'

        # 將 "80,443, 5000-6000" 轉為可餵給 -LocalPort 的陣列
        $portTokens = @()
        foreach ($tok in ($newPortsRaw -split '\\s*,\\s*')) {
            if ([string]::IsNullOrWhiteSpace($tok)) { continue }
            $portTokens += $tok
        }
        
        function PortsEqual($existing, $desired) {
            if ($null -eq $existing) { $existing = @() }
            elseif ($existing -is [string]) { $existing = @($existing) }

            if ($null -eq $desired) { $desired = @() }
            elseif ($desired -is [string]) { $desired = @($desired) }

            $exNorm = @()
            foreach ($i in $existing) { $exNorm += (($i -split ',') | % { $_.Trim() } | ? { $_ }) }

            $deNorm = @()
            foreach ($i in $desired)  { $deNorm += (($i -split ',') | % { $_.Trim() } | ? { $_ }) }

            $exNorm = @($exNorm | Sort-Object -Unique)
            $deNorm = @($deNorm | Sort-Object -Unique)

            if ($exNorm.Count -ne $deNorm.Count) { return $false }
            for ($i = 0; $i -lt $exNorm.Count; $i++) {
                if ($exNorm[$i] -ne $deNorm[$i]) { return $false }
            }
            return $true
        }

        function ProcessDirection($dir) {
            # 取得此方向、同名、同協定的所有規則
            $all = Get-NetFirewallRule -DisplayName $targetName -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq $dir }
            $sameProto = @()
            foreach ($r in $all) {
                $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r
                if ($pf.Protocol -eq $protocol) { $sameProto += $r }
            }

            # 檢查是否已有完全符合的規則
            $hasExact = $false
            foreach ($r in $sameProto) {
                $pf  = Get-NetFirewallPortFilter       -AssociatedNetFirewallRule $r
                $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r

                $portsOK   = PortsEqual -existing $pf.LocalPort -desired $portTokens
                $programOK = $true
                if ($programPath) {
                    $programOK = ($app.Program -eq $programPath)
                }
                $actionOK  = ($r.Action -eq $action)
                $profileOK = ($profileMask -eq 0) -or ($r.Profile -eq $profileMask)

                if ($portsOK -and $programOK -and $actionOK -and $profileOK) {
                    $hasExact = $true
                }
            }

            if ($hasExact) {
                return [PSCustomObject]@{
                    DisplayName = $targetName
                    Direction   = $dir
                    Protocol    = $protocol
                    LocalPorts  = $portTokens
                    Action      = $action
                    Enabled     = $enabledText
                    ProfileMask = $profileMask
                    Program     = $programPath
                    Recreated   = $false
                    SkippedBecauseAlreadyMatches = $true
                }
            }

            # 沒有完全符合 → 刪掉此方向、同名、同協定的規則
            if ($sameProto.Count -gt 0) { $sameProto | ForEach-Object { Remove-NetFirewallRule -Name $_.Name } }

            # 依 opts 建立新規則
            $params = @{
                DisplayName = $targetName
                Direction   = $dir
                Action      = $action
                Protocol    = $protocol
                LocalPort   = $portTokens
                Enabled     = $enabledText
            }
            if ($profileMask -ne 0) { $params.Profile = $profileMask }
            if ($programPath)       { $params.Program = $programPath }

            New-NetFirewallRule @params | Out-Null

            return [PSCustomObject]@{
                DisplayName = $targetName
                Direction   = $dir
                Protocol    = $protocol
                LocalPorts  = $portTokens
                Action      = $action
                Enabled     = $enabledText
                ProfileMask = $profileMask
                Program     = $programPath
                Recreated   = $true
                SkippedBecauseAlreadyMatches = $false
            }
        }

       $result = @()
       ${dirs.map((d) => `\$result += ProcessDirection('${d}')`).join("\n")}
       $result | ConvertTo-Json -Depth 4
       `.trim();

    return new Promise((resolve, reject) => {
        execFile(
            "powershell",
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            { windowsHide: true, maxBuffer: 1024 * 1024 },
            (err, stdout, stderr) => {
                if (err) return reject(err);
                try {
                    resolve(JSON.parse(stdout || "[]"));
                } catch (e) {
                    reject(
                        new Error(`PowerShell 輸出解析失敗：${e}\nstdout=${stdout}\nstderr=${stderr}`)
                    );
                }
            }
        );
    });
}


module.exports = { checkAndUpdateFirewallRule };