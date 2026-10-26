#Requires -Version 5.1
<#
.SYNOPSIS
    READ-ONLY window summarising the PSM configuration seen from the CPM:
    profiles and their servers, effective software per profile, zones and
    VIPs, common settings, consistency checks.

.DESCRIPTION
    Reads (never writes):
      - config\distribution.psd1 (this folder): profiles (ServerTypes),
        servers, push lots;
      - the base tree (SourceRoot): config\settings.psd1, zones.psd1,
        software.psd1 (+ software.extra.psd1);
      - each profile's overlay (OverlayRoot\<PROFILE>): a file there WINS over
        the base file, as Distribute-PSMSources composes the trees - so the
        software list shown is the one the profile's servers will install.

    Optional key on a Servers entry: Zone = '<zones.psd1 key>' (ignored by
    Distribute-PSMSources). Without it, the zone is deduced from the VIPs the
    server belongs to.

    Windows PowerShell 5.1 + WPF (STA: the default of powershell.exe).
    -NoGui prints the same content to the console, -PassThru returns the model.

.EXAMPLE
    .\Show-PSMConfig.ps1

.EXAMPLE
    .\Show-PSMConfig.ps1 -NoGui
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config\distribution.psd1'),
    [switch] $NoGui,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===========================================================================
# Model: everything the window shows, built from the config files only
# ===========================================================================

function Get-CfgValue {
    # Optional key of a psd1 table ('A.B' = nested); $null when absent.
    param($Config, [string] $Path)
    $node = $Config
    foreach ($part in $Path.Split('.')) {
        if ($node -isnot [System.Collections.IDictionary] -or -not $node.Contains($part)) { return $null }
        $node = $node[$part]
    }
    return $node
}

function Format-CfgValue {
    param($Value)
    if ($null -eq $Value) { return '(not set)' }
    if ($Value -is [array]) { return ($Value -join ', ') }
    if ($Value -is [string] -and $Value -eq '') { return '(empty)' }
    return [string]$Value
}

function Get-Psd1SyntaxErrors {
    # Import-PowerShellDataFile only says "could not be parsed": the parser gives
    # the line and the reason (missing quote, duplicate key, missing brace...).
    param([Parameter(Mandatory)] [string] $Path)
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$errs)
    return @($errs | Select-Object -First 3 | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
}

function New-PSMConfigModel {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ConfigPath)

    $checks = New-Object System.Collections.Generic.List[object]
    function Add-Check {
        param([string] $Level, [string] $Topic, [string] $Detail)
        $checks.Add([pscustomobject]@{ Level = $Level; Topic = $Topic; Detail = $Detail })
    }
    function Read-Psd1 {
        param([string] $Path, [string] $Label, [switch] $Required)
        if (-not (Test-Path -LiteralPath $Path)) {
            if ($Required) { Add-Check 'Error' $Label "Not found: $Path" }
            return $null
        }
        $syntax = @(Get-Psd1SyntaxErrors -Path $Path)
        if ($syntax) {
            Add-Check 'Error' $Label "SYNTAX ERROR in $Path - $($syntax -join ' | ') (the deployment cannot read this file either)."
            return $null
        }
        # -ErrorAction Stop: on 5.1 the cmdlet only WRITES its error (not catchable otherwise).
        try { return Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop }
        catch { Add-Check 'Error' $Label "Cannot be read: $($_.Exception.Message)"; return $null }
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "distribution.psd1 not found: $ConfigPath (use -ConfigPath)." }
    $syntax = @(Get-Psd1SyntaxErrors -Path $ConfigPath)
    if ($syntax) { throw "SYNTAX ERROR in $ConfigPath - $($syntax -join ' | ')" }
    $dist        = Import-PowerShellDataFile -LiteralPath $ConfigPath -ErrorAction Stop
    $baseRoot    = [string](Get-CfgValue $dist 'SourceRoot')
    $overlayRoot = [string](Get-CfgValue $dist 'OverlayRoot')
    if (-not $baseRoot -or -not $overlayRoot) { throw "distribution.psd1: SourceRoot and OverlayRoot are required." }
    $profiles  = @(Get-CfgValue $dist 'ServerTypes' | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $inventory = @(Get-CfgValue $dist 'Servers' | Where-Object { $_ })
    $pushLots  = Get-CfgValue $dist 'PushAccounts'
    if ($pushLots -isnot [System.Collections.IDictionary]) { $pushLots = @{} }

    if (-not (Test-Path -LiteralPath $baseRoot)) { Add-Check 'Error' 'Base tree' "SourceRoot not found: $baseRoot" }
    $settings = Read-Psd1 (Join-Path $baseRoot 'config\settings.psd1') 'settings.psd1' -Required
    $zones    = Read-Psd1 (Join-Path $baseRoot 'config\zones.psd1')    'zones.psd1'    -Required

    function Resolve-TreeFile {
        # Effective file for a profile: the overlay copy WINS over the base one.
        param([string] $ProfileName, [string] $RelPath)
        $o = Join-Path (Join-Path $overlayRoot $ProfileName) $RelPath
        if (Test-Path -LiteralPath $o) { return [pscustomobject]@{ Path = $o; From = 'Profile' } }
        $b = Join-Path $baseRoot $RelPath
        if (Test-Path -LiteralPath $b) { return [pscustomobject]@{ Path = $b; From = 'Base' } }
        return $null
    }

    # --- VIPs (zones.psd1 PsmVips) ---------------------------------------------
    $vips = New-Object System.Collections.Generic.List[object]
    $zoneKeys = @()
    if ($zones) { $zoneKeys = @($zones.Keys | Sort-Object) }
    foreach ($zk in $zoneKeys) {
        $pv = Get-CfgValue $zones[$zk] 'PsmVips'
        if ($pv -isnot [System.Collections.IDictionary]) { continue }
        foreach ($vip in @($pv.Keys | Sort-Object)) {
            $members = @(Get-CfgValue $pv[$vip] 'Members' | Where-Object { $_ } | ForEach-Object { ([string]$_).Split('.')[0] })
            $vips.Add([pscustomobject]@{ Vip = [string]$vip; Zone = [string]$zk; Members = $members })
        }
    }

    # --- Profiles and their effective software ----------------------------------
    $softwareByProfile = @{}
    $profileRows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $profiles) {
        $overlayDir = Join-Path $overlayRoot $p
        $hasOverlay = Test-Path -LiteralPath $overlayDir
        if (-not $hasOverlay) {
            Add-Check 'Info' "Profile $p" "No overlay folder ($overlayDir): its servers get the base tree only."
        }
        else {
            foreach ($cfg in 'config\zones.psd1', 'config\settings.psd1') {
                if (Test-Path -LiteralPath (Join-Path $overlayDir $cfg)) {
                    Add-Check 'Warning' "Profile $p" "The overlay overrides $cfg - environment settings belong in the base."
                }
            }
            if (Test-Path -LiteralPath (Join-Path $overlayDir 'config\software.psd1')) {
                Add-Check 'Info' "Profile $p" ('The overlay ships a full config\software.psd1 that REPLACES the common list ' +
                    '(software.extra.psd1 adds to it instead).')
            }
        }

        # Common list (or the overlay's full list), then software.extra.psd1:
        # same Name = replaces in place, new Name = appended (Get-PSMSoftwareList rule).
        $apps = New-Object System.Collections.Generic.List[object]
        $listFile = Resolve-TreeFile $p 'config\software.psd1'
        if ($listFile) {
            $origin = if ($listFile.From -eq 'Profile') { 'Profile (full list)' } else { 'Common' }
            $data = Read-Psd1 $listFile.Path "software.psd1 ($p)"
            foreach ($a in @(Get-CfgValue $data 'Applications' | Where-Object { $_ })) { $apps.Add(@{ App = $a; Origin = $origin }) }
        }
        $extraFile = Resolve-TreeFile $p 'config\software.extra.psd1'
        if ($extraFile) {
            $data = Read-Psd1 $extraFile.Path "software.extra.psd1 ($p)"
            foreach ($a in @(Get-CfgValue $data 'Applications' | Where-Object { $_ })) {
                $idx = -1
                for ($i = 0; $i -lt $apps.Count; $i++) { if ($apps[$i].App['Name'] -eq $a['Name']) { $idx = $i; break } }
                if ($idx -ge 0) { $apps[$idx] = @{ App = $a; Origin = 'Profile (replaces common)' } }
                else            { $apps.Add(@{ App = $a; Origin = 'Profile' }) }
            }
        }
        $sw = New-Object System.Collections.Generic.List[object]
        foreach ($e in $apps) {
            $a        = $e.App
            $isCopy   = [bool]$a['Source']
            $rel      = if ($isCopy) { [string]$a['Source'] } else { [string]$a['Installer'] }
            $optional = [bool]$a['Optional']
            $staged   = '(none)'
            if ($rel) {
                $f = Resolve-TreeFile $p $rel
                $staged = if ($f) { $f.From } else { 'MISSING' }
            }
            if ($staged -eq 'MISSING') {
                if ($optional) { Add-Check 'Info'  "Profile $p" "'$($a['Name'])' not staged ($rel): skipped at deployment (Optional)." }
                else           { Add-Check 'Error' "Profile $p" "'$($a['Name'])': file not found ($rel) - the Software phase will FAIL." }
            }
            $sw.Add([pscustomobject]@{
                Software    = [string]$a['Name']
                Origin      = $e.Origin
                Mode        = $(if ($isCopy) { 'Copy' } else { 'Installer' })
                File        = $rel
                Staged      = $staged
                Optional    = $(if ($optional) { 'Yes' } else { 'No' })
                Destination = [string]$a['Destination']
            })
        }
        $softwareByProfile[$p] = $sw.ToArray()

        $members = @($inventory | Where-Object { [string]$_['Type'] -eq $p } | ForEach-Object { [string]$_['Name'] })
        if (-not $members) { Add-Check 'Info' "Profile $p" 'No server assigned.' }
        $profileRows.Add([pscustomobject]@{
            Name     = $p
            Label    = "$p   ($($members.Count) server(s), $($sw.Count) software)"
            Servers  = $members
            Overlay  = $(if ($hasOverlay) { $overlayDir } else { '(no overlay folder: base tree only)' })
            Software = $sw.ToArray()
        })
    }

    # Overlay folders that no profile uses (e.g. an old PRD / PREMW left behind).
    if (Test-Path -LiteralPath $overlayRoot) {
        foreach ($d in @(Get-ChildItem -LiteralPath $overlayRoot -Directory)) {
            if ($profiles -notcontains $d.Name) {
                Add-Check 'Warning' 'Overlays' "Folder '$($d.Name)' is not a declared profile (ServerTypes): never distributed - remove it or declare it."
            }
        }
    }
    else { Add-Check 'Warning' 'Overlays' "OverlayRoot not found: $overlayRoot" }

    # --- Servers ------------------------------------------------------------------
    function Resolve-PushLot {
        # Same order as Distribute-PSMSources: explicit Push, first lot (alphabetical)
        # whose Match fits the name, 'Default', none.
        param($Server)
        if ($Server['Push']) { return [string]$Server['Push'] }
        foreach ($k in @($pushLots.Keys | Where-Object { $_ -ne 'Default' } | Sort-Object)) {
            $m = Get-CfgValue $pushLots[$k] 'Match'
            if ($m -and [string]$Server['Name'] -like $m) { return [string]$k }
        }
        if ($pushLots.Contains('Default')) { return 'Default' }
        return $null
    }

    $serverRows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($s in $inventory) {
        $name = [string]$s['Name']
        $type = [string]$s['Type']
        if (-not $name) { Add-Check 'Error' 'Servers' 'An entry has no Name.'; continue }
        $short = $name.Split('.')[0]
        if ($seen.ContainsKey($short)) { Add-Check 'Error' "Server $name" 'Listed twice in Servers.' }
        $seen[$short] = $true
        if ($profiles -notcontains $type) {
            Add-Check 'Error' "Server $name" "Profile '$type' is not declared in ServerTypes - PSM-Distribute refuses it."
        }

        $myVips   = @($vips | Where-Object { $_.Members -contains $short })
        $vipZones = @($myVips | ForEach-Object { $_.Zone } | Sort-Object -Unique)
        $declared = [string]$s['Zone']
        if ($declared) {
            if ($zones -and -not $zones.Contains($declared)) { Add-Check 'Error' "Server $name" "Zone '$declared' does not exist in zones.psd1." }
            if ($vipZones -and ($vipZones -notcontains $declared)) {
                Add-Check 'Warning' "Server $name" "Zone '$declared', but member of a VIP of zone $($vipZones -join ', ')."
            }
            $zoneText = $declared
        }
        elseif ($vipZones) { $zoneText = "$($vipZones -join ', ') (from VIP)" }
        else               { $zoneText = '-' }
        if (-not $myVips) { Add-Check 'Info' "Server $name" 'Behind no VIP: the RDP certificate phase does nothing there.' }

        $explicit = [string]$s['Push']
        if ($explicit -and -not $pushLots.Contains($explicit)) {
            Add-Check 'Error' "Server $name" "Push='$explicit' has no PushAccounts entry - PSM-Distribute refuses it."
        }
        $lot = Resolve-PushLot $s
        $lotText = if ($lot -and $pushLots.Contains($lot)) {
            $acct = Get-CfgValue $pushLots[$lot] 'LogonName'
            if (-not $acct) { $acct = Get-CfgValue $pushLots[$lot] 'UserName' }
            "$lot ($acct)"
        }
        elseif ($lot) { $lot }
        else { '- (current session, then local admin)' }

        $swCount = 0
        if ($softwareByProfile.ContainsKey($type)) { $swCount = @($softwareByProfile[$type]).Count }
        $serverRows.Add([pscustomobject]@{
            Server   = $name
            Profile  = $type
            Zone     = $zoneText
            VIP      = (@($myVips | ForEach-Object { $_.Vip }) -join ', ')
            PushLot  = $lotText
            Software = [string]$swCount
        })
    }

    # --- VIP rows + checks ----------------------------------------------------------
    $vipRows = New-Object System.Collections.Generic.List[object]
    foreach ($v in $vips) {
        if (-not $v.Members) { Add-Check 'Warning' "VIP $($v.Vip)" 'No Members: entry ignored by the deployment.' }
        $outside = @($v.Members | Where-Object { -not $seen.ContainsKey($_) })
        foreach ($m in $outside) { Add-Check 'Warning' "VIP $($v.Vip)" "Member '$m' is not in the server inventory (distribution.psd1)." }
        $vipRows.Add([pscustomobject]@{
            Vip            = $v.Vip
            Zone           = $v.Zone
            Members        = ($v.Members -join ', ')
            NotInInventory = ($outside -join ', ')
        })
    }

    # --- Zones ------------------------------------------------------------------------
    $zoneRows = New-Object System.Collections.Generic.List[object]
    foreach ($zk in $zoneKeys) {
        $z = $zones[$zk]
        $user = Get-CfgValue $z 'InstallAccountUserName'
        $inst = if ($user) { "$(Get-CfgValue $z 'InstallAccountSafe') / $user" } else { '(PVWA admin at launch)' }
        $placeholders = @(@($z.Values) | Where-Object { $_ -is [string] -and $_ -match '<[^>]+>' })
        if ($placeholders) { Add-Check 'Info' "Zone $zk" 'Not filled in yet (<...> placeholders).' }
        $zoneRows.Add([pscustomobject]@{
            Zone            = [string]$zk
            Pvwa            = "$(Get-CfgValue $z 'PvwaUrl') ($(Get-CfgValue $z 'PvwaAuthMethod'))"
            Vault           = [string](Get-CfgValue $z 'VaultAddress')
            InstallAccount  = $inst
            PSMConnect      = (Format-CfgValue (Get-CfgValue $z 'PSMConnectUserName'))
            PSMAdminConnect = (Format-CfgValue (Get-CfgValue $z 'PSMAdminConnectUserName'))
            Vips            = [string](@($vips | Where-Object { $_.Zone -eq $zk }).Count)
        })
    }

    # --- Media hygiene: autorun.inf is blocked by the EDR on the targets ---------------
    $mediaRel = [string](Get-CfgValue $settings 'Install.MediaRelativePath')
    if ($mediaRel) {
        $trees = @($baseRoot) + @($profiles | ForEach-Object { Join-Path $overlayRoot $_ })
        foreach ($t in $trees) {
            $f = Join-Path (Join-Path $t $mediaRel) 'autorun.inf'
            if (Test-Path -LiteralPath $f) { Add-Check 'Warning' 'Media' "$f is present: blocked by the EDR on the targets - remove it from the tree." }
        }
    }

    # --- Settings ------------------------------------------------------------------------
    $settingRows = New-Object System.Collections.Generic.List[object]
    foreach ($k in 'PsmVersion', 'Install.InstallDir', 'Install.RecordingDir', 'Install.MediaRelativePath',
                   'Rds.LicenseMode', 'Rds.LicenseServers', 'Registration.RenameComponents',
                   'Registration.AppUserPattern', 'Registration.GwUserPattern',
                   'Registration.ExistingAccountAction', 'Hardening.NonBlocking') {
        $v = Format-CfgValue (Get-CfgValue $settings $k)
        if ($k -eq 'Install.RecordingDir' -and $v -eq '(empty)') { $v = '(empty: <InstallDir>\PSM\Recordings)' }
        $settingRows.Add([pscustomobject]@{ Area = 'PSM-Deploy (settings.psd1)'; Setting = $k; Value = $v })
    }
    foreach ($k in 'SourceRoot', 'OverlayRoot', 'StagingRoot', 'TargetPath', 'TryCurrentSession',
                   'LocalAdminUserName', 'Pvwa.Url', 'Pvwa.AuthMethod') {
        $settingRows.Add([pscustomobject]@{ Area = 'PSM-Distribute (distribution.psd1)'; Setting = $k; Value = (Format-CfgValue (Get-CfgValue $dist $k)) })
    }
    foreach ($lk in @($pushLots.Keys | Sort-Object)) {
        $l = $pushLots[$lk]
        $acct = Get-CfgValue $l 'LogonName'
        if (-not $acct) { $acct = "$(Get-CfgValue $l 'UserName')@$(Get-CfgValue $l 'Address')" }
        $settingRows.Add([pscustomobject]@{ Area = 'PSM-Distribute (distribution.psd1)'; Setting = "PushAccounts.$lk"
            Value = "Match=$(Format-CfgValue (Get-CfgValue $l 'Match')), account=$acct" })
    }

    $rank = @{ Error = 0; Warning = 1; Info = 2 }
    $sorted = @($checks | Sort-Object @{ Expression = { $rank[$_.Level] } }, Topic)
    $nErr  = @($sorted | Where-Object { $_.Level -eq 'Error' }).Count
    $nWarn = @($sorted | Where-Object { $_.Level -eq 'Warning' }).Count

    return [pscustomobject]@{
        ConfigPath  = $ConfigPath
        BaseRoot    = $baseRoot
        OverlayRoot = $overlayRoot
        Summary     = ("PSM $(Format-CfgValue (Get-CfgValue $settings 'PsmVersion'))  |  $($profiles.Count) profile(s), " +
                       "$($inventory.Count) server(s), $($zoneKeys.Count) zone(s), $($vips.Count) VIP(s)  |  " +
                       "$nErr error(s), $nWarn warning(s)")
        Profiles    = $profileRows.ToArray()
        Servers     = $serverRows.ToArray()
        Zones       = $zoneRows.ToArray()
        Vips        = $vipRows.ToArray()
        Settings    = $settingRows.ToArray()
        Checks      = $sorted
        Errors      = $nErr
        Warnings    = $nWarn
    }
}

# ===========================================================================
# Console view (-NoGui)
# ===========================================================================

function Show-PSMConfigConsole {
    param([Parameter(Mandatory)] $Model)
    Write-Host ''
    Write-Host "=== PSM configuration - $($Model.ConfigPath) ===" -ForegroundColor White
    Write-Host $Model.Summary
    foreach ($p in $Model.Profiles) {
        Write-Host ''
        Write-Host "Profile $($p.Name): $(if ($p.Servers) { $p.Servers -join ', ' } else { '(no server)' })" -ForegroundColor Cyan
        Write-Host "  Overlay: $($p.Overlay)"
        if ($p.Software) { $p.Software | Format-Table Software, Origin, Mode, Staged, Optional -AutoSize | Out-String -Width 400 | Write-Host }
        else { Write-Host '  (no software)' }
    }
    Write-Host 'Servers' -ForegroundColor Cyan
    $Model.Servers | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
    Write-Host 'Zones' -ForegroundColor Cyan
    $Model.Zones | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
    Write-Host 'VIPs' -ForegroundColor Cyan
    $Model.Vips | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
    Write-Host 'Settings' -ForegroundColor Cyan
    $Model.Settings | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
    Write-Host 'Checks' -ForegroundColor Cyan
    foreach ($c in $Model.Checks) {
        $color = switch ($c.Level) { 'Error' { 'Red' } 'Warning' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  [{0,-7}] {1}: {2}" -f $c.Level, $c.Topic, $c.Detail) -ForegroundColor $color
    }
}

# ===========================================================================
# Window (WPF)
# ===========================================================================

$script:Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PSM configuration" Width="1200" Height="760" MinWidth="900" MinHeight="500"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="12" Background="#F7F7F7">
  <Window.Resources>
    <Style TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E6E6E6"/>
      <Setter Property="BorderBrush" Value="#D4D4D4"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="RowHeaderWidth" Value="0"/>
      <Setter Property="SelectionMode" Value="Single"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="6,5"/>
      <Setter Property="Background" Value="#EFEFEF"/>
      <Setter Property="BorderBrush" Value="#D4D4D4"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
    </Style>
    <Style x:Key="Wrap" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="White" BorderBrush="#D4D4D4" BorderThickness="0,0,0,1" Padding="16,10">
      <DockPanel>
        <Button Name="BtnReload" DockPanel.Dock="Right" Content="Reload" Padding="16,4" VerticalAlignment="Center"/>
        <StackPanel>
          <TextBlock Text="PSM configuration" FontSize="17" FontWeight="SemiBold"/>
          <TextBlock Name="TxtSummary" Foreground="#444" Margin="0,3,0,0"/>
          <TextBlock Name="TxtSource" Foreground="#888" Margin="0,2,0,0"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <TabControl Name="Tabs" Margin="10">
      <TabItem Header="Profiles">
        <Grid Margin="8">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="270"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <ListBox Name="LstProfiles" FontSize="13" BorderBrush="#D4D4D4"/>
          <DockPanel Grid.Column="1" Margin="14,0,0,0">
            <TextBlock Name="TxtProfileName" DockPanel.Dock="Top" FontSize="16" FontWeight="SemiBold"/>
            <TextBlock Name="TxtProfileOverlay" DockPanel.Dock="Top" Foreground="#666" Margin="0,3,0,0"/>
            <TextBlock DockPanel.Dock="Top" Text="Servers" FontWeight="SemiBold" Margin="0,12,0,2"/>
            <TextBlock Name="TxtProfileServers" DockPanel.Dock="Top" TextWrapping="Wrap"/>
            <TextBlock DockPanel.Dock="Top" Text="Software installed on these servers (common list + profile)" FontWeight="SemiBold" Margin="0,12,0,4"/>
            <DataGrid Name="GridSoftware">
              <DataGrid.RowStyle>
                <Style TargetType="DataGridRow">
                  <Style.Triggers>
                    <DataTrigger Binding="{Binding Staged}" Value="MISSING">
                      <Setter Property="Background" Value="#FDE7E9"/>
                    </DataTrigger>
                  </Style.Triggers>
                </Style>
              </DataGrid.RowStyle>
              <DataGrid.Columns>
                <DataGridTextColumn Header="Software" Binding="{Binding Software}" Width="2*"/>
                <DataGridTextColumn Header="Origin" Binding="{Binding Origin}" Width="1.5*"/>
                <DataGridTextColumn Header="Mode" Binding="{Binding Mode}" Width="Auto"/>
                <DataGridTextColumn Header="File (relative to the tree)" Binding="{Binding File}" Width="2.5*"/>
                <DataGridTextColumn Header="Staged in" Binding="{Binding Staged}" Width="Auto"/>
                <DataGridTextColumn Header="Optional" Binding="{Binding Optional}" Width="Auto"/>
                <DataGridTextColumn Header="Destination (copy)" Binding="{Binding Destination}" Width="1.5*"/>
              </DataGrid.Columns>
            </DataGrid>
          </DockPanel>
        </Grid>
      </TabItem>
      <TabItem Header="Servers">
        <DataGrid Name="GridServers" Margin="8">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Server" Binding="{Binding Server}" Width="1.2*"/>
            <DataGridTextColumn Header="Profile" Binding="{Binding Profile}" Width="Auto"/>
            <DataGridTextColumn Header="Zone" Binding="{Binding Zone}" Width="Auto"/>
            <DataGridTextColumn Header="VIP" Binding="{Binding VIP}" Width="1.6*"/>
            <DataGridTextColumn Header="Push lot (account)" Binding="{Binding PushLot}" Width="1.6*"/>
            <DataGridTextColumn Header="Software" Binding="{Binding Software}" Width="Auto"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem Header="Zones and VIPs">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <TextBlock Text="Zones (zones.psd1)" FontWeight="SemiBold" Margin="0,0,0,4"/>
          <DataGrid Name="GridZones" Grid.Row="1">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Zone" Binding="{Binding Zone}" Width="Auto"/>
              <DataGridTextColumn Header="PVWA" Binding="{Binding Pvwa}" Width="2*"/>
              <DataGridTextColumn Header="Vault (cluster,DR)" Binding="{Binding Vault}" Width="1.4*"/>
              <DataGridTextColumn Header="Install account" Binding="{Binding InstallAccount}" Width="1.3*"/>
              <DataGridTextColumn Header="PSMConnect" Binding="{Binding PSMConnect}" Width="1.4*"/>
              <DataGridTextColumn Header="PSMAdminConnect" Binding="{Binding PSMAdminConnect}" Width="1.4*"/>
              <DataGridTextColumn Header="VIPs" Binding="{Binding Vips}" Width="Auto"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock Grid.Row="2" Text="PSM VIPs - the VIP name is the SAN expected in the RDP certificate" FontWeight="SemiBold" Margin="0,14,0,4"/>
          <DataGrid Name="GridVips" Grid.Row="3">
            <DataGrid.Columns>
              <DataGridTextColumn Header="VIP" Binding="{Binding Vip}" Width="2*"/>
              <DataGridTextColumn Header="Zone" Binding="{Binding Zone}" Width="Auto"/>
              <DataGridTextColumn Header="Members" Binding="{Binding Members}" Width="2*"/>
              <DataGridTextColumn Header="Not in the inventory" Binding="{Binding NotInInventory}" Width="1.5*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="Settings">
        <DataGrid Name="GridSettings" Margin="8">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Area" Binding="{Binding Area}" Width="Auto"/>
            <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="Auto"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem Name="TabChecks" Header="Checks">
        <DataGrid Name="GridChecks" Margin="8">
          <DataGrid.RowStyle>
            <Style TargetType="DataGridRow">
              <Style.Triggers>
                <DataTrigger Binding="{Binding Level}" Value="Error">
                  <Setter Property="Background" Value="#FDE7E9"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Level}" Value="Warning">
                  <Setter Property="Background" Value="#FFF4CE"/>
                </DataTrigger>
              </Style.Triggers>
            </Style>
          </DataGrid.RowStyle>
          <DataGrid.Columns>
            <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="Auto"/>
            <DataGridTextColumn Header="Topic" Binding="{Binding Topic}" Width="Auto"/>
            <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@

function ConvertTo-PSMDataView {
    # Rows -> DataTable view: plain string columns, the canonical WPF binding source.
    param($Rows, [Parameter(Mandatory)] [string[]] $Columns)
    $table = New-Object System.Data.DataTable
    foreach ($c in $Columns) { [void]$table.Columns.Add($c, [string]) }
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $row = $table.NewRow()
        foreach ($c in $Columns) { $row[$c] = [string]$r.$c }
        $table.Rows.Add($row)
    }
    return , $table.DefaultView
}

function Update-PSMWindow {
    $m = $script:Model
    $ui = $script:Ui
    $ui.TxtSummary.Text = $m.Summary
    $ui.TxtSource.Text  = "Read from $($m.ConfigPath)  |  base $($m.BaseRoot)  |  overlays $($m.OverlayRoot)"

    $ui.LstProfiles.Items.Clear()
    foreach ($p in $m.Profiles) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = $p.Label
        $item.Tag     = $p.Name
        $item.Padding = New-Object System.Windows.Thickness 6, 4, 6, 4
        [void]$ui.LstProfiles.Items.Add($item)
    }
    if ($ui.LstProfiles.Items.Count -gt 0) { $ui.LstProfiles.SelectedIndex = 0 }
    else { $ui.TxtProfileName.Text = '(no profile declared in ServerTypes)' }

    $ui.GridServers.ItemsSource  = ConvertTo-PSMDataView $m.Servers  'Server', 'Profile', 'Zone', 'VIP', 'PushLot', 'Software'
    $ui.GridZones.ItemsSource    = ConvertTo-PSMDataView $m.Zones    'Zone', 'Pvwa', 'Vault', 'InstallAccount', 'PSMConnect', 'PSMAdminConnect', 'Vips'
    $ui.GridVips.ItemsSource     = ConvertTo-PSMDataView $m.Vips     'Vip', 'Zone', 'Members', 'NotInInventory'
    $ui.GridSettings.ItemsSource = ConvertTo-PSMDataView $m.Settings 'Area', 'Setting', 'Value'
    $ui.GridChecks.ItemsSource   = ConvertTo-PSMDataView $m.Checks   'Level', 'Topic', 'Detail'
    $ui.TabChecks.Header = "Checks ($($m.Errors) error(s), $($m.Warnings) warning(s))"
}

function Show-PSMProfile {
    $item = $script:Ui.LstProfiles.SelectedItem
    if (-not $item) { return }
    $p = @($script:Model.Profiles | Where-Object { $_.Name -eq $item.Tag }) | Select-Object -First 1
    if (-not $p) { return }
    $script:Ui.TxtProfileName.Text    = "Profile $($p.Name)"
    $script:Ui.TxtProfileOverlay.Text = "Overlay: $($p.Overlay)"
    $script:Ui.TxtProfileServers.Text = $(if ($p.Servers) { $p.Servers -join ', ' } else { '(no server assigned)' })
    $script:Ui.GridSoftware.ItemsSource = ConvertTo-PSMDataView $p.Software 'Software', 'Origin', 'Mode', 'File', 'Staged', 'Optional', 'Destination'
}

function Show-PSMConfigWindow {
    param([Parameter(Mandatory)] [string] $ConfigPath)
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The window needs an STA thread: run powershell.exe -STA -File .\Show-PSMConfig.ps1 (or use -NoGui).'
    }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$script:Xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)
    $script:Ui = @{}
    foreach ($n in 'BtnReload', 'TxtSummary', 'TxtSource', 'LstProfiles', 'TxtProfileName', 'TxtProfileOverlay',
                   'TxtProfileServers', 'GridSoftware', 'GridServers', 'GridZones', 'GridVips', 'GridSettings',
                   'GridChecks', 'TabChecks') {
        $script:Ui[$n] = $window.FindName($n)
    }
    $script:Ui.LstProfiles.Add_SelectionChanged({
        try { Show-PSMProfile }
        catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'PSM configuration') | Out-Null }
    })
    $script:Ui.BtnReload.Add_Click({
        try { $script:Model = New-PSMConfigModel -ConfigPath $ConfigPath; Update-PSMWindow }
        catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'PSM configuration - reload failed') | Out-Null }
    })
    Update-PSMWindow
    [void]$window.ShowDialog()
}

# ===========================================================================
# Main
# ===========================================================================

$script:Model = New-PSMConfigModel -ConfigPath $ConfigPath
if ($PassThru) { return $script:Model }
if ($NoGui)    { Show-PSMConfigConsole -Model $script:Model; return }
Show-PSMConfigWindow -ConfigPath $ConfigPath
