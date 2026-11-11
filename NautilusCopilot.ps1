# Registry helper functions
function Set-RegistryValue($Path, $Name, $Type, $Data) {
    reg add "$Path" /v "$Name" /t "$Type" /d "$Data" /f 2>$null | Out-Null
}
function Remove-RegistryValue($Path, $Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) {
        reg delete "$Path" /f 2>$null | Out-Null
    } else {
        reg delete "$Path" /v "$Name" /f 2>$null | Out-Null
    }
}

function Enable-ProcessPrivileges {
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;
    public class TokenManipulator {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
        public static void AddPrivilege(string privilege) {
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            OpenProcessToken(hproc, 0x0028, ref htok);
            TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = 0x00000002 };
            LookupPrivilegeValue(null, privilege, ref tp.Luid);
            AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
    }
"@
    if (-not ([System.Management.Automation.PSTypeName]'TokenManipulator').Type) {
        Add-Type -TypeDefinition $Definition
    }
    [TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege")
    [TokenManipulator]::AddPrivilege("SeRestorePrivilege")
    [TokenManipulator]::AddPrivilege("SeBackupPrivilege")
}

function Unlock-OfflineCbsPackages {
    param (
        [string]$MountPath,
        [string[]]$TargetPatterns
    )
    Enable-ProcessPrivileges
    $AdminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $AdminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $AdminSID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )

    reg load HKLM\zSOFTWARE "$MountPath\Windows\System32\config\SOFTWARE" 2>$null | Out-Null
    try {
        $CbsBaseKey = "zSOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        $BaseHive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($CbsBaseKey, $true)
        if (-not $BaseHive) { return }

        $AllPkgNames = $BaseHive.GetSubKeyNames()
        foreach ($Pattern in $TargetPatterns) {
            $MatchedPkgs = $AllPkgNames | Where-Object { $_ -like $Pattern }
            foreach ($PkgName in $MatchedPkgs) {
                $PkgRelativePath = "$CbsBaseKey\$PkgName"
                
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    $PkgRelativePath,
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::TakeOwnership
                )
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
                    $Acl.SetOwner($AdminSID)
                    $RegKey.SetAccessControl($Acl)
                    $RegKey.Close()
                }

                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    $PkgRelativePath,
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::ChangePermissions
                )
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    $Acl.AddAccessRule($AdminRule)
                    $RegKey.SetAccessControl($Acl)
                    $RegKey.Close()
                }

                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($PkgRelativePath, $true)
                if ($RegKey) {
                    $RegKey.SetValue("Visibility", 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                    $RegKey.DeleteValue("DefVis", $false)
                    
                    if ($RegKey.GetSubKeyNames() -contains "Owners") {
                        $OwnersKey = $RegKey.OpenSubKey("Owners", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
                        if ($OwnersKey) {
                            $OAcl = $OwnersKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
                            $OAcl.SetOwner($AdminSID)
                            $OwnersKey.SetAccessControl($OAcl)
                            $OwnersKey.Close()
                        }
                        $OwnersKey = $RegKey.OpenSubKey("Owners", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                        if ($OwnersKey) {
                            $OAcl = $OwnersKey.GetAccessControl()
                            $OAcl.AddAccessRule($AdminRule)
                            $OwnersKey.SetAccessControl($OAcl)
                            $OwnersKey.Close()
                        }
                        $RegKey.DeleteSubKeyTree("Owners", $false)
                    }
                    $RegKey.Close()
                }
            }
        }
        $BaseHive.Close()
    } finally {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        reg unload HKLM\zSOFTWARE 2>$null | Out-Null
    }
}

function Get-OscdimgPath {
    $candidates = @(
        "$env:SystemRoot\System32\oscdimg.exe",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "$env:ProgramFiles(x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe",
        "$env:ProgramFiles(x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $cmd = Get-Command oscdimg.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

# Phase 1: Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You must run PowerShell with Administrator privileges!" -ForegroundColor Red
    Pause
    Exit
}

# Phase 2: Build configuration
Clear-Host
Write-Host "=== PastelPink Nautilus w/ Administrator ===" -ForegroundColor Cyan
Write-Host "=== for Windows 11 (and CopilotAI) ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] THIS PROJECT IS NOT AFFILIATED WITH MICROSOFT:" -ForegroundColor Yellow
Write-Host "    PastelPink Nautilus is an independent open-source utility and is NOT endorsed," -ForegroundColor White
Write-Host "    sponsored, or officially connected to Microsoft Corporation." -ForegroundColor White
Write-Host "    'Windows' is a registered trademark of Microsoft Corporation." -ForegroundColor White
Write-Host ""
Write-Host "[!] INTENDED USAGE & DISTRIBUTION WARNING:" -ForegroundColor Yellow
Write-Host "    This script is designed for personal, local image creation." -ForegroundColor White
Write-Host "    Redistributing modified ISOs to third parties, especially without a clear" -ForegroundColor White
Write-Host "    understanding of removed packages, dependencies, or security risks," -ForegroundColor White
Write-Host "    is not recommended. Always use official media and valid licenses." -ForegroundColor White
Write-Host ""
Write-Host "[!] DISCLAIMER OF WARRANTY (AS-IS):" -ForegroundColor Yellow
Write-Host "    This tool modifies core system components and is provided 'AS IS'," -ForegroundColor White
Write-Host "    without warranty of any kind. Modifying system packages may lead to" -ForegroundColor White
Write-Host "    instability or update failures. Use entirely at your own risk." -ForegroundColor White
Write-Host ""
Write-Host "    Thanks for using Nautilus :D, we appreciate all of your support! <3"
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "`n=== Build configuration ===" -ForegroundColor Yellow

$WorkspaceInput = Read-Host "-> Enter workspace path (Default: C:\NautilusBuilder)"
if ([string]::IsNullOrWhiteSpace($WorkspaceInput)) { 
    $Workspace = "C:\NautilusBuilder" 
} else { 
    $Workspace = $WorkspaceInput 
}
$MountDir = "$Workspace\Mount"
$ExtractDir = "$Workspace\Extract"

$IsoPath = Read-Host "-> Enter the path of the original ISO (Example: C:\Windows11.iso)"
if (!(Test-Path $IsoPath -PathType Leaf)) {
    Write-Host "Cannot find the ISO, please check the path again :3" -ForegroundColor Red
    Exit
}

$FinalISO = Read-Host "-> Enter output ISO path (Default: C:\Nautilus.iso)"
if ([string]::IsNullOrWhiteSpace($FinalISO)) { $FinalISO = "C:\Nautilus.iso" }

$CompressionChoice = Read-Host "-> Compression: [1] WIM [2] ESD (Default: 1)"
if ([string]::IsNullOrWhiteSpace($CompressionChoice)) { $CompressionChoice = "1" }

$InjectDriver = Read-Host "-> Inject drivers into ISO? [Y/N] (Default: N)"
if ([string]::IsNullOrWhiteSpace($InjectDriver)) { $InjectDriver = "N" }
$UseDriverInjection = ($InjectDriver.Trim().ToUpperInvariant() -eq "Y")
$AutoScanDrivers = $false
$DriverFolder = ""

if ($UseDriverInjection) {
    $DriverInput = Read-Host "-> Driver folder path (Leave blank to auto-export from current system)"
    if ([string]::IsNullOrWhiteSpace($DriverInput)) {
        $AutoScanDrivers = $true
        $DriverFolder = "$Workspace\AutoDrivers"
    } elseif (Test-Path $DriverInput -PathType Container) {
        $DriverFolder = $DriverInput
    } else {
        Write-Host "  [!] Driver folder does not exist! Driver injection will be disabled." -ForegroundColor Red
        $UseDriverInjection = $false
    }
}

$HardwareBypass = Read-Host "-> Enable hardware bypass (TPM/CPU/Secure Boot)? [Y/N]"
if ([string]::IsNullOrWhiteSpace($HardwareBypass)) { $HardwareBypass = "N" }
$HardwareBypass = $HardwareBypass.Trim().ToUpperInvariant()

$AggressiveDebloat = Read-Host "-> Use aggressive debloat? [Y/N]"
if ([string]::IsNullOrWhiteSpace($AggressiveDebloat)) { $AggressiveDebloat = "N" }
$AggressiveDebloat = $AggressiveDebloat.Trim().ToUpperInvariant()

$DriverDisplay = if (-not $UseDriverInjection) { 'Disabled' } elseif ($AutoScanDrivers) { 'Exporting installed drivers' } else { $DriverFolder }

Write-Host ""
Write-Host "============================================"
Write-Host "Selected configuration:" -ForegroundColor Cyan
Write-Host "  - Workspace: $Workspace" -ForegroundColor DarkGray
Write-Host "  - ISO: $IsoPath" -ForegroundColor DarkGray
Write-Host "  - Output ISO: $FinalISO" -ForegroundColor DarkGray
Write-Host "  - Compression: $CompressionChoice" -ForegroundColor DarkGray
Write-Host "  - Drivers: $DriverDisplay" -ForegroundColor DarkGray
Write-Host "  - Hardware bypass: $HardwareBypass" -ForegroundColor DarkGray
Write-Host "  - Aggressive debloat: $AggressiveDebloat" -ForegroundColor DarkGray
Write-Host "============================================"
Write-Host ""

$ConfirmBuild = Read-Host "Start build now? [Y/N]"
Write-Host ""
if ([string]::IsNullOrWhiteSpace($ConfirmBuild)) { $ConfirmBuild = "N" }
if ($ConfirmBuild.Trim().ToUpperInvariant() -ne "Y") {
    Write-Host "Build cancelled by user." -ForegroundColor Yellow
    Exit
}

# Phase 3: Cleaning up previous workspaces
Write-Host "[*] Cleaning up previous workspaces..." -ForegroundColor DarkGray
reg unload HKLM\zCOMPONENTS 2>$null | Out-Null
reg unload HKLM\zDEFAULT 2>$null | Out-Null
reg unload HKLM\zNTUSER 2>$null | Out-Null
reg unload HKLM\zSOFTWARE 2>$null | Out-Null
reg unload HKLM\zSYSTEM 2>$null | Out-Null
dism.exe /Cleanup-Wim /Quiet | Out-Null
dism.exe /Cleanup-Mountpoints /Quiet | Out-Null

if (Test-Path $Workspace) { 
    Remove-Item -Path $Workspace -Recurse -Force -ErrorAction SilentlyContinue 
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force -Path $MountDir | Out-Null
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

$BootDriverFolder = "$Workspace\BootDrivers"

if ($UseDriverInjection) {
    if ($AutoScanDrivers) {
        Write-Host "  - Exporting third-party drivers from host system..." -ForegroundColor DarkGray
        New-Item -ItemType Directory -Force -Path $DriverFolder | Out-Null
        try {
            Export-WindowsDriver -Online -Destination $DriverFolder -ErrorAction Stop | Out-Null
            Write-Host "  - Host drivers exported to: $DriverFolder" -ForegroundColor Green
        } catch {
            Write-Host "  - Export failed: $($_.Exception.Message). Skipping driver injection." -ForegroundColor Yellow
            $UseDriverInjection = $false
        }
    } elseif (-not (Test-Path $DriverFolder -PathType Container)) {
        Write-Host "  - Driver folder '$DriverFolder' does not exist! Skipping driver injection." -ForegroundColor Yellow
        $UseDriverInjection = $false
    }

    if ($UseDriverInjection) {
        New-Item -ItemType Directory -Force -Path $BootDriverFolder | Out-Null
        $BootCriticalClasses = @('SCSIAdapter', 'HDC', 'Volume', 'USB', 'Net', 'HIDClass', 'Mouse', 'Keyboard', 'System')
        
        Write-Host "  - Filtering boot-critical drivers (Storage/NVMe/USB/Net) for boot.wim..." -ForegroundColor DarkGray
        $AllInfs = Get-ChildItem -Path $DriverFolder -Recurse -Filter "*.inf" -File -ErrorAction SilentlyContinue
        
        foreach ($Inf in $AllInfs) {
            $Header = Get-Content -Path $Inf.FullName -TotalCount 60 -ErrorAction SilentlyContinue
            $ClassMatch = $Header | Select-String -Pattern '^\s*Class\s*=\s*([a-zA-Z0-9_\-]+)' | Select-Object -First 1
            
            if ($ClassMatch) {
                $DriverClass = $ClassMatch.Matches[0].Groups[1].Value.Trim()
                if ($BootCriticalClasses -contains $DriverClass) {
                    $DestSubDir = Join-Path $BootDriverFolder $Inf.Directory.Name
                    if (-not (Test-Path $DestSubDir)) {
                        Copy-Item -Path $Inf.Directory.FullName -Destination $DestSubDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

# Phase 4: Mounting ISO and copying
Write-Host "`n[1/15] Mounting ISO and copying contents into the workspace..." -ForegroundColor Yellow
$IsoImage = Mount-DiskImage -ImagePath $IsoPath -PassThru
$IsoDrive = ($IsoImage | Get-Volume).DriveLetter + ":"

robocopy "$IsoDrive\" "$ExtractDir" /E /MT:8 /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null

Dismount-DiskImage -ImagePath $IsoPath | Out-Null
$InstallSystem = "wim"
if (Test-Path "$ExtractDir\sources\install.esd") {
    $InstallSystem = "esd"
}
Set-ItemProperty -Path "$ExtractDir\sources\install.$InstallSystem" -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$ExtractDir\sources\boot.wim" -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

# Phase 5: Choosing index
Write-Host "`n[2/15] List of available Windows SKUs:" -ForegroundColor Yellow
dism.exe /Get-WimInfo /WimFile:"$ExtractDir\sources\install.$InstallSystem"
$WimIndex = Read-Host "-> Enter the index number you want to build (e.g., 6)"
if ([string]::IsNullOrWhiteSpace($WimIndex)) { $WimIndex = "1" }

if ($InstallSystem -eq "esd") {
    Write-Host "`n[!] Detected install.esd (Read-Only format). Converting Index $WimIndex to install.wim first..." -ForegroundColor Cyan
    $TempWim = "$ExtractDir\sources\install.wim"
    dism.exe /Export-Image /SourceImageFile:"$ExtractDir\sources\install.esd" /SourceIndex:$WimIndex /DestinationImageFile:"$TempWim" /Compress:fast
    Remove-Item -Path "$ExtractDir\sources\install.esd" -Force
    $InstallSystem = "wim"
    $WimIndex = "1"
}

Write-Host "`n[3/15] Mounting install.wim (Index $WimIndex)..." -ForegroundColor Yellow
dism.exe /Mount-Image /ImageFile:"$ExtractDir\sources\install.wim" /Index:$WimIndex /MountDir:"$MountDir" /Optimize

Write-Host "`n[SCAN] Inspecting system inventory before debloat..." -ForegroundColor Cyan
$CapabilityReport = Join-Path $Workspace "capabilities-before.txt"
$FeatureReport    = Join-Path $Workspace "features-before.txt"
$PackageReport    = Join-Path $Workspace "packages-before.txt"

$InstalledCapabilities = Get-WindowsCapability -Path $MountDir -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Installed" }
if ($InstalledCapabilities) {
    $InstalledCapabilities.Name | Out-File -FilePath $CapabilityReport -Encoding UTF8
    Write-Host "  - Capabilities found: $($InstalledCapabilities.Count) (Saved to capabilities-before.txt)" -ForegroundColor DarkGray
}
$InstalledFeatures = Get-WindowsOptionalFeature -Path $MountDir -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Enabled" }
if ($InstalledFeatures) {
    $InstalledFeatures.FeatureName | Out-File -FilePath $FeatureReport -Encoding UTF8
    Write-Host "  - Optional Features found: $($InstalledFeatures.Count) (Saved to features-before.txt)" -ForegroundColor DarkGray
}

$PackageScan = dism.exe /Image:"$MountDir" /Get-Packages /English
$PackageScan | Out-File -FilePath $PackageReport -Encoding UTF8
$PkgNames = $PackageScan | Select-String "Package Identity : " | ForEach-Object { $_.Line.Replace("Package Identity : ", "").Trim() }
Write-Host "  - CBS Packages found: $($PkgNames.Count) (Saved to packages-before.txt)" -ForegroundColor DarkGray

Write-Host "  - Deep scanning hidden CBS Packages (Registry direct mapping)..." -ForegroundColor DarkGray
$HiddenPkgReport = Join-Path $Workspace "hidden-packages-before.txt"

reg load HKLM\zSOFTWARE "$MountDir\Windows\System32\config\SOFTWARE" 2>$null | Out-Null
try {
    $CbsBaseKey = "zSOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    $BaseHive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($CbsBaseKey)
    if ($BaseHive) {
        $AllPkgNames = $BaseHive.GetSubKeyNames()
        
        $FilteredPkgs = $AllPkgNames | Where-Object {
            $_ -notlike "Package_for_RollupFix*" -and
            $_ -notlike "Package_for_ServicingStack*" -and
            $_ -notlike "Package_for_KB*"
        }
        
        $FilteredPkgs | Out-File -FilePath $HiddenPkgReport -Encoding UTF8
        Write-Host "  - Hidden/Deep CBS Packages found: $($FilteredPkgs.Count) (Saved to hidden-packages-before.txt)" -ForegroundColor DarkGray
        $BaseHive.Close()
    }
} finally {
    reg unload HKLM\zSOFTWARE 2>$null | Out-Null
}

# Phase 6: Debloating

$AdminGroup = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value

Write-Host "`n[4/15] Debloating system apps..." -ForegroundColor Yellow

Write-Host "  - Dynamically scanning and removing UWP/APPX apps..."

$KeepApps = @(
    "Microsoft.DesktopAppInstaller",
    "Microsoft.AV1VideoExtension",
    "Microsoft.AVCEncoderVideoExtension",
    "Microsoft.HEIFImageExtension",
    "Microsoft.HEVCVideoExtension",
    "Microsoft.MPEG2VideoExtension",
    "Microsoft.Paint",
    "Microsoft.RawImageExtension",
    "Microsoft.VP9VideoExtensions",
    "Microsoft.WebMediaExtensions",
    "Microsoft.WebpImageExtension",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsNotepad",
    "Microsoft.NET.Native",
    "Microsoft.SecHealthUI",
    "Microsoft.Services.Store.Engagement",
    "Microsoft.StorePurchaseApp",
    "Microsoft.UI.Xaml",
    "Microsoft.VCLibs",
    "Microsoft.WindowsAppRuntime"
)

$InstalledAppx = Get-AppxProvisionedPackage -Path $MountDir -ErrorAction SilentlyContinue
foreach ($App in $InstalledAppx) {
    $IsKept = $false
    foreach ($Keep in $KeepApps) {
        if ($App.DisplayName -match $Keep -or $App.PackageName -match $Keep) {
            $IsKept = $true
            break
        }
    }
    if (-not $IsKept) {
        Write-Host "  - Removing: $($App.DisplayName)" -ForegroundColor DarkGray
        Remove-AppxProvisionedPackage -Path $MountDir -PackageName $App.PackageName -ErrorAction SilentlyContinue | Out-Null
    } else {
        Write-Host "  - Keeping : $($App.DisplayName)" -ForegroundColor Green
    }
}

Write-Host "  - Optimizing remaining AppX packages (Hardlink deduplication)..." -ForegroundColor Cyan
dism.exe /Image:"$MountDir" /Optimize-ProvisionedAppxPackages /Quiet | Out-Null

Write-Host "`n[5/15] Removing Edge and OneDrive..." -ForegroundColor Yellow

$EdgePaths = @(
    "$MountDir\Program Files (x86)\Microsoft\Edge",
    "$MountDir\Program Files (x86)\Microsoft\EdgeUpdate",
    "$MountDir\Program Files (x86)\Microsoft\EdgeCore",
    "$MountDir\Windows\System32\Microsoft-Edge-Webview"
)

foreach ($Path in $EdgePaths) {
    if (Test-Path $Path) {
        Write-Host "  - Removed $Path" -ForegroundColor DarkGray
        takeown.exe /F $Path /R /A /D Y 2>$null | Out-Null
        icacls.exe $Path /grant "$($AdminGroup):(F)" /T /C /Q 2>$null | Out-Null
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$OneDrivePaths = @(
    "$MountDir\Windows\System32\OneDriveSetup.exe",
    "$MountDir\Windows\SysWOW64\OneDriveSetup.exe"
)

foreach ($Path in $OneDrivePaths) {
    if (Test-Path $Path) {
        if ((Get-Item $Path) -is [System.IO.DirectoryInfo]) {
            takeown.exe /F $Path /R /A /D Y 2>$null | Out-Null
            icacls.exe $Path /grant "$($AdminGroup):(F)" /T /C /Q 2>$null | Out-Null
        } else {
            takeown.exe /F $Path /A 2>$null | Out-Null
            icacls.exe $Path /grant "$($AdminGroup):(F)" /C /Q 2>$null | Out-Null
        }
        
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue

        if (!(Test-Path $Path)) {
            Write-Host "  - Removed $Path" -ForegroundColor DarkGray
        } else {
            Write-Host "  - Failed to remove $Path" -ForegroundColor Red
        }
    }
}

Write-Host "`n[6/15] Unlocking DMA Region Policy & Purging Optional Features..." -ForegroundColor Yellow

$DmaPolicyJson = "$MountDir\Windows\System32\IntegratedServicesRegionPolicySet.json"
if (Test-Path $DmaPolicyJson) {
    Write-Host "  - Unlocking IntegratedServicesRegionPolicySet.json (DMA Mode)..." -ForegroundColor DarkGray
    takeown.exe /F "$DmaPolicyJson" /A 2>$null | Out-Null
    icacls.exe "$DmaPolicyJson" /grant "*S-1-5-32-544:(F)" /C /Q 2>$null | Out-Null
    $JsonRaw = Get-Content -Path $DmaPolicyJson -Raw -Encoding UTF8
    $JsonRaw = $JsonRaw -replace '"defaultState"\s*:\s*"disabled"', '"defaultState": "enabled"'
    $JsonRaw | Set-Content -Path $DmaPolicyJson -Encoding UTF8 -Force
}

$OptionalFeatures = @(
    "Printing-Foundation-InternetPrinting-Client",
    "Printing-XPSServices-Features",
    "Printing-PrintToPDFServices-Features",
    "WorkFolders-Client",
    "SMB1Protocol",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
    "SMB1Protocol-Deprecation",
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
    "MSRDC-Infrastructure",
    "MediaPlayback",
    "WindowsMediaPlayer"
)

$AvailableFeatures = Get-WindowsOptionalFeature -Path $MountDir -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne "DisabledWithPayloadRemoved" }

foreach ($FeatName in $OptionalFeatures) {
    if ($AvailableFeatures.FeatureName -contains $FeatName) {
        Write-Host "  - Purging $FeatName" -ForegroundColor DarkGray
        Disable-WindowsOptionalFeature -Path $MountDir -FeatureName $FeatName -Remove -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }
}

Write-Host "`n[7/15] Removing Windows Capabilities (FOD)..." -ForegroundColor Yellow

$CapabilityPatterns = @(
    "App.StepsRecorder*",
    "App.Support.QuickAssist*",
    "Browser.InternetExplorer*",
    "MathRecognizer*",
    "Media.WindowsMediaPlayer*",
    "Microsoft.Wallpapers.Extended*",
    "Microsoft.Windows.PowerShell.ISE*",
    "Microsoft.Windows.WordPad*",
    "OneCoreUAP.OneSync*",
    "Print.Management.Console*",
    "WMI-SNMP-Provider*",
    "VBSCRIPT*"
)

if ($AggressiveDebloat -eq "Y") {
    $CapabilityPatterns += @(
        "Language.Handwriting*",
        "Language.OCR*",
        "Language.Speech*",
        "Language.TextToSpeech*",
        "Rsat.*"
    )
}

$CurrentCapabilities = Get-WindowsCapability -Path $MountDir -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Installed" -and $_.Name -notlike "*Language.Basic*" }

foreach ($Cap in $CurrentCapabilities) {
    foreach ($Pat in $CapabilityPatterns) {
        if ($Cap.Name -like $Pat) {
            Write-Host "  - Removing $($Cap.Name)" -ForegroundColor DarkGray
            Remove-WindowsCapability -Path $MountDir -Name $Cap.Name -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
}

# Phase 7: Removing System Packages
Write-Host "`n[8/15] Unlocking Hidden CBS Packages & Deep Cleaning via DISM..." -ForegroundColor Yellow

$CbsTargetPatterns = @(
    "*OneDrive-Setup*",
    "*OneDrive-Setup-Package*",
    "*Internet-Browser-Package*",
    "*InternetExplorer-Optional*",
    "*InternetExplorer*",
    "*QuickAssist*",
    "*StepsRecorder*",
    "*TabletPCMath*",
    "*Wallpaper-Content-Extended*",
    "*WordPad*",
    "*RemoteAssistance*",
    "*Printing-XPSServices*",
    "*Printing-XpsDocumentWriter*",
    "*FaxServices*",
    "*ContactSupport*",
    "*WorkFolders*",
    "*RetailDemo*",
    "*FlipGridPWA*",
    "*OutlookPWA*",
    "*CEIPEnable*",
    "*Recall*"
)

if ($AggressiveDebloat -eq "Y") {
    $CbsTargetPatterns += @(
        "*LanguageFeatures-Handwriting*",
        "*LanguageFeatures-OCR*",
        "*LanguageFeatures-Speech*",
        "*LanguageFeatures-TextToSpeech*",
        "*MediaPlayer*",
        "*PowerShell-ISE*",
        "*OpenSSH-Server*",
        "*Application-Experience*",
        "*Customer-Experience-Improvement*",
        "*Windows-Error-Reporting*"
    )
}

Write-Host "  - Unlocking CBS Registry locks (Visibility & Owners) for target packages..." -ForegroundColor Cyan
Unlock-OfflineCbsPackages -MountPath $MountDir -TargetPatterns $CbsTargetPatterns

Write-Host "  - Querying unlocked CBS packages (Installed & Staged) via DISM..." -ForegroundColor DarkGray
$UnlockedPackages = Get-WindowsPackage -Path $MountDir -ErrorAction SilentlyContinue |
    Where-Object {
        $_.PackageState -in @("Installed", "Staged") -and
        $_.PackageName -notlike "Package_for_RollupFix*" -and
        $_.PackageName -notlike "Package_for_ServicingStack*" -and
        $_.PackageName -notlike "Package_for_DotNetRollup*" -and
        $_.PackageName -notlike "Package_for_KB*"
    }

foreach ($Pkg in $UnlockedPackages) {
    foreach ($Pattern in $CbsTargetPatterns) {
        if ($Pkg.PackageName -like $Pattern) {
            Write-Host "  - [DISM CBS] Purging $($Pkg.PackageState) package: $($Pkg.PackageName)" -ForegroundColor DarkGray
            dism.exe /Image:"$MountDir" /Remove-Package /PackageName:"$($Pkg.PackageName)" /Quiet /NoRestart | Out-Null
            break
        }
    }
}

dism.exe /Image:"$MountDir" /Remove-Edge /Quiet /NoRestart 2>$null | Out-Null

Write-Host "  - [DISM] Purging orphaned Default App Associations..." -ForegroundColor DarkGray
$AssocFile = "$Workspace\appassoc.xml"
dism.exe /Image:"$MountDir" /Export-DefaultAppAssociations:"$AssocFile" | Out-Null
if (Test-Path $AssocFile) {
    $AssocContent = Get-Content -Path $AssocFile
    $CleanAssoc = $AssocContent | Where-Object { $_ -notmatch 'AppX|MicrosoftEdge|Zune|Bing|Xbox' }
    $CleanAssoc | Set-Content -Path $AssocFile -Force
    dism.exe /Image:"$MountDir" /Import-DefaultAppAssociations:"$AssocFile" | Out-Null
}

# Phase 8: Registry settings
Write-Host "`n[9/15] Applying hardware requirement bypasses and registry changes..." -ForegroundColor Yellow
try {
    reg load HKLM\zCOMPONENTS "$MountDir\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "$MountDir\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "$MountDir\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "$MountDir\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "$MountDir\Windows\System32\config\SYSTEM" | Out-Null

    Write-Host "  - Bypassing Hardware Requirements..."
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'
    
    Write-Host "  - Disabling Sponsored Apps & Content Delivery..."
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'OemPreInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEverEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'ContentDeliveryAllowed' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'FeatureManagementEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContentEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338387Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenOverlayEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' 'ConfigureStartPins' 'REG_SZ' '{\"pinnedList\": [{}]}'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'
    Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
    Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
    
    Write-Output "  - Enabling Local Accounts on OOBE..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'OOBELocalAccount' 'REG_SZ' 'start ms-cxh:localonly'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'
    
    Write-Output "  - Disabling Reserved Storage..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'
    
    Write-Output "  - Disabling BitLocker Device Encryption..."
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'
    
    Write-Output "  - Disabling Services..."
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\SysMain' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\DiagTrack' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\DPS' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\WdiServiceHost' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\WdiSystemHost' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\PcaSvc' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\TrkWks' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\MapsBroker' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\WerSvc' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\SDRSVC' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\wbengine' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\fhsvc' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\wisvc' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\RemoteRegistry' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\PhoneSvc' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\RetailDemo' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\shpamsvc' 'Start' 'REG_DWORD' '4'

    Write-Output "  - Disabling Chat..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'
    
    Write-Output "  - Disabling Telemetry..."
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' 'Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' 'Start' 'REG_DWORD' '4'
    
    Write-Output "  - Preventing installation of apps..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
    Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
    Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
    Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe' 'OutlookUpdate'
    Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe' 'DevHomeUpdate'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'
    
    Write-Output "  - Disabling Folder Auto Discovery..."
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell' 'FolderType' 'REG_SZ' 'NotSpecified'
    
    Write-Output "  - Disabling Search Highlights..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' 'IsDynamicSearchBoxEnabled' 'REG_DWORD' '0'
    
    Write-Output "  - Disabling Bing..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' 'CortanaConsent' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' 'REG_DWORD' '0'
    
    Write-Output "  - Disabling OneDrive registries..."
    Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}'
    Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup'
    Set-RegistryValue "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "REG_DWORD" "1"

    Write-Output "  - Disabling Start Menu Iris recommendation..."
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_IrisRecommendations' 'REG_DWORD' '0'
    
    Write-Output "  - Disabling GameDVR and Xbox Game Bar..."
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\BcastDVRUserService' 'Start' 'REG_DWORD' '4'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\GameBarPresenceWriter' 'Start' 'REG_DWORD' '4'
    
    Write-Output "  - Deleting Edge related registries..."
    Remove-RegistryValue "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
    Remove-RegistryValue "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\EdgeUpdate' 'DoNotUpdateToEdgeWithChromium' 'REG_DWORD' '1'

    Write-Output "  - Disabling HR, Hibernation..."
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Power' 'HibernateEnabledDefault' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Power' 'HibernateEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' 'DisableSR' 'REG_DWORD' '1'
    
    Write-Output "  - Deleting Telemetry Scheduled Tasks..."
    $tasksPath = "$MountDir\Windows\System32\Tasks"
    Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" -Force -ErrorAction SilentlyContinue
}
finally {
    reg unload HKLM\zCOMPONENTS 2>$null | Out-Null
    reg unload HKLM\zDEFAULT 2>$null | Out-Null
    reg unload HKLM\zNTUSER 2>$null | Out-Null
    reg unload HKLM\zSOFTWARE 2>$null | Out-Null
    reg unload HKLM\zSYSTEM 2>$null | Out-Null
    [GC]::Collect()
    Start-Sleep -Seconds 3
}

# Phase 9: Driver Injection
Write-Host "`n[10/15] Injecting full hardware drivers into install.wim..." -ForegroundColor Yellow
if ($UseDriverInjection) {
    $InfCount = (Get-ChildItem -Path $DriverFolder -Recurse -Filter "*.inf" -File -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($InfCount -gt 0) {
        Write-Host "  - Injecting $InfCount INF files into offline OS..." -ForegroundColor DarkGray
        dism.exe /Image:"$MountDir" /Add-Driver /Driver:"$DriverFolder" /Recurse /ForceUnsigned | Out-Null
        Write-Host "  - OS driver injection completed." -ForegroundColor Green
    }
}

# Phase 10: ResetBase
Write-Host "`n[11/15] Deep cleaning image components (ResetBase)..." -ForegroundColor Yellow

Write-Host "  - [DISM] Disabling Reserved Storage..." -ForegroundColor DarkGray
dism.exe /Image:"$MountDir" /Set-ReservedStorageState /State:Disabled /Quiet | Out-Null

reg load HKLM\zSOFTWARE "$MountDir\Windows\System32\config\SOFTWARE" 2>$null | Out-Null
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' 'DisableResetbase' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' 'SupersededActions' 'REG_DWORD' '1'
reg unload HKLM\zSOFTWARE 2>$null | Out-Null

Write-Host "  - Executing DISM Component Cleanup & ResetBase..." -ForegroundColor Cyan
dism.exe /Image:"$MountDir" /Cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "  - Cleaning up temporary servicing caches..." -ForegroundColor DarkGray
Remove-Item -Path "$MountDir\Windows\WinSxS\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$MountDir\Windows\WinSxS\InstallTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$MountDir\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$MountDir\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue

# Phase 11: Saving & Exporting
Write-Host "`n[12/15] Saving changes to install.$InstallSystem..." -ForegroundColor Yellow
dism.exe /Unmount-Image /MountDir:"$MountDir" /Commit | Out-Null

Write-Host "`n[!] Compression mode selected:" -ForegroundColor Cyan
Write-Host "   [1] WIM (Fast and recommended)" -ForegroundColor Cyan
Write-Host "   [2] ESD (Slow, smallest size)" -ForegroundColor Cyan

$Choice = $CompressionChoice
$DestExt = if ($Choice -eq '2') { "esd" } else { "wim" }
$CompressType = if ($Choice -eq '2') { "recovery" } else { "max" }

$SourceFile = "$ExtractDir\sources\install.$InstallSystem"
$OptimizedFile = "$ExtractDir\sources\install_optimized.$DestExt"

Write-Host "  - Exporting and optimizing to install.$DestExt..." -ForegroundColor DarkGray
dism.exe /Export-Image /SourceImageFile:$SourceFile /SourceIndex:$WimIndex /DestinationImageFile:$OptimizedFile /Compress:$CompressType | Out-Null

Remove-Item -Path $SourceFile -Force
Rename-Item -Path $OptimizedFile -NewName "install.$DestExt"

$InstallSystem = $DestExt

# Phase 12: Bypass
Write-Host "`n[13/15] Mounting boot.wim (Index 2) for Hardware Bypass & Storage Drivers..." -ForegroundColor Yellow
dism.exe /Mount-Image /ImageFile:"$ExtractDir\sources\boot.wim" /Index:2 /MountDir:"$MountDir" /Optimize

if ($UseDriverInjection -and (Test-Path $BootDriverFolder)) {
    $BootInfCount = (Get-ChildItem -Path $BootDriverFolder -Recurse -Filter "*.inf" -File -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($BootInfCount -gt 0) {
        Write-Host "  - Injecting $BootInfCount boot-critical INF files (NVMe/VMD/USB/Net) into WinPE..." -ForegroundColor Cyan
        dism.exe /Image:"$MountDir" /Add-Driver /Driver:"$BootDriverFolder" /Recurse /ForceUnsigned | Out-Null
        Write-Host "  - WinPE driver injection completed." -ForegroundColor Green
    }
}

try {
    reg load HKLM\zSYSTEM "$MountDir\Windows\System32\config\SYSTEM" | Out-Null
    if ($HardwareBypass -eq "Y") {
        Write-Host "  - Applying Hardware Bypass to WinPE..." -ForegroundColor DarkGray
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
        Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'
    }
} finally {
    reg unload HKLM\zSYSTEM 2>$null | Out-Null
}

# Phase 13: Saving boot.wim
Write-Host "`nSaving changes to boot.wim..." -ForegroundColor Yellow
dism.exe /Unmount-Image /MountDir:"$MountDir" /Commit

# Phase 14: Autounattend.xml
Write-Host "`n[14/15] Generating autounattend.xml..." -ForegroundColor Yellow
$XmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <ConfigureChatAutoInstall>false</ConfigureChatAutoInstall>
        </component>
    </settings>
    <settings pass="windowsPE">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DynamicUpdate>
                <WillShowUI>OnError</WillShowUI>
            </DynamicUpdate>
            <ImageInstall>
                <OSImage>
                    <WillShowUI>OnError</WillShowUI>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/INDEX</Key>
                            <Value>1</Value>
                        </MetaData>
                    </InstallFrom>
                </OSImage>
            </ImageInstall>
            <UserData>
                <ProductKey>
                    <Key/>
                </ProductKey>
            </UserData>
        </component>
    </settings>
</unattend>
"@
$XmlContent | Out-File -FilePath "$ExtractDir\autounattend.xml" -Encoding UTF8

# Phase 15: Creating ISO files
Write-Host "ISO Creation Process..." -ForegroundColor Yellow

$OscdimgPath = Get-OscdimgPath
$MicrosoftUrl = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"

if (-not $OscdimgPath) {
    $OscdimgPath = "$Workspace\oscdimg.exe"
    Write-Host "-> oscdimg not found locally, scanning runtime environment and preparing download..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MicrosoftUrl -OutFile $OscdimgPath -UseBasicParsing
        Write-Host "-> Download completed successfully." -ForegroundColor Green
    } catch {
        Write-Host "-> Error: Cannot download oscdimg.exe. Please install Windows ADK or check your internet connection." -ForegroundColor Red
        Exit
    }
} else {
    Write-Host "-> oscdimg found: $OscdimgPath" -ForegroundColor Green
}

if (Test-Path $OscdimgPath) {
    Write-Host "Building ISO... (Please wait)" -ForegroundColor Cyan
    $BuildArgs = "-m -o -u2 -udfver102 -bootdata:2#p0,e,b`"$ExtractDir\boot\etfsboot.com`"#pEF,e,b`"$ExtractDir\efi\microsoft\boot\efisys.bin`" `"$ExtractDir`" `"$FinalISO`""

    Start-Process -FilePath $OscdimgPath -ArgumentList $BuildArgs -Wait -NoNewWindow

    Write-Host "`nCompleted! Your ISO is ready at: $FinalISO" -ForegroundColor Green
    Write-Host "Cleaning up workspace..." -ForegroundColor DarkGray
    Remove-Item -Path $Workspace -Recurse -Force
} else {
    Write-Host "`n[!] Cannot compress into ISO, your Windows path is: $ExtractDir" -ForegroundColor Yellow
}

Write-Host "`nPress Enter to exit..."
Read-Host
