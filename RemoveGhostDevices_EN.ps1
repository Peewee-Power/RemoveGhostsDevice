# Check for admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting with administrator privileges..."
    $argList = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    foreach ($a in $args) { $argList += " `"$a`"" }
    Start-Process -FilePath "powershell" -ArgumentList $argList -Verb RunAs
    exit
}

# --- Define functions ---

# Function to check for admin rights (already present, but initial check is better)
function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Function to filter a single device
function Filter-Device {
    param(
        [Parameter(Mandatory=$true)]
        $Dev,
        [string[]]$FilterByClass,
        [string[]]$NarrowByClass,
        [string[]]$FilterByFriendlyName,
        [string[]]$NarrowByFriendlyName
    )
    $Class = $Dev.Class
    $FriendlyName = $Dev.FriendlyName
    $matchFilter = $false

    if (($matchFilter -eq $false) -and ($FilterByClass)) {
        foreach ($ClassFilter in $FilterByClass) {
            if ($ClassFilter -eq $Class) {
                Write-Verbose "Class filter match $ClassFilter, skipping"
                $matchFilter = $true
                break
            }
        }
    }
    if (($matchFilter -eq $false) -and ($NarrowByClass)) {
        $shouldInclude = $false
        foreach ($ClassFilter in $NarrowByClass) {
            if ($ClassFilter -eq $Class) {
                $shouldInclude = $true
                break
            }
        }
        $matchFilter = !$shouldInclude
    }
    if (($matchFilter -eq $false) -and ($FilterByFriendlyName)) {
        foreach ($FriendlyNameFilter in $FilterByFriendlyName) {
            if ($FriendlyName -like '*'+$FriendlyNameFilter+'*') {
                Write-Verbose "FriendlyName filter match $FriendlyName, skipping"
                $matchFilter = true
                break
            }
        }
    }
    if (($matchFilter -eq $false) -and ($NarrowByFriendlyName)) {
        $shouldInclude = false
        foreach ($FriendlyNameFilter in $NarrowByFriendlyName) {
            if ($FriendlyName -like '*'+$FriendlyNameFilter+'*') {
                $shouldInclude = $true
                break
            }
        }
        $matchFilter = !$shouldInclude
    }
    return $matchFilter
}

# Function to retrieve ghost devices
function Get-Ghost-Devices {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Devices
    )
    return ($Devices | where {$_.InstallState -eq $false} | sort -Property FriendlyName)
}

# C# code for SetupApi (remains unchanged)
$setupapi = @"
using System;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
namespace Win32
{
    public static class SetupApi
    {
           // 1st form using a ClassGUID only, with Enumerator = IntPtr.Zero
         [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
         public static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            IntPtr Enumerator,
            IntPtr hwndParent,
            int Flags
         );
        
         // 2nd form uses an Enumerator only, with ClassGUID = IntPtr.Zero
         [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
         public static extern IntPtr SetupDiGetClassDevs(
            IntPtr ClassGuid,
            string Enumerator,
            IntPtr hwndParent,
            int Flags
         );
         
         [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
         public static extern bool SetupDiEnumDeviceInfo(
             IntPtr DeviceInfoSet,
             uint MemberIndex,
             ref SP_DEVINFO_DATA DeviceInfoData
         );
        
         [DllImport("setupapi.dll", SetLastError = true)]
         public static extern bool SetupDiDestroyDeviceInfoList(
             IntPtr DeviceInfoSet
         );
         [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
         public static extern bool SetupDiGetDeviceRegistryProperty(
             IntPtr deviceInfoSet,
             ref SP_DEVINFO_DATA deviceInfoData,
             uint property,
             out UInt32 propertyRegDataType,
             byte[] propertyBuffer,
             uint propertyBufferSize,
             out UInt32 requiredSize
         );
         [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
         public static extern bool SetupDiGetDeviceInstanceId(
             IntPtr DeviceInfoSet,
             ref SP_DEVINFO_DATA DeviceInfoData,
             StringBuilder DeviceInstanceId,
             int DeviceInstanceIdSize,
             out int RequiredSize
         );

        
         [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
         public static extern bool SetupDiRemoveDevice(IntPtr DeviceInfoSet,ref SP_DEVINFO_DATA DeviceInfoData);
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
       public uint cbSize;
       public Guid classGuid;
       public uint devInst;
       public IntPtr reserved;
    }
    [Flags]
    public enum DiGetClassFlags : uint
    {
        DIGCF_DEFAULT       = 0x00000001,  // only valid with DIGCF_DEVICEINTERFACE
        DIGCF_PRESENT       = 0x00000002,
        DIGCF_ALLCLASSES    = 0x00000004,
        DIGCF_PROFILE       = 0x00000008,
        DIGCF_DEVICEINTERFACE   = 0x00000010,
    }
    public enum SetupDiGetDeviceRegistryPropertyEnum : uint
    {
          SPDRP_DEVICEDESC          = 0x00000000, // DeviceDesc (R/W)
          SPDRP_HARDWAREID          = 0x00000001, // HardwareID (R/W)
          SPDRP_COMPATIBLEIDS         = 0x00000002, // CompatibleIDs (R/W)
          SPDRP_UNUSED0               = 0x00000003, // unused
          SPDRP_SERVICE               = 0x00000004, // Service (R/W)
          SPDRP_UNUSED1               = 0x00000005, // unused
          SPDRP_UNUSED2               = 0x00000006, // unused
          SPDRP_CLASS                 = 0x00000007, // Class (R--tied to ClassGUID)
          SPDRP_CLASSGUID             = 0x00000008, // ClassGUID (R/W)
          SPDRP_DRIVER                = 0x00000009, // Driver (R/W)
          SPDRP_CONFIGFLAGS           = 0x0000000A, // ConfigFlags (R/W)
          SPDRP_MFG                   = 0x0000000B, // Mfg (R/W)
          SPDRP_FRIENDLYNAME          = 0x0000000C, // FriendlyName (R/W)
          SPDRP_LOCATION_INFORMATION  = 0x0000000D, // LocationInformation (R/W)
          SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E, // PhysicalDeviceObjectName (R)
          SPDRP_CAPABILITIES          = 0x0000000F, // Capabilities (R)
          SPDRP_UI_NUMBER             = 0x00000010, // UiNumber (R)
          SPDRP_UPPERFILTERS          = 0x00000011, // UpperFilters (R/W)
          SPDRP_LOWERFILTERS          = 0x00000012, // LowerFilters (R/W)
          SPDRP_BUSTYPEGUID           = 0x00000013, // BusTypeGUID (R)
          SPDRP_LEGACYBUSTYPE         = 0x00000014, // LegacyBusType (R)
          SPDRP_BUSNUMBER             = 0x00000015, // BusNumber (R)
          SPDRP_ENUMERATOR_NAME       = 0x00000016, // Enumerator Name (R)
          SPDRP_SECURITY              = 0x00000017, // Security (R/W, binary form)
          SPDRP_SECURITY_SDS          = 0x00000018, // Security (W, SDS form)
          SPDRP_DEVTYPE               = 0x00000019, // Device Type (R/W)
          SPDRP_EXCLUSIVE             = 0x0000001A, // Device is exclusive-access (R/W)
          SPDRP_CHARACTERISTICS       = 0x0000001B, // Device Characteristics (R/W)
          SPDRP_ADDRESS               = 0x0000001C, // Device Address (R)
          SPDRP_UI_NUMBER_DESC_FORMAT = 0X0000001D, // UiNumberDescFormat (R/W)
          SPDRP_DEVICE_POWER_DATA     = 0x0000001E, // Device Power Data (R)
          SPDRP_REMOVAL_POLICY        = 0x0000001F, // Removal Policy (R)
          SPDRP_REMOVAL_POLICY_HW_DEFAULT   = 0x00000020, // Hardware Removal Policy (R)
          SPDRP_REMOVAL_POLICY_OVERRIDE     = 0x00000021, // Removal Policy Override (RW)
          SPDRP_INSTALL_STATE         = 0x00000022, // Device Install State (R)
          SPDRP_LOCATION_PATHS        = 0x00000023, // Device Location Paths (R)
          SPDRP_BASE_CONTAINERID      = 0x00000024  // Base ContainerID (R)
    }
}
"@
Add-Type -TypeDefinition $setupapi

# --- Main part of the script ---

# Array for all detected devices
$allDevices = @()
# Array for all removed devices (report)
$removeArray = @()

# Initialize parameters for filtering
$FilterByClass = @()
$NarrowByClass = @()
$FilterByFriendlyName = @()
$NarrowByFriendlyName = @()
$Force = $false
$regardlessOfInstallState = $false

# Manual argument processing for the script
for ($i = 0; $i -lt $args.Length; $i++) {
    switch ($args[$i].ToLower()) {
        "-filterbyclass"            { $i++; $FilterByClass += $args[$i] }
        "-narrowbyclass"            { $i++; $NarrowByClass += $args[$i] }
        "-filterbyfriendlyname"     { $i++; $FilterByFriendlyName += $args[$i] }
        "-narrowbyfriendlyname"     { $i++; $NarrowByFriendlyName += $args[$i] }
        "-force"                    { $Force = $true }
        "-regardlessofinstallstate" { $regardlessOfInstallState = $true }
    }
}

# Initialization for SetupApi to collect all devices
$setupClass = [Guid]::Empty
$devs = [Win32.SetupApi]::SetupDiGetClassDevs([ref]$setupClass, [IntPtr]::Zero, [IntPtr]::Zero, [Win32.DiGetClassFlags]::DIGCF_ALLCLASSES)

# Initialize structure for device info data
$devInfo = new-object Win32.SP_DEVINFO_DATA
$devInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($devInfo)

# Device counter
$devCount = 0

Write-Host "Collecting all device information..." -ForegroundColor DarkYellow

# Enumerate and collect devices
while([Win32.SetupApi]::SetupDiEnumDeviceInfo($devs, $devCount, [ref]$devInfo)) {
    # Get FriendlyName
    $propType = 0
    [byte[]]$propBuffer = $null
    $propBufferSize = 0
    [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, 0, [ref]$propBufferSize) | Out-null
    [byte[]]$propBuffer = New-Object byte[] $propBufferSize
    if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, $propBufferSize, [ref]$propBufferSize)){
        # If no FriendlyName, try DeviceDesc
        $propTypeDD = 0
        [byte[]]$propBufferDD = $null
        $propBufferSizeDD = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, 0, [ref]$propBufferSizeDD) | Out-null
        [byte[]]$propBufferDD = New-Object byte[] $propBufferSizeDD
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, $propBufferSizeDD, [ref]$propBufferSizeDD)  | out-null
        $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBufferDD)
        if ($FriendlyName.Length -ge 1) {
            $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
        }
    } else {
        $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBuffer)
        if ($FriendlyName.Length -ge 1) {
            $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
        }
    }

    # Get HardwareID
    $propTypeHWID = 0
    [byte[]]$propBufferHWID = $null
    $propBufferSizeHWID = 0
    [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, 0, [ref]$propBufferSizeHWID) | Out-null
    [byte[]]$propBufferHWID = New-Object byte[] $propBufferSizeHWID
    if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, $propBufferSizeHWID, [ref]$propBufferSizeHWID)){
        $HWID = ""
    } else {
        $HWID = [System.Text.Encoding]::Unicode.GetString($propBufferHWID)
        $HWID = $HWID.split([char]0x0000)[0].ToUpper()
    }

    # Get Install State
    $propTypeIS = 0
    [byte[]]$propBufferIS = $null
    $propBufferSizeIS = 0
    [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, 0, [ref]$propBufferSizeIS) | Out-null
    [byte[]]$propBufferIS = New-Object byte[] $propBufferSizeIS
    $InstallState = [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, $propBufferSizeIS, [ref]$propBufferSizeIS)

    # Hole Class
    $propTypeCLSS = 0
    [byte[]]$propBufferCLSS = $null
    $propBufferSizeCLSS = 0
    [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, 0, [ref]$propBufferSizeCLSS) | Out-null
    [byte[]]$propBufferCLSS = New-Object byte[] $propBufferSizeCLSS
    [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, $propBufferSizeCLSS, [ref]$propBufferSizeCLSS) | out-null
    $Class = [System.Text.Encoding]::Unicode.GetString($propBufferCLSS)

    # Hole Device Instance ID
    $deviceInstanceIdBuilder = New-Object System.Text.StringBuilder(256) # Max path length for device instance ID
    $requiredSize = 0
    [Win32.SetupApi]::SetupDiGetDeviceInstanceId($devs, [ref]$devInfo, $deviceInstanceIdBuilder, $deviceInstanceIdBuilder.Capacity, [ref]$requiredSize) | Out-Null
    $DeviceInstanceId = $deviceInstanceIdBuilder.ToString()

    # Create device object and add it to the array
    $device = New-Object System.Object
    $device | Add-Member -type NoteProperty -name FriendlyName -value $FriendlyName
    $device | Add-Member -type NoteProperty -name HWID -value $HWID
    $device | Add-Member -type NoteProperty -name InstallState -value $InstallState
    $device | Add-Member -type NoteProperty -name Class -value $Class
    $device | Add-Member -type NoteProperty -name DeviceInstanceId -value $DeviceInstanceId
    $allDevices += $device

    $devCount++
}
Write-Host "Device collection completed. Total number of devices: $($allDevices.Count)" -ForegroundColor Green

# Destroy the DeviceInfoSet since we have collected all info
[Win32.SetupApi]::SetupDiDestroyDeviceInfoList($devs) | Out-Null


# --- Logic to display and remove devices ---

# Identify and filter ghost devices
$ghostDevices = Get-Ghost-Devices -Devices $allDevices
$filteredGhostDevices = @()

foreach ($dev in $ghostDevices) {
    $matchFilter = Filter-Device -Dev $dev `
        -FilterByClass $FilterByClass `
        -NarrowByClass $NarrowByClass `
        -FilterByFriendlyName $FilterByFriendlyName `
        -NarrowByFriendlyName $NarrowByFriendlyName
    if ($matchFilter -eq $false) {
        $filteredGhostDevices += $dev
    }
}

# Zeige die Overview of found inactive (ghost) devices an
Write-Host "`n---------------------------------------------"
Write-Host "Overview of found inactive (ghost) devices:" -ForegroundColor Cyan
if ($filteredGhostDevices.Count -eq 0) {
    Write-Host "No inactive (ghost) devices found matching the filters." -ForegroundColor Green
} else {
    $filteredGhostDevices | Format-Table -AutoSize
    Write-Host "Number of filtered inactive (ghost) devices: $($filteredGhostDevices.Count)"
}
Write-Host "---------------------------------------------`n"

# Frage nach Bestätigung für die Entfernung und führe sie durch
if ($filteredGhostDevices.Count -gt 0) {
    $proceedWithRemoval = $false
    $confirmEach = $false

    if (-not $Force) {
        $message = "Möchten Sie mit dem Entfernen der oben gelisteten inaktiven (Ghost-)Geräte fortfahren?"
        $question = "Wählen Sie eine Option:"
        $choices = '&Alle entfernen (nach Liste)', '&Einzeln bestätigen', '&Abbrechen'
        $decision = $Host.UI.PromptForChoice($message, $question, $choices, 2) # Standard ist Abbrechen

        switch ($decision) {
            0 { $proceedWithRemoval = $true; $confirmEach = $false } # Alle entfernen
            1 { $proceedWithRemoval = $true; $confirmEach = $true }  # Einzeln bestätigen
            2 { Write-Host "Entfernung abgebrochen." -ForegroundColor Yellow; exit } # Abbrechen
        }
    } else {
        $proceedWithRemoval = $true # Wenn -Force verwendet wird, automatisch fortfahren
    }

    if ($proceedWithRemoval) {
        Write-Host "`nBeginne mit dem Entfernen von inaktiven (Ghost-)Geräten..." -ForegroundColor Yellow
        foreach ($deviceToRemove in $filteredGhostDevices) {
            $name = if ($deviceToRemove.FriendlyName) { $deviceToRemove.FriendlyName } else { $deviceToRemove.HWID }
            
            $confirmIndividualRemoval = $false
            if ($confirmEach) { # Nur fragen, wenn "Einzeln bestätigen" gewählt wurde
                $question = "Möchten Sie das Gerät '$name' wirklich entfernen? (J/N)"
                $choices = '&Ja', '&Nein'
                $decision = $Host.UI.PromptForChoice("Gerät entfernen?", $question, $choices, 1) # Standard ist Nein
                if ($decision -eq 0) {
                    $confirmIndividualRemoval = $true
                }
            } else { # Wenn "Alle entfernen" oder -Force, dann direkt bestätigen
                $confirmIndividualRemoval = $true
            }

            if ($confirmIndividualRemoval) {
                # NEUER ANSATZ FÜR DIE ENTFERNUNG:
                # Erstelle ein neues DeviceInfoSet für alle Klassen, um das spezifische Gerät zu finden
                $devsForRemoval = [Win32.SetupApi]::SetupDiGetClassDevs([ref][Guid]::Empty, [IntPtr]::Zero, [IntPtr]::Zero, [Win32.DiGetClassFlags]::DIGCF_ALLCLASSES)
                
                $devInfoForRemoval = new-object Win32.SP_DEVINFO_DATA
                $devInfoForRemoval.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($devInfoForRemoval)

                $foundForRemoval = $false
                $removalIndex = 0
                while ([Win32.SetupApi]::SetupDiEnumDeviceInfo($devsForRemoval, $removalIndex, [ref]$devInfoForRemoval)) {
                    $tempDeviceInstanceIdBuilder = New-Object System.Text.StringBuilder(256)
                    $tempRequiredSize = 0
                    [Win32.SetupApi]::SetupDiGetDeviceInstanceId($devsForRemoval, [ref]$devInfoForRemoval, $tempDeviceInstanceIdBuilder, $tempDeviceInstanceIdBuilder.Capacity, [ref]$tempRequiredSize) | Out-Null
                    $tempDeviceInstanceId = $tempDeviceInstanceIdBuilder.ToString()

                    if ($tempDeviceInstanceId -eq $deviceToRemove.DeviceInstanceId) {
                        $foundForRemoval = $true
                        break # Gerät gefunden
                    }
                    $removalIndex++
                }

                if ($foundForRemoval) {
                    Write-Host "Versuche Gerät '$name' (Instance ID: $($deviceToRemove.DeviceInstanceId)) zu entfernen..." -ForegroundColor Yellow
                    if([Win32.SetupApi]::SetupDiRemoveDevice($devsForRemoval, [ref]$devInfoForRemoval)){
                        Write-Host "Gerät '$name' erfolgreich entfernt." -ForegroundColor Green
                        $removeArray += $deviceToRemove # Füge es zum Bericht der entfernten Geräte hinzu
                    } else {
                        Write-Host "Fehler beim Entfernen von Gerät '$name'. Fehlercode: $LASTERROR" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Gerät '$name' (Instance ID: $($deviceToRemove.DeviceInstanceId)) konnte für die Entfernung nicht erneut gefunden werden. Möglicherweise bereits entfernt oder nicht mehr verfügbar." -ForegroundColor Red
                }
                [Win32.SetupApi]::SetupDiDestroyDeviceInfoList($devsForRemoval) | Out-Null # Handles freigeben
            } else {
                Write-Host "Gerät '$name' übersprungen (manuell bestätigt)." -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "No devices available for removal." -ForegroundColor Yellow
}

# Abschlussbericht
Write-Host "`n---------------------------------------------"
write-host "Report of removed inactive (ghost) devices:" -ForegroundColor Green
if ($removeArray.Count -eq 0) {
    Write-Host "No inactive (ghost) devices removed." -ForegroundColor Yellow
} else {
    $removeArray | sort -Property FriendlyName | Format-Table -AutoSize
    write-host "Gesamtzahl der entfernten inaktiven (Ghost-)Geräte: $($removeArray.count)"
}
Write-Host "---------------------------------------------`n"

Write-Host "`nPress any key to continue... . . ."
[void][System.Console]::ReadKey($true)
