<#
.DESCRIPTION
    Script to replace MDT Gather in MECM Task Sequences
.EXAMPLE
    PowerShell.exe -ExecutionPolicy ByPass -File <ScriptName>.ps1 [-Debug]
.NOTES
    Author(s):  Jonathan Conway
    Modified:   09/06/2021
    Version:    1.7
#>

Param (
    [Switch]$Debug
)

$TSvars = @{ }

function Get-BatteryInfo {

    # Is a battery present?
    if ($null -ne (Get-CimInstance -ClassName 'Win32_Battery')) {

        # Check if AC Power is connected - if it is connected then return '$IsOnBattery' = '$false'
        if ((Get-CimInstance -Namespace 'root\WMI' -Query 'SELECT * FROM BatteryStatus Where Voltage > 0' -ErrorAction 'SilentlyContinue').PowerOnline) {
            $IsOnBattery = $false
        }
        else {
            $IsOnBattery = $true
        }
    }
    else {
        # Otherwise return 'AcConnected' = 'false'
        $IsOnBattery = $false
    }

    $TSvars.Add('IsOnBattery', $IsOnBattery)

}

function Get-BaseBoardInfo {

    $BaseBoard = Get-CimInstance -ClassName 'Win32_BaseBoard'

    $TSvars.Add('Product', $BaseBoard.Product)

}

function Get-BiosInfo {

    $Bios = Get-CimInstance -ClassName 'Win32_BIOS'

    $TSvars.Add('BIOSReleaseDate', $Bios.ReleaseDate)
    $TSvars.Add('BIOSVersion', $Bios.SMBIOSBIOSVersion)
    $TSvars.Add('SerialNumber', $Bios.SerialNumber)

}

function Get-BitLockerInfo {

    $EncryptionMethods = @{
        '0' = 'NO_ENCRYPTION';
        '1' = 'AES_128_WITH_DIFFUSER';
        '2' = 'AES_256_WITH_DIFFUSER';
        '3' = 'AES_128';
        '4' = 'AES_256';
        '5' = 'HARDWARE_ENCRYPTION';
        '6' = 'AES_256';
        '7' = 'XTS_AES_256'
    }

    $IsBDE = $false
    $BitlockerEncryptionMethod = "N/A"
    $EncryptedVolumes = Get-CimInstance -Namespace 'ROOT\cimv2\Security\MicrosoftVolumeEncryption' -Query 'SELECT * FROM Win32_EncryptableVolume'

    if ($EncryptedVolumes) {

        foreach ($EncryptedVolume in $EncryptedVolumes) {

            if ($EncryptedVolume.ProtectionStatus -ne '0') {

                $EncryptionMethod = [int]$EncryptedVolume.EncryptionMethod

                if ($EncryptionMethods.ContainsKey("$EncryptionMethod")) {
                    $BitlockerEncryptionMethod = $EncryptionMethods["$EncryptionMethod"]
                }

                $IsBDE = $true

            }
        }
    }

    $TSvars.Add('IsBDE', $IsBDE.ToString())
    $TSvars.Add('BitlockerEncryptionMethod', $BitlockerEncryptionMethod)

}

function Get-ChassisInfo {

    $VirtualHosts = @{
        'Virtual Machine'         = 'Hyper-V'
        'VMware Virtual Platform' = 'VMware'
        'VMware7,1'               = 'VMware'
        'VirtualBox'              = 'VirtualBox'
        'Xen'                     = 'Xen'
        'AHV'                     = 'Nutanix'
    }

    $ComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem'

    $TSvars.Add('Memory', ($ComputerSystem.TotalPhysicalMemory / 1024 / 1024).ToString())
    $TSvars.Add('Make', $ComputerSystem.Manufacturer)
    $TSvars.Add('Model', $ComputerSystem.Model)
    $TSvars.Add('SystemSKU', $ComputerSystem.SystemSKUNumber)

    if ($VirtualHosts.ContainsKey($ComputerSystem.Model)) {
        $IsVM = $true
        $TSvars.Add('IsVM', "$IsVM")
        $TSvars.Add('VMPlatform', $VirtualHosts[$ComputerSystem.Model])
    }
    else {
        $IsVM = $false
        $TSvars.Add('IsVM', "$IsVM")
        $TSvars.Add('VMPlatform', 'N/A')
    }

    $DesktopChassisTypes = @('3', '4', '5', '6', '7', '13', '15', '16', '35', '36')
    $LaptopChassisTypes = @('8', '9', '10', '11', '12', '14', '18', '21')
    $ServerChassisTypes = @('23', '28')
    $TabletChassisTypes = @('30', '31', '32')

    $ChassisInfo = Get-CimInstance -ClassName 'Win32_SystemEnclosure'

    $TSvars.Add('AssetTag', $ChassisInfo.SMBIOSAssetTag)

    if ($IsVM -eq $false) {

        $ChassisInfo.ChassisTypes | ForEach-Object {

            if ($TSvars.ContainsKey('IsDesktop')) {
                $TSvars['IsDesktop'] = [string]$DesktopChassisTypes.Contains($_.ToString())
            }
            else {
                $TSvars.Add('IsDesktop', [string]$DesktopChassisTypes.Contains($_.ToString()))
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsServer', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsLaptop')) {
                $TSvars['IsLaptop'] = [string]$LaptopChassisTypes.Contains($_.ToString())
            }
            else {
                $TSvars.Add('IsLaptop', [string]$LaptopChassisTypes.Contains($_.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsServer', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsServer')) {
                $TSvars['IsServer'] = [string]$ServerChassisTypes.Contains($_.ToString())
            }
            else {
                $TSvars.Add('IsServer', [string]$ServerChassisTypes.Contains($_.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsTablet')) {
                $TSvars['IsTablet'] = [string]$TabletChassisTypes.Contains($_.ToString())
            }
            else {
                $TSvars.Add('IsTablet', [string]$TabletChassisTypes.Contains($_.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsServer', "$false")
            }
        }
    }

}

function Get-ComputerSystemProductInfo {

    $ComputerSystemProduct = Get-CimInstance -ClassName 'Win32_ComputerSystemProduct'

    $TSvars.Add('UUID', $ComputerSystemProduct.UUID)
    $TSvars.Add('Vendor', $ComputerSystemProduct.Vendor)

}

function Get-HardwareInfo {

    $Processor = Get-CimInstance -ClassName 'Win32_Processor'

    if ($Processor.Manufacturer -eq 'GenuineIntel') {

        $ProcessorName = $Processor.Name
        [int]$ProcessorFamily = $ProcessorName.Substring($ProcessorName.LastIndexOf('-') + 1, 5)

        if ($ProcessorFamily -ge '8000') {
            $IsCoffeeLakeOrLater = $true
        }
        else {
            $IsCoffeeLakeOrLater = $false
        }

        $TSvars.Add('IsCoffeeLakeOrLater', "$IsCoffeeLakeOrLater")
        $TSvars.Add('ProcessorFamily', $ProcessorFamily)
        $TSvars.Add('ProcessorName', $ProcessorName)

    }

    $TSvars.Add('ProcessorManufacturer', $Processor.Manufacturer)
    $TSvars.Add('ProcessorSpeed', $Processor.MaxClockSpeed.ToString())

}

function Get-NetworkInfo {

    (Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = 1') | ForEach-Object {

        # Get IP address information
        $_.IPAddress | ForEach-Object {
            if ($_ -ne $null) {
                if ($_.IndexOf('.') -gt 0 -and !$_.StartsWith('169.254') -and $_ -ne '0.0.0.0') {

                    if ($TSvars.ContainsKey('IPAddress')) {
                        $TSvars['IPAddress'] = $TSvars['IPAddress'] + ',' + $_
                    }
                    else {
                        $TSvars.Add('IPAddress', $_)
                    }
                }
            }
        }

        # Get Default Gateway information
        $_.DefaultIPGateway -split ',' | Select-Object -First '1' | ForEach-Object {
            if ($_ -ne $null -and $_.IndexOf('.') -gt 0) {

                if ($TSvars.ContainsKey('DefaultGateway')) {
                    $TSvars['DefaultGateway'] = $TSvars['DefaultGateway'] + ',' + $_
                }
                else {
                    $TSvars.Add("DefaultGateway", $_)
                }
            }
        }

    }

    # Check to see if the device is connected via Ethernet and return $true if it is
    $EthernetConnection = Get-CimInstance -ClassName 'Win32_NetworkAdapter' | Where-Object { $_.Name -like "*Ethernet Connection*" -or $_.Name -like "*Realtek PCIe*" -and $_.NetConnectionStatus -eq '2' }

    if ($null -eq $EthernetConnection) {
        $IsOnEthernet = $false
    }
    else {
        $IsOnEthernet = $true
    }

    $TSvars.Add('IsOnEthernet', "$IsOnEthernet")

    # Get device MAC addresses for connected NICs
    $Nic = (Get-CimInstance -ClassName 'Win32_NetworkAdapter' -Filter 'NetConnectionStatus = 2')

    $TSvars.Add('MacAddress', $Nic.MACAddress -join ',')

}

function Get-OsInfo {

    $Os = Get-CimInstance -ClassName 'Win32_OperatingSystem'
    $OsBuildNumber = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild').CurrentBuild + '.' + (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR').UBR
    $ComputerInfo = Get-ComputerInfo

    if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        $Architecture = 'X64'
    }
    else {
        $Architecture = 'X86'
    }

    $TSvars.Add('Architecture', $Architecture)
    $TSvars.Add('OSCurrentVersion', $Os.Version)
    $TSvars.Add('OSCurrentBuild', $Os.BuildNumber)
    $TSvars.Add('OSBuildNumber', $OsBuildNumber)
    $TSvars.Add('OsLocale', $ComputerInfo.OsLocale)
    $TSvars.Add('OsWindowsInstallationType', $ComputerInfo.WindowsInstallationType)
    $TSvars.Add('OsWindowsProductName', $ComputerInfo.WindowsProductName)

    if ($ComputerInfo.WindowsInstallationType -eq 'WindowsPE') {
        $TSvars.Add('OsTimeZone', 'N/A')
    }
    else {
        $TSvars.Add('OsTimeZone', $ComputerInfo.TimeZone)
    }

}

# Run all functions
Get-BatteryInfo
Get-BaseBoardInfo
Get-BiosInfo
Get-BitLockerInfo
Get-ChassisInfo
Get-ComputerSystemProductInfo
Get-HardwareInfo
Get-NetworkInfo
Get-OsInfo

# If Debug is true then print all variables to the console
if ($Debug) {

    Start-Transcript -Path "$env:windir\Temp\Pwsh-Gather.log" -Append -NoClobber

    $TSvars.Keys | Sort-Object | ForEach-Object {
        Write-Host "$($_) = $($TSvars[$_])"
    }

    Stop-Transcript

}

# If Debug is false then add variables to the Task Sequence environment
else {

    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $temp = $tsenv.Value("OSDComputerName")
    $LogPath = $tsenv.Value("_SMSTSLogPath")

    Start-Transcript -Path $LogPath\Pwsh-Gather.log -Append -NoClobber

    if (-not $temp) {
        $TSvars.Add("OSDComputerName", $tsenv.Value("_SMSTSMachineName"))
    }

    $TSvars.Keys | Sort-Object | ForEach-Object {
        $tsenv.Value($_) = $TSvars[$_]
        Write-Output "$($_) = $($TSvars[$_])"
    }

    Stop-Transcript

}