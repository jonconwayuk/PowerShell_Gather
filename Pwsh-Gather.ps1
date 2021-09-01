<#
.DESCRIPTION
    Script to replace MDT Gather in MECM Task Sequences
.EXAMPLE
    PowerShell.exe -ExecutionPolicy ByPass -File <ScriptName>.ps1 [-Debug]
.NOTES
    Author(s):  Jonathan Conway
    Modified:   01/09/2021
    Version:    1.10
#>

Param (
    [Switch]$Debug
)

$TSvars = @{ }

Function Get-BatteryInfo {

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

Function Get-BaseBoardInfo {

    $BaseBoard = Get-CimInstance -ClassName 'Win32_BaseBoard'

    $TSvars.Add('Product', $BaseBoard.Product)

}

Function Get-BiosInfo {

    $Bios = Get-CimInstance -ClassName 'Win32_BIOS'

    $TSvars.Add('BIOSReleaseDate', $Bios.ReleaseDate)
    $TSvars.Add('BIOSVersion', $Bios.SMBIOSBIOSVersion)
    $TSvars.Add('SerialNumber', $Bios.SerialNumber)

}

Function Get-BitLockerInfo {

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

Function Get-ChassisInfo {

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
    if ($ComputerSystem.Manufacturer -eq 'LENOVO') {
        $LenovoModel = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).Version
        $TSvars.Add('Model', $LenovoModel)
    }
    else {
        $TSvars.Add('Model', $ComputerSystem.Model)
    }
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

    if ($null -or "" -or " " -eq $ChassisInfo.SMBIOSAssetTag) {
        $TSvars.Add('AssetTag', 'N/A')
    }
    else {
        $TSvars.Add('AssetTag', $ChassisInfo.SMBIOSAssetTag)
    }

    if ($IsVM -eq $false) {

        $ChassisInfo.ChassisTypes | ForEach-Object {

            if ($TSvars.ContainsKey('IsDesktop')) {
                $TSvars['IsDesktop'] = [string]$DesktopChassisTypes.Contains($PSItem.ToString())
            }
            else {
                $TSvars.Add('IsDesktop', [string]$DesktopChassisTypes.Contains($PSItem.ToString()))
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsServer', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsLaptop')) {
                $TSvars['IsLaptop'] = [string]$LaptopChassisTypes.Contains($PSItem.ToString())
            }
            else {
                $TSvars.Add('IsLaptop', [string]$LaptopChassisTypes.Contains($PSItem.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsServer', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsServer')) {
                $TSvars['IsServer'] = [string]$ServerChassisTypes.Contains($PSItem.ToString())
            }
            else {
                $TSvars.Add('IsServer', [string]$ServerChassisTypes.Contains($PSItem.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsTablet', "$false")
            }

            if ($TSvars.ContainsKey('IsTablet')) {
                $TSvars['IsTablet'] = [string]$TabletChassisTypes.Contains($PSItem.ToString())
            }
            else {
                $TSvars.Add('IsTablet', [string]$TabletChassisTypes.Contains($PSItem.ToString()))
                $TSvars.Add('IsDesktop', "$false")
                $TSvars.Add('IsLaptop', "$false")
                $TSvars.Add('IsServer', "$false")
            }
        }
    }

}

Function Get-ComputerSystemProductInfo {

    $ComputerSystemProduct = Get-CimInstance -ClassName 'Win32_ComputerSystemProduct'

    $TSvars.Add('UUID', $ComputerSystemProduct.UUID)
    $TSvars.Add('Vendor', $ComputerSystemProduct.Vendor)

}

Function Get-HardwareInfo {

    $Processor = Get-CimInstance -ClassName 'Win32_Processor' | Select-Object -First '1'

    if ($Processor.Manufacturer -eq 'GenuineIntel') {

        $ProcessorName = $Processor.Name
        [String]$RegExPattern = '([^-][0-9]{3,})'
        [int]$ProcessorFamily = ($ProcessorName | Select-String -Pattern $RegExPattern | Select-Object -ExpandProperty 'Matches').Value

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

Function Get-NetworkInfo {

    (Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = 1') | ForEach-Object {

        # Get IP address information
        $PSItem.IPAddress | ForEach-Object {
            if ($PSItem -ne $null) {
                if ($PSItem.IndexOf('.') -gt 0 -and -not $PSItem.StartsWith('169.254') -and $PSItem -ne '0.0.0.0') {

                    if ($TSvars.ContainsKey('IPAddress')) {
                        $TSvars['IPAddress'] = $TSvars['IPAddress'] + ',' + $PSItem
                    }
                    else {
                        $TSvars.Add('IPAddress', $PSItem)
                    }
                }
            }
        }

        # Get Default Gateway information
        $PSItem.DefaultIPGateway -split ',' | Select-Object -First '1' | ForEach-Object {
            if ($PSItem -ne $null -and $PSItem.IndexOf('.') -gt 0) {

                if ($TSvars.ContainsKey('DefaultGateway')) {
                    $TSvars['DefaultGateway'] = $TSvars['DefaultGateway'] + ',' + $PSItem
                }
                else {
                    $TSvars.Add("DefaultGateway", $PSItem)
                }
            }
        }

    }

    # Check to see if the device is connected via Ethernet and return $true if it is
    $EthernetConnection = Get-CimInstance -ClassName 'Win32_NetworkAdapter' | Where-Object { $PSItem.Name -like "*Ethernet Connection*" -or $PSItem.Name -like "*Realtek PCIe*" -and $PSItem.NetConnectionStatus -eq '2' }

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

Function Get-OsInfo {

    $Os = Get-CimInstance -ClassName 'Win32_OperatingSystem'
    $OsBuildRegistryInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [string]$OsBuildNumber = ($OsBuildRegistryInfo.CurrentBuild) + '.' + ($OsBuildRegistryInfo.UBR)
    $OsInWinPE = Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
    [string]$OsWindowsInstallationType = $OsBuildRegistryInfo.InstallationType
    [string]$OsProductName = $OsBuildRegistryInfo.ProductName

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
    $TSvars.Add('OsInWinPE', $OsInWinPE)

    if ($OsInWinPE -eq $true) {
        $TSvars.Add('OsLocale', 'N/A')
    }
    else {
        $TSvars.Add('OsLocale', (Get-WinSystemLocale).Name)
    }

    if ($ComputerInfo.WindowsInstallationType -eq 'WindowsPE' -or $OsInWinPE -eq $true) {
        $TSvars.Add('OsTimeZone', 'N/A')
    }
    else {
        $TSvars.Add('OsTimeZone', (Get-TimeZone).DisplayName)
    }

    $TSvars.Add('OsWindowsInstallationType', $OsWindowsInstallationType)
    $TSvars.Add('OsWindowsProductName', $OsProductName)

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
        Write-Host "$($PSItem) = $($TSvars[$PSItem])" -BackgroundColor 'Blue' -ForegroundColor 'Black'
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
        $tsenv.Value($PSItem) = $TSvars[$PSItem]
        Write-Output "$($PSItem) = $($TSvars[$PSItem])"
    }

    Stop-Transcript

}