[![Latest Release](https://img.shields.io/github/v/release/jonconwayuk/PowerShell_Gather)](https://github.com/jonconwayuk/PowerShell_Gather/releases/latest)

# PowerShell_Gather

## Description

PowerShell script designed to replace MDT Gather functionality when deploying a Windows OS using Microsoft Configuration Manager.

It collects information from a device and stores these as variables which can then be utilised as MCM Task Sequence variables to set logic for various actions.

The advantage of this is that in the majority of scenarios, you not longer need to use MDT-integrated Task Sequences and can therefore avoid using and maintaining the various MDT components required otherwise.

> [!Caution]
> MDT has now been retired by Microsoft and is **_no longer supported_**.
>
> [Microsoft Deployment Toolkit (MDT) - immediate retirement notice](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/mdt/mdt-retirement)

## Instructions

Script can be run in a Task in an MCM Task Sequence - easiest way is to add the script content as a "Run PowerShell Script' step with the Execution Policy set to 'Bypass'.

The vast majority of the groundwork for this script was done by Johan Schrewelius ([Johan's GitHub Repo](https://github.com/Josch62/Gather-Script-For-ConfigMgr-TS/blob/main/Gather.ps1)) who has kindly allowed me to share and update his work.

> [!Tip]
> For testing, the script can be run locally by using the '-Debug' parameter as per the example below from an Administrator PowerShell prompt:
>``` powershell
> PS .\Pwsh-Gather.ps1 -Debug
>```

Feel free to reach out if there are any feature requests for the script and I will try to accomodate. 

Variables currently gathered are shown in the example output below:

## Sample Output Values

- AssetTag = "No Asset Information"
- BIOSReleaseDate = "10/17/2025 01:00:00"
- BIOSVersion = "N2JETA9W (1.87 )"
- BitlockerEncryptionMethod = "AES_256"
- DefaultGateway = "XXX.XXX.XXX.XXX"
- IPAddress = "XXX.XXX.XXX.XXX"
- IsBDE = "True"
- IsCoffeeLakeOrLater = "True"
- IsDesktop = "False"
- IsLaptop = "True"
- IsOnBattery = "False"
- IsOnEthernet = "False"
- IsServer = "False"
- IsTablet = "False"
- IsVM = "False"
- MacAddress = "XX:XX:XX:XX:XX:XX"
- Make = "LENOVO"
- Memory = "8005.1640625"
- Model = "ThinkPad X390"
- OsArchitecture = "64-bit"
- OsBuildNumber = "26200.8117"
- OsCaption = "Microsoft Windows 11 Pro"
- OsCurrentBuild = "26200"
- OsCurrentVersion = "10.0.26200"
- OsFeatureUpdateVersion = "25H2"
- OsInWinPE = "False"
- OsLocale = "en-GB"
- OsTimeZone = "(UTC+00:00) Dublin, Edinburgh, Lisbon, London"
- OsWindowsInstallationType = "Client"
- ProcessorFamily = "8265"
- ProcessorManufacturer = "GenuineIntel"
- ProcessorName = "Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz"
- ProcessorSpeed = "1800"
- Product = "20Q1000LUK"
- SerialNumber = "XXXXXXXX"
- SystemSKU = "LENOVO_MT_20Q1_BU_Think_FM_ThinkPad X390"
- UUID = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
- Vendor = "LENOVO"
- VMPlatform = "N/A"

## Give a Star ⭐
If you like or find the script useful then please repository a star ⭐.
