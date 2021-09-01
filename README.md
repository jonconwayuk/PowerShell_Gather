# PowerShell_Gather
PowerShell script to replace MDT Gather in Windows OSD.

It collects information from a device and stores these as variables which can then be utilised as SCCM Task Sequence variables to set logic for various actions.

The advantage of this is that in most scenarios, you not longer need to use MDT-integrated Task Sequences and can therefore avoid using and maintaining the various MDT components required otherwise.

Script can be run in a Task in an SCCM Task Sequence - easiest way is to add the script content as a "Run PowerShell Script' step with the Execution Policy set to 'Bypass'.

For testing, the script can be run locally by using the '-Debug' parameter as per the example below from an Administrator PowerShell prompt:

**PS C:\Users\Administrator\Documents\PowerShell_Gather> .\Pwsh-Gather.ps1 -Debug**

The vast majority of the groundwork for this script was done by Johan Schrewelius (https://gallery.technet.microsoft.com/PowerShell-script-that-a8a7bdd8) who has kindly allowed me to share and update his work.

Variables currently gathered are shown in the example output below:

- Architecture = X64
- AssetTag = CZC6XXXXXX
- BIOSReleaseDate = 04/19/2021 01:00:00
- BIOSVersion = N01 Ver. 02.53
- BitlockerEncryptionMethod = N/A
- DefaultGateway = 192.168.1.1
- IPAddress = 192.168.1.20
- IsBDE = False
- IsCoffeeLakeOrLater = False
- IsDesktop = True
- IsLaptop = False
- IsOnBattery = False
- IsOnEthernet = True
- IsServer = False
- IsTablet = False
- IsVM = False
- MacAddress = 48:0F:CF:45:06:F1,48:0F:CF:45:06:F1
- Make = HP
- Memory = 65415.58203125
- Model = HP EliteDesk 800 G2 SFF
- OSBuildNumber = 17763.2114
- OSCurrentBuild = 17763
- OSCurrentVersion = 10.0.17763
- OsInWinPE = False
- OsLocale = en-GB
- OsTimeZone = (UTC+00:00) Dublin, Edinburgh, Lisbon, London
- OsWindowsInstallationType = Server
- OsWindowsProductName = Windows Server 2019 Standard
- ProcessorFamily = 6700
- ProcessorManufacturer = GenuineIntel
- ProcessorName = Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz
- ProcessorSpeed = 3408
- Product = 8054
- SerialNumber = CZC6XXXXXX
- SystemSKU = L1G76AV
- UUID = D41CCC6A-E086-11E5-9C43-BC0000EE0000
- Vendor = HP
- VMPlatform = N/A