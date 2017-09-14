# hp-wbem
### Powershell Cmdlets for Hewlett Packard Insight Management WBEM providers

#### Functions in this module
* ##### Get-HPArrayDisks

  Information about pysical disks attached to array controllers
  
* ##### Get-HPArrayControllers

  Information about installed array controllers
  
* ##### Get-HPArrayVolumes

  Information about array storage volumes

* ##### Get-HPiLOInformation

  Information about iLO interfaces in a system

* ##### Get-HPNetworkAdapters

  Information about activated network adapters in a system

* ##### Get-HPPowerSupplies

  Information about installed power supplies

* ##### Get-HPSystemInformation

  Basic information about system such as product and serial number, amount and type of  CPU, RAM and power supplies

* ##### Get-HPTapeDrives

  Information about HP tape drives connected to a system through an HP controller
  
* ##### Get-HPTemperatureSensor

  Temperature status readings from all thermal sensors in a system

#### Usage
Import module in PowerShell:

`Import-Module hp-wbem.psm1`

#### Getting help
The Cmdlets are documented so you can use the normal get-help command in Powershell after loading the module.

`Get-Help Get-HPArrayDisks`
