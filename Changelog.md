# Changelog
### History for module hp-wbem.psm1

### Sep 18, 2016
  **Get-HPArrayDisks**
  
  Added Status property for physical drive status (OK, Predictive Failure or Error) 

  **Get-HPArrayControllers**
  
  Added StorageVolumes (count) and CacheBackupType (Battery, Capacitor or N/A) properties. Improved ControllerStatus property

### Sep 14, 2016
  **Get-HPArrayVolumes**
  
  Added new function

### Jul 18, 2016
Moved project to Github. Functions included:
* Get-HPArrayDisks
* Get-HPArrayControllers
* Get-HPiLOInformation
* Get-HPNetworkAdapters
* Get-HPPowerSupplies
* Get-HPSystemInformation
