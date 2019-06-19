# Changelog
## History for module manifest file hp-wbem.psd1

### June 19, 2019

Generated manifest file


## History for module hp-wbem.psm1

### Sep 14, 2017
  **Get-HPTemperatureSensor**
  
  Added new function

### Dec 14, 2016
  **Get-HPArrayControllers**
  
  Added errorhandling
  
  **Get-HPArrayDisks**
  
  Added errorhandling

  **Get-HPArrayVolumes**
  
  Added errorhandling

**General**

  Improved error handling

### Oct 15, 2016
  **Get-HPTapeDrives**
  
  Added new function
  
  **General**

  Tidied up a few bits of code
  
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
