<#
HP Insight Management WBEM Provider functions

Per Bengtsson 2013-2016

Functions in this module:

Get-HPArrayDisks
Get-HPArrayControllers
Get-HPArrayVolumes
Get-HPiLOInformation
Get-HPNetworkAdapters
Get-HPPowerSupplies
Get-HPSystemInformation
Get-HPTapeDrives
Get-HPTemperatureSensor
#>



function Get-HPArrayDisks
{
    <#
    .SYNOPSIS
    Retrieves physical hard disk information for HP servers.
    
    .DESCRIPTION
    The Get-HPArrayDisks function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPArrayDisks
    Lists physical disk information for the local machine

    .EXAMPLE
    Get-HPArrayDisks SRV-HP-A
    Lists physical disk information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPArrayDisks
    Lists physical disk information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List disks on server " +$Computername)){
            Try
            {
                $diskdrives =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HPSA_DiskDrive" -ErrorAction Stop
                ForEach ($disk in $diskdrives){
                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name Slot -value $disk.ElementName
                    $OutObject | Add-Member -type NoteProperty -name Interface -value $disk.Description
                    $OutObject | Add-Member -type NoteProperty -name RotationalSpeed -value $disk.DriveRotationalSpeed

                    $drivePhys = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HPSA_DiskDrive.CreationClassName='HPSA_DiskDrive',DeviceID='" + $disk.DeviceID + "',SystemCreationClassName='" + $disk.SystemCreationClassName + "',SystemName='" + $disk.SystemName + "'} WHERE AssocClass=HPSA_DiskPhysicalPackageDiskDrive")
                    $driveModel = $drivePhys.Model
                    $driveModel = $driveModel -Replace "HP      ", ""
                    $driveModel = $driveModel -Replace "ATA     ", ""
                    $OutObject | Add-Member -type NoteProperty -name Model -value $driveModel
                    $OutObject | Add-Member -type NoteProperty -name SerialNumber -value $drivePhys.SerialNumber.trim()

                    $driveFW = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HPSA_DiskDrive.CreationClassName='HPSA_DiskDrive',DeviceID='" + $disk.DeviceID + "',SystemCreationClassName='" + $disk.SystemCreationClassName + "',SystemName='" + $disk.SystemName + "'} WHERE AssocClass=HPSA_DiskDriveDiskDriveFirmware")
                    $OutObject | Add-Member -type NoteProperty -name FirmwareVersion -value $driveFW.VersionString.trim()

                    $driveStorage = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HPSA_DiskDrive.CreationClassName='HPSA_DiskDrive',DeviceID='" + $disk.DeviceID + "',SystemCreationClassName='" + $disk.SystemCreationClassName + "',SystemName='" + $disk.SystemName + "'} WHERE AssocClass=HPSA_DiskDriveStorageExtent")
                    $OutObject | Add-Member -type NoteProperty -name SizeInGigabytes -value ([math]::round(($driveStorage.BlockSize * $driveStorage.NumberOfBlocks) / 1000000000))
                    $PowerOnHours = $driveStorage.TotalPowerOnHours
                    if ($PowerOnHours -eq 0) {$PowerOnHours = $null}
                    $OutObject | Add-Member -type NoteProperty -name PowerOnHours -value $PowerOnHours


                    Switch ($driveStorage.OperationalStatus){
                        2 {$driveStatus = "OK";break}
                        5 {$driveStatus = "Predictive Failure";break}
                        6 {$driveStatus = "Error";break}
                        default {$driveStatus = "Unknown";break}
                    }
                    $OutObject | Add-Member -type NoteProperty -name Status -value $driveStatus

                    Write-Output $OutObject
                } #end ForEach $disk
            }
            Catch
            {
                Write-Warning ("Can't get array disk information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }
            
        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPArrayDisks



function Get-HPArrayControllers
{
    <#
    .SYNOPSIS
    Retrieves array controller information for HP servers.
    
    .DESCRIPTION
    The Get-HPArrayControllers function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPArrayControllers
    Lists array controller information for the local machine

    .EXAMPLE
    Get-HPArrayControllers SRV-HP-A
    Lists array controller information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPArrayControllers
    Lists array controller information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List array controllers on server " +$Computername)){
            Try
            {
                $ArraySystems =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HPSA_ArraySystem -ErrorAction Stop
                ForEach ($ArraySys in $ArraySystems){
                
                    #ArraySystemFirmware
                    $ArrayFW = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemFirmware")

                    #ArraySystemArrayController
                    $ArrayController = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemArrayController")
                
                    #ArraySystemStorageVolume
                    $ArrayVolume = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemStorageVolume")
                    $ArrayVolumeCount = ($ArrayVolume | Measure-Object).Count
                
                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name ControllerName -value $ArrayController.ElementName

                    Switch ($ArrayController | Select-Object -ExpandProperty OperationalStatus -First 1) {
                        $null {$ControllerStatus = $null;break}
                        2 {$ControllerStatus = "OK";break}
                        3 {$ControllerStatus = "Degraded";break}
                        6 {$ControllerStatus = "Error";break}
                        default {$ControllerStatus = "Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name ControllerStatus -value $ControllerStatus

                    Switch ($ArrayController.AcceleratorBackupPowerSource) {
                        $null {$CacheBackupType = $null;break}
                        1 {$CacheBackupType="Battery";break}
                        2 {$CacheBackupType="Capacitor";break}
                        3 {$CacheBackupType="N/A";break}
                        default {$CacheBackupType="Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name CacheBackupType -value $CacheBackupType

                    Switch ($ArrayController.BatteryStatus) {
                        $null {$BatteryStatus = $null;break}
                        1 {$BatteryStatus = "OK";break}
                        2 {$BatteryStatus = "Failed";break}
                        3 {$BatteryStatus = "Not Fully Charged";break}
                        4 {$BatteryStatus = "Not Present";break}
                        default {$BatteryStatus = "Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name BatteryStatus -value $BatteryStatus
                
                    Switch ($ArrayController.CacheStatus) {
                        $null {$CacheStatus = $null;break}
                        1 {$CacheStatus="OK";break}
                        2 {$CacheStatus="Temporarily disabled";break}
                        3 {$CacheStatus="Permanently disabled";break}
                        4 {$CacheStatus="Not Configured";break}
                        default {$CacheStatus="Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name CacheStatus -value $CacheStatus
                
                    if ($ArrayController.IsSplitCacheSupported) {
                        $SplitReadSize = $ArrayController.SplitReadSize/1024/1024
                        $SplitWriteSize = $ArrayController.SplitWriteSize/1024/1024
                    }
                    else{
                        $SplitReadSize = $Null
                        $SplitWriteSize = $Null
                    }
                    $CacheSizeTotal = $ArrayController.CacheSizeTotal/1024/1024
                    $OutObject | Add-Member -type NoteProperty -name SplitCacheSupported -value ($ArrayController.IsSplitCacheSupported)
                    $OutObject | Add-Member -type NoteProperty -name ReadCacheSizeMB -value ($SplitReadSize)
                    $OutObject | Add-Member -type NoteProperty -name WriteCacheSizeMB -value ($SplitWriteSize)
                    $OutObject | Add-Member -type NoteProperty -name TotalCacheSizeMB -value ($CacheSizeTotal)
                    $OutObject | Add-Member -type NoteProperty -name StorageVolumes -value ($ArrayVolumeCount)
                    $OutObject | Add-Member -type NoteProperty -name FirmwareVersion -value ($ArrayFW.VersionString)
                    Write-Output $OutObject
                } # end Foreach $ArraySys
            }
            Catch
            {
                Write-Warning ("Can't get array controller information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        } # end of ShouldProcess
    } # end process
} # end function Get-HPArrayControllers



function Get-HPArrayVolumes
{
    <#
    .SYNOPSIS
    Retrieves array storage volume information for HP servers.
    
    .DESCRIPTION
    The Get-HPArrayVolumes function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPArrayVolumes
    Lists array volume information for the local machine

    .EXAMPLE
    Get-HPArrayVolumes SRV-HP-A
    Lists array volume information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPArrayVolumes
    Lists array volume information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List array volumes on server " +$Computername)){
            Try {
                $ArraySystems =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HPSA_ArraySystem -ErrorAction Stop
                ForEach ($ArraySys in $ArraySystems){
                
                    #ArraySystemArrayController
                    $ArrayController = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemArrayController")
                
                    #ArraySystemStorageVolume
                    $ArrayVolumes = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemStorageVolume")
                    # array controllers with no volumes return a null object instead of an empty collection which breaks the ForEach loop
                    if ($null -eq $ArrayVolumes){$ArrayVolumes = @()} 

                    ForEach ($ArrayVolume in $ArrayVolumes){
                        $OutObject = New-Object System.Object
                        $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                        $OutObject | Add-Member -type NoteProperty -name ControllerName -value $ArrayController.ElementName
                        $OutObject | Add-Member -type NoteProperty -name OSDiskID -value $ArrayVolume.OSName
                        $OutObject | Add-Member -type NoteProperty -name SizeInGigabytes -value ([math]::round(($ArrayVolume.BlockSize * $ArrayVolume.NumberOfBlocks) / 1000000000))
                
                        # Fault tolerance model
                        Switch ($ArrayVolume.FaultTolerance) {
                            1 {$FaultTolerance = "RAID 0";break}
                            2 {$FaultTolerance = "RAID 1";break}
                            3 {$FaultTolerance = "RAID 1+0";break}
                            4 {$FaultTolerance = "RAID 4";break}
                            5 {$FaultTolerance = "RAID 5";break}
                            6 {$FaultTolerance = "RAID 51";break}
                            7 {$FaultTolerance = "RAID 6";break}
                            8 {$FaultTolerance = "RAID 50";break}
                            9 {$FaultTolerance = "RAID 60";break}
                            default {$FaultTolerance = "Unknown"}
                        }
                        $OutObject | Add-Member -type NoteProperty -name FaultTolerance -value $FaultTolerance
                        $OutObject | Add-Member -type NoteProperty -name StripeSizeKB -value ($ArrayVolume.StripeSize/1024)

                        # Operational Status
                        Switch ($ArrayVolume.OperationalStatus) {
                            2 {
                                $OperationalStatus = "OK"
                                $ExtStatus = $null
                                break
                                }
                            3 {
                                $OperationalStatus = "Degraded"
                                $ExtStatus = $ArrayVolume.OperationalStatus[1]
                                break
                                }
                            6 {
                                $OperationalStatus = "Failed"
                                $ExtStatus = $ArrayVolume.OperationalStatus[1]
                                break
                                }
                            default {
                                $FaultTolerance = "Unknown"
                                $ExtStatus = $null
                                }
                        } # end switch
                    
                        Switch ($ExtStatus) {
                            $null {
                                $StatusReason = $null
                                break;
                            }
                            0x8000 {
                                $StatusReason = "Physical drive improperly connected"
                                break
                            }
                            0x8001 {
                                $StatusReason = "Expanding"
                                break
                            }
                            0x8002 {
                                $StatusReason = "Overheated"
                                break
                            }
                            0x8003 {
                                $StatusReason = "Overheating"
                                break
                            }
                            0x8004 {
                                $StatusReason = "Interim Recovery"
                                break
                            }
                            0x8005 {
                                $StatusReason = "Not configured"
                                break
                            }
                            0x8006 {
                                $StatusReason = "Not yet available"
                                break
                            }
                            0x8007 {
                                $StatusReason = "Queued for expansion"
                                break
                            }
                            0x8008 {
                                $StatusReason = "Ready for recovery"
                                break
                            }
                            0x8009 {
                                $StatusReason = "Recovering"
                                break
                            }
                            0x800A {
                                $StatusReason = "Wrong drive replaced"
                                break
                            }
                            0x800B {
                                $StatusReason = "Erase in Progress"
                                break
                            }
                            0x800C {
                                $StatusReason = "Erase completed"
                                break
                            }
                            default {
                                $StatusReason = "Unknown"
                                break
                            }
                        }
                    
                        $OutObject | Add-Member -type NoteProperty -name OperationalStatus -value $OperationalStatus
                        $OutObject | Add-Member -type NoteProperty -name StatusReason -value $StatusReason
                                    
                        $OutObject | Add-Member -type NoteProperty -name PercentComplete -value $ArrayVolume.PercentComplete

                        Write-Output $OutObject
                    } # end ForEach $ArrayVolume
                } #end ForEach $ArraySys
            }
            Catch
            {
                Write-Warning ("Can't get array volume information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }
        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPArrayVolumes



function Get-HPiLOInformation
{
    <#
    .SYNOPSIS
    Retrieves iLO management controller firmware information
    for HP servers.
    
    .DESCRIPTION
    The Get-HPiLOInformation function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPiLOInformation
    Lists iLO firmware information for the local machine

    .EXAMPLE
    Get-HPiLOInformation SRV-HP-A
    Lists iLO firmware information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPiLOInformation
    Lists iLO firmware information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("Retrieve iLO information from server " +$Computername)){
            Try
            {
                $MpFirmwares =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HP_MPFirmware" -ErrorAction Stop
                ForEach ($fw in $MpFirmwares){
                    $Mp = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HP_MPFirmware.InstanceID='" + $fw.InstanceID + "'} WHERE AssocClass=HP_MPInstalledFirmwareIdentity")

                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name ControllerName -value $fw.Name

                    Switch ($Mp.HealthState){
                        5 {$stat = "OK"; break}
                        10 {$stat = "Degraded/Warning"; break}
                        20 {$stat = "Major Failure"; break}
                        default {$stat = "Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name HealthState -value $stat

                    $OutObject | Add-Member -type NoteProperty -name UniqueIdentifier -value $Mp.UniqueIdentifier.Trim()
                    $OutObject | Add-Member -type NoteProperty -name Hostname -value $Mp.Hostname
                    $OutObject | Add-Member -type NoteProperty -name IPAddress -value $Mp.IPAddress

                    Switch ($Mp.NICCondition){
                        2 {$stat = "OK"; break}
                        3 {$stat = "Disabled"; break}
                        4 {$stat = "Not in use"; break}
                        5 {$stat = "Disconnected"; break}
                        6 {$stat = "Failed"; break}
                        default {$stat = "Unknown"}
                    }
                    $OutObject | Add-Member -type NoteProperty -name NICCondition -value $stat
                    $OutObject | Add-Member -type NoteProperty -name FirmwareVersion -value $fw.VersionString
                    $OutObject | Add-Member -type NoteProperty -name ReleaseDate -value ($fw.ConvertToDateTime($fw.ReleaseDate))

                    Write-Output $OutObject

                } # end of ForEach $fw
            }
            Catch
            {
                Write-Warning ("Can't get iLO information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }
        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPiLOInformation



function Get-HPNetworkAdapters
{
    <#
    .SYNOPSIS
    Retrieves network adapter information for HP servers.
    
    .DESCRIPTION
    The Get-HPNetworkAdapters function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    Adapters that have been disabled will not be listed since they
    don't expose enough information through the WBEM providers.    
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPNetworkAdapters
    Lists network adapter information for the local machine

    .EXAMPLE
    Get-HPNetworkAdapters SRV-HP-A
    Lists network adapter information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPNetworkAdapters
    Lists network adapter information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List network adapters on server " +$Computername)){
            Try {
                $HpWinEthBootcodeVersions = Get-WmiObject -ComputerName $Computername -Namespace "Root\Hpq" -Class "HP_WinEthBootcodeVersion" -ErrorAction Stop
                foreach ($Nic in $HpWinEthBootcodeVersions) {
                    $NicId = $Nic.InstanceID
                    $Firmware = $Nic.VersionString

                    $HpWinEthernetPort = Get-WmiObject -ComputerName $Computername -Namespace "Root\Hpq" -Class "HP_WinEthernetPort" -ErrorAction Stop -Filter "DeviceID='$NicID'"
                    $PDO = $HpWinEthernetPort.Name -replace '\\', '\\'
                    
                    $Win32PnpSignedDriver = Get-WmiObject -ComputerName $Computername -Namespace "Root\Cimv2" -Class Win32_PnpSignedDriver -ErrorAction Stop -Filter "PDO='$PDO'"
                    $DriverVersion = $Win32PnpSignedDriver.DriverVersion
                    $DriverName = $Win32PnpSignedDriver.DeviceName
                    
                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name DriverName -value $DriverName
                    $OutObject | Add-Member -type NoteProperty -name DriverVersion -value $DriverVersion
                    $OutObject | Add-Member -type NoteProperty -name Firmware -value $Firmware
                    Write-Output $OutObject

                } # end foreach nic

            }
            Catch
            {
                Write-Warning ("Can't get network adapter information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPNetworkAdapters



function Get-HPPowerSupplies
{
    <#
    .SYNOPSIS
    Retrieves power supply information for HP servers.
    
    .DESCRIPTION
    The Get-HPPowerSupplies function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPPowerSupplies
    Lists power supply information for the local machine

    .EXAMPLE
    Get-HPPowerSupplies SRV-HP-A
    Lists power supply information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPPowerSupplies
    Lists power supply information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List power supplies on server " +$Computername)){
            Try {
                $HpPowerSupplyModules = Get-WmiObject -ComputerName $Computername -Namespace "Root\Hpq" -Class "HP_PowerSupplyModule" -ErrorAction Stop
                foreach ($Psu in $HpPowerSupplyModules) {
                    $PsuCaption = $Psu.Caption
                    $PsuPartNumber = $Psu.PartNumber
                    if ($Psu.RemovalConditions -eq 3) {
                        $HotSwappable = $false
                    }
                    if ($Psu.RemovalConditions -eq 4) {
                        $HotSwappable = $true
                    }
                    $PsuStatus = $Psu.StatusDescriptions[0]
                    
                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name Caption -value $PsuCaption
                    $OutObject | Add-Member -type NoteProperty -name PartNumber -value $PsuPartNumber
                    $OutObject | Add-Member -type NoteProperty -name HotSwappable -value $HotSwappable
                    $OutObject | Add-Member -type NoteProperty -name Status -value $PsuStatus
                    Write-Output $OutObject

                } # end foreach PSU

            }
            Catch
            {
                Write-Warning ("Can't get power supply information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPPowerSupplies



function Get-HPSystemInformation
{
    <#
    .SYNOPSIS
    Retrieves general system information for HP servers.
    
    .DESCRIPTION
    The Get-HPSystemInformation function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPSystemInformation
    Lists system information for the local machine

    .EXAMPLE
    Get-HPSystemInformation SRV-HP-A
    Lists system information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPSystemInformation
    Lists system information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("Retrieve system information from server " +$ComputerName)){

            Try
            {
                $Processors = Get-WmiObject -Computername $ComputerName -Namespace root\cimv2 -Class Win32_Processor -ErrorAction Stop
                $PowerSupplies = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_WinPowerRedundancySet -ErrorAction Stop
                $PowerSupplySlots = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_PowerSupplySlot -ErrorAction Stop
                $SystemRom = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_SystemROMFirmware -ErrorAction Stop | Where-Object {$_.instanceID -match '001'}
                $Chassis =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -class HP_ComputerSystemChassis -ErrorAction Stop
                ForEach ($chassisitem in $Chassis){

                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name Model -value $chassisitem.Model
                    $OutObject | Add-Member -type NoteProperty -name ProductID -value $chassisitem.ProductID
                    $OutObject | Add-Member -type NoteProperty -name SerialNumber -value $chassisitem.SerialNumber
                    
                    $ProcessorCount = ($Processors | Measure-Object).Count
                    $OutObject | Add-Member -type NoteProperty -name NoOfProcessors -value $ProcessorCount
                    $ProcessorModel = $Processors | Select-Object -ExpandProperty Name -Unique
                    $OutObject | Add-Member -type NoteProperty -name ProcessorModel -value $ProcessorModel
                    
                    $PsuSlotCount = ($PowerSupplySlots | Measure-Object).Count
                    $OutObject | Add-Member -type NoteProperty -name NoOfPsuSlots -value $PsuSlotCount
                    if ($PowerSupplies) {
                        switch ($PowerSupplies.RedundancyStatus){
                            2 {$RedundancyStatus = "Fully Redundant"; break}
                            3 {$RedundancyStatus = "Degraded Redundancy"; break}
                            4 {$RedundancyStatus = "Redundancy Lost"; break}
                            5 {$RedundancyStatus = "Overall Failure"; break}
                            default {$RedundancyStatus = "Unknown"}
                        }
                        $OutObject | Add-Member -type NoteProperty -name PSURedundancy -value $True
                        $OutObject | Add-Member -type NoteProperty -name PSURedundancyStatus -value $RedundancyStatus
                    }
                    else {
                        $OutObject | Add-Member -type NoteProperty -name PSURedundancy -value $False
                        $OutObject | Add-Member -type NoteProperty -name PSURedundancyStatus -value $Null
                    }

                    $OutObject | Add-Member -type NoteProperty -name SystemROMName -value $SystemROM.Name
                    $OutObject | Add-Member -type NoteProperty -name SystemROMVersion -value $SystemROM.VersionString

                    Write-Output $OutObject

                }
            }
            Catch
            {
                Write-Warning ("Can't get system information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }
        }

    } # end of ShouldProcess
} # end function Get-HPSystemInformation



function Get-HPTapeDrives
{
    <#
    .SYNOPSIS
    Retrieves tape drive information for HP servers.
    
    .DESCRIPTION
    The Get-HPTapeDrives function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPTapeDrives
    Lists tape drive information for the local machine

    .EXAMPLE
    Get-HPTapeDrives SRV-HP-A
    Lists tape drive information for server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPTapeDrives
    Lists tape drive information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername
    )

    Process{

        if ($pscmdlet.ShouldProcess("List tape drives on server " +$Computername)){
            Try {
                $tapedrives = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HPWMITape_TapeDrive" -ErrorAction Stop
                ForEach ($tapedrive in $tapedrives){
                    $OutObject = New-Object System.Object
                    # basic information
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name ElementName -value $tapedrive.ElementName
                    
                    # interface type
                    $driveConnection = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HPWMITape_TapeDrive.CreationClassName='HPWMITape_TapeDrive',DeviceID='" + $tapedrive.DeviceID + "',SystemCreationClassName='" + $tapedrive.SystemCreationClassName + "',SystemName='" + $tapedrive.SystemName + "'} WHERE AssocClass=HPWMITape_TapeDriveToProtocolEndpoint") -ErrorAction Stop
                    Switch ($driveConnection.ConnectionType){
                        3 {$driveInterface="Parallel SCSI";break}
                        8 {$driveInterface="SAS";break}
                    }
                    $OutObject | Add-Member -type NoteProperty -name Interface -value $driveInterface

                    # drive firmware and s/n
                    $driveFW = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query ("ASSOCIATORS OF {HPWMITape_TapeDrive.CreationClassName='HPWMITape_TapeDrive',DeviceID='" + $tapedrive.DeviceID + "',SystemCreationClassName='" + $tapedrive.SystemCreationClassName + "',SystemName='" + $tapedrive.SystemName + "'} WHERE AssocClass=HPWMITape_TapeDriveToTapeDriveFirmware") -ErrorAction Stop
                    $OutObject | Add-Member -type NoteProperty -name SerialNumber -value $driveFW.SerialNumber.trim()
                    $OutObject | Add-Member -type NoteProperty -name FirmwareVersion -value $driveFW.VersionString.trim()

                    # operational status
                    Switch ($tapedrive.OperationalStatus){
                        2 {$driveStatus = "OK";break}
                        3 {$driveStatus = "Degraded";break}
                        6 {$driveStatus = "Error";break}
                        10 {$driveStatus = "Stopped/Offline";break}
                        default {$driveStatus = "Unknown";break}
                    }
                    $OutObject | Add-Member -type NoteProperty -name Status -value $driveStatus
                    
                    # cleaning status
                    if ($tapedrive.NeedsCleaning)
                    {
                        $NeedsCleaning = $true
                    }
                    else
                    {
                        $NeedsCleaning = $false
                    }
                    $OutObject | Add-Member -type NoteProperty -name NeedsCleaning -value $NeedsCleaning
                    
                    Write-Output $OutObject
                }
            }
            Catch
            {
                Write-Warning ("Can't get tape drive information for "+$Computername + ". " + $_.Exception.Message)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        } # end of ShouldProcess
    } # end of Process
} # end function Get-HPTapeDrives



function Get-HPTemperatureSensor
{
    <#
    .SYNOPSIS
    Retrieves temperature sensor readings from HP servers.
    
    .DESCRIPTION
    The Get-HPTemperatureSensor function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being queried.
    
    .PARAMETER Computername
    The HP server to retrieve information from.
    This parameter is optional and if the parameter isn't specified
    the command defaults to local machine.
    First positional parameter.

    .EXAMPLE
    Get-HPTemperatureSensor
    Lists temperature sensor information from all sensor on for the 
    local machine

    .EXAMPLE
    Get-HPTemperatureSensor SRV-HP-A
    Lists all temperature sensor information on server SRV-HP-A

    .EXAMPLE
    Get-HPTemperatureSensor SRV-HP-A -SensorID 1
    Lists information for temperature sensor 1 on server SRV-HP-A

    .EXAMPLE
    "SRV-HP-A", "SRV-HP-B", "SRV-HP-C" | Get-HPTemperatureSensor
    Lists tape drive information for three servers
    
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)][string]$Computername=$env:computername,
    [Parameter(Mandatory=$false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true)][int[]]$SensorID
    )

    Process{

        if ($SensorID -eq $null ){

            if ($pscmdlet.ShouldProcess("List all temperature sensors information on server " +$Computername)){
                # retrieve all sensors
                Try {
                    $tempsensors = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HP_WinNumericSensor" -ErrorAction Stop
                    ForEach ($tempsensor in $tempsensors){
                        $OutObject = New-Object System.Object
                        $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                        $OutObject | Add-Member -type NoteProperty -name ID -value $tempsensor.DeviceID
                        $OutObject | Add-Member -type NoteProperty -name Status -value $tempsensor.CurrentState
                        $OutObject | Add-Member -type NoteProperty -name Temp -value $tempsensor.CurrentReading
                        $OutObject | Add-Member -type NoteProperty -name Threshhold -value $tempsensor.UpperThresholdCritical
                        $OutObject | Add-Member -type NoteProperty -name Description -value $tempsensor.Description
                        Write-Output $OutObject
                    }
                }
                Catch
                {
                    Write-Warning ("Can't get temperature sensor information for "+$Computername + ". " + $_.Exception.Message)
                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    Write-Output $OutObject
                }

            } # end of ShouldProcess
        }
        else {

            if ($pscmdlet.ShouldProcess("List selected temperature sensors information on server " +$Computername)){
                # retrieve specified sensors
                foreach ($sensor in $SensorID) {
                    Try {
                        $tempsensors = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HP_WinNumericSensor where DeviceID ='Temperature Sensor $sensor'" -ErrorAction Stop
                        ForEach ($tempsensor in $tempsensors){
                            $OutObject = New-Object System.Object
                            $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                            $OutObject | Add-Member -type NoteProperty -name ID -value $tempsensor.DeviceID
                            $OutObject | Add-Member -type NoteProperty -name Description -value $tempsensor.Description
                            $OutObject | Add-Member -type NoteProperty -name Status -value $tempsensor.CurrentState
                            $OutObject | Add-Member -type NoteProperty -name Temp -value $tempsensor.CurrentReading
                            $OutObject | Add-Member -type NoteProperty -name Threshhold -value $tempsensor.UpperThresholdCritical
                            Write-Output $OutObject
                        }
                    }
                    Catch
                    {
                        Write-Warning ("Can't get temperature sensor information for "+$Computername + ". " + $_.Exception.Message)
                        $OutObject = New-Object System.Object
                        $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                        Write-Output $OutObject
                    }
                }

            } # end of ShouldProcess
                
        } #end if SensorID

    } # end of Process
} # end function Get-HPTemperatureSensor
