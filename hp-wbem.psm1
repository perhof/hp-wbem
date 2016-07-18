<#
HP Insight Management WBEM Provider functions

Per Bengtsson 2013-2016

Functions in this module:

Get-HPArrayDisks
Get-HPArrayControllers
Get-HPiLOInformation
Get-HPNetworkAdapters
Get-HPPowerSupplies
Get-HPSystemInformation

#>



function Get-HPArrayDisks
{
    <#
    .SYNOPSIS
    Retrieves physical hard disk information for HP servers.
    
    .DESCRIPTION
    The Get-HPArrayDisks function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    
    .PARAMETER Computername
    The HP server for which the disks should be listed.
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
            $diskdrives =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HPSA_DiskDrive"
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
                $OutObject | Add-Member -type NoteProperty -name PowerOnHours -value $driveStorage.TotalPowerOnHours

                Write-Output $OutObject
            }
        }

    } # end of ShouldProcess
} # end function Get-HPArrayDisks



function Get-HPArrayControllers
{
    <#
    .SYNOPSIS
    Retrieves array controller information for HP servers.
    
    .DESCRIPTION
    The Get-HPArrayControllers function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    
    .PARAMETER Computername
    The HP server for which the array controllers should be listed.
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
            $ArraySystems =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HPSA_ArraySystem
            ForEach ($ArraySys in $ArraySystems){
                
                #ArraySystem
                #$sa = Get-WmiObject -ComputerName kst-kal -Namespace root\hpq -class HPSA_ArraySystem

                #ArraySystemFirmware
                $ArrayFW = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemFirmware")

                #ArraySystemArrayController
                $ArrayController = Get-WmiObject -Computername $Computername -Namespace root\hpq -Query ("associators of {HPSA_ArraySystem.CreationClassName='HPSA_ArraySystem',Name='" + $ArraySys.Name + "'} WHERE AssocClass=HPSA_ArraySystemArrayController")
                
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                $OutObject | Add-Member -type NoteProperty -name ControllerName -value $ArrayController.ElementName

                Switch ($ArrayController | select -ExpandProperty OperationalStatus | select -first 1) {
                    2 {$ControllerStatus = "OK";break}
                    6 {$ControllerStatus = "ERROR";break}
                    default {$ControllerStatus = "Unknown"}
                }
                $OutObject | Add-Member -type NoteProperty -name ControllerStatus -value $ControllerStatus

                Switch ($ArrayController.BatteryStatus) {
                    1 {$BatteryStatus = "OK";break}
                    2 {$BatteryStatus = "Failed";break}
                    3 {$BatteryStatus = "Not Fully Charged";break}
                    4 {$BatteryStatus = "Not Present";break}
                    default {$BatteryStatus = "Unknown"}
                }
                $OutObject | Add-Member -type NoteProperty -name BatteryStatus -value $BatteryStatus
                
                Switch ($ArrayController.CacheStatus) {
                    1 {$CacheStatus="OK";break}
                    2 {$CacheStatus="Temporarily disabled";break}
                    3 {$CacheStatus="Permanently disabled";break}
                    4 {$CacheStatus="Not Configured";break}
                    default {$CacheStatus="Unknown"}
                }
                $OutObject | Add-Member -type NoteProperty -name CacheStatus -value ($CacheStatus)
                
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
                
                $OutObject | Add-Member -type NoteProperty -name FirmwareVersion -value ($ArrayFW.VersionString)
                Write-Output $OutObject
            }
        }

    } # end of ShouldProcess
} # end function Get-HPArrayControllers



function Get-HPiLOInformation
{
    <#
    .SYNOPSIS
    Retrieves iLO management controller firmware information
    for HP servers.
    
    .DESCRIPTION
    The Get-HPiLOInformation function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    
    .PARAMETER Computername
    The HP server for which the iLO firmware info should be listed.
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
            $MpFirmwares =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Query "select * from HP_MPFirmware"
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

            }
        }

    } # end of ShouldProcess
} # end function Get-HPiLOInformation



function Get-HPNetworkAdapters
{
    <#
    .SYNOPSIS
    Retrieves network adapter information for HP servers.
    
    .DESCRIPTION
    The Get-HPNetworkAdapters function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    Adapters that have been disabled will not be listed since they
    don't expose enough information through the WBEM providers.    
    
    .PARAMETER Computername
    The HP server for which the network adapters should be listed.
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
                Write-Warning ("Can't get system information for "+$Computername)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        }

    } # end of ShouldProcess
} # end function Get-HPNetworkAdapters



function Get-HPPowerSupplies
{
    <#
    .SYNOPSIS
    Retrieves power supply information for HP servers.
    
    .DESCRIPTION
    The Get-HPPowerSupplies function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    
    .PARAMETER Computername
    The HP server for which the power supplies should be listed.
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
                Write-Warning ("Can't get system information for "+$Computername)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }

        }

    } # end of ShouldProcess
} # end function Get-HPPowerSupplies



function Get-HPSystemInformation
{
    <#
    .SYNOPSIS
    Retrieves general system information for HP servers.
    
    .DESCRIPTION
    The Get-HPSystemInformation function works through WMI and requires
    that the HP Insight Management WBEM Providers are installed on
    the server that is being quiered.
    
    .PARAMETER Computername
    The HP server for which the system information should be listed.
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
                $Processors = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_Processor -ErrorAction Stop
                $PowerSupplies = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_WinPowerRedundancySet -ErrorAction Stop
                $PowerSupplySlots = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_PowerSupplySlot -ErrorAction Stop
                $SystemRom = Get-WmiObject -Computername $ComputerName -Namespace root\hpq -Class HP_SystemROMFirmware -ErrorAction Stop | where {$_.instanceID -match '001'}
                $Chassis =  Get-WmiObject -Computername $ComputerName -Namespace root\hpq -class HP_ComputerSystemChassis -ErrorAction Stop
                #if ($Chassis -eq $null) { return }
                ForEach ($item in $Chassis){

                    $OutObject = New-Object System.Object
                    $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                    $OutObject | Add-Member -type NoteProperty -name Model -value $item.Model
                    $OutObject | Add-Member -type NoteProperty -name ProductID -value $item.ProductID
                    $OutObject | Add-Member -type NoteProperty -name SerialNumber -value $item.SerialNumber
                    
                    $ProcessorCount = ($Processors | measure).Count
                    $OutObject | Add-Member -type NoteProperty -name NoOfProcessors -value $ProcessorCount
                    $ProcessorModel = $Processors | select -ExpandProperty Description -Unique
                    $OutObject | Add-Member -type NoteProperty -name ProcessorModel -value $ProcessorModel
                    
                    $PsuSlotCount = ($PowerSupplySlots | measure).Count
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

                Write-Warning ("Can't get system information for "+$Computername)
                $OutObject = New-Object System.Object
                $OutObject | Add-Member -type NoteProperty -name ComputerName -value $ComputerName
                Write-Output $OutObject
            }
        }

    } # end of ShouldProcess
} # end function Get-HPSystemInformation