function Get-OfficeErrorCode
{
    param
    (
    [int]
    [Parameter(Mandatory=$true)]
    $ErrorCode
    )
    # Office Error Codes
    # https://technet.microsoft.com/en-us/library/cc179058%28v=office.14%29.aspx
    switch($ErrorCode)
    {
        17301 { Write-Host 'Error: General Detection error' }
        17302 { Write-Host 'Error: Applying patch' }
        17303 { Write-Host 'Error: Extracting file' }
        17021 { Write-Host 'Error: Creating temp folder' }
        17022 { Write-Host 'Success: Reboot flag set' }
        17023 { Write-Host 'Error: User cancelled installation' }
        17024 { Write-Host 'Error: Creating folder failed' }
        17025 { Write-Host 'Patch already installed' }
        17026 { Write-Host 'Patch already installed to admin installation' }
        17027 { Write-Host 'Installation source requires full file update' }
        17028 { Write-Host 'No product installed for contained patch' }
        17029 { Write-Host 'Patch failed to install' }
        17030 { Write-Host 'Detection: Invalid CIF format' }
        17031 { Write-Host 'Detection: Invalid baseline' }
        17034 { Write-Host 'Error: Required patch does not apply to the machine' }
        17038 { Write-Host 'You do not have sufficient privileges to complete this installation for all users of the machine. Log on as administrator and then retry this installation.' }
        17044 { Write-Host 'Installer was unable to run detection for this package.' }
        default { Write-Host 'Unknown error' }
    }
}

function Invoke-SharePointWinRmConfig
{
    Enable-PSRemoting -Force
    Enable-WSManCredSSP –Role Server -Force
    winrm set winrm/config/winrs '@{MaxShellsPerUser="25"}'
    winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
}

function Get-RmFarmVersion
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Cred
    )

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $Cred
    $Version = Invoke-Command -Session $session -ScriptBlock { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell
            (Get-SPFarm).BuildVersion.Major
        }
    Remove-PSSession $session
    return $Version   
}

function Get-RmFarmServers
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Cred
    )

    $scriptBlock = { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell
            Get-SPServer | ?{$_.Role -ne 'Invalid'} | Select Name,Role 
        }

    $servers = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $Cred
    $serverList = $servers | select Name,Role
    return $serverList
}

function Get-RmDistributedCacheHosts
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Cred
    )


    $scriptBlock = { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell
            $dcs = Get-SPServiceInstance | ?{$_.TypeName -eq 'Distributed Cache'}
            $dcHosts = @()
            if($dcs.Count -gt 0)
            {
                foreach($dc in $dcs)
                {
                    $dcHosts += $dc.Server.Address
                }
            }

            return $dcHosts
        }

    $dcHosts = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $Cred

    return $dcHosts 
}

function Get-RmSearchServerHosts
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Cred
    )


    $scriptBlock = { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell
            $srs = Get-SPEnterpriseSearchServiceInstance| ?{$_.Status -eq 'Online'}
            $srsHosts = @()
            if($srs.Count -gt 0)
            {
                foreach($sr in $srs)
                {
                    $srsHosts += $sr.Server.Address
                }
            }

            return $srsHosts
        }

    $srsHosts = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $Cred
    return $srsHosts 
}

#Get-Patches not used
function Get-Patches
{
    $patches = gci -Path "$($patchesUnc)\" -Include *.exe
    foreach($patch in $patches)
    {
        $fullPaths = += $patch.FullName + ';'
    }
}

function Stop-RmSPServices
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $cred
    )

    $scriptBlock = {
        Write-Host 'Stopping IIS'
        Start-Process 'iisreset.exe' -ArgumentList '/stop' -Wait -PassThru -NoNewWindow
        Write-Host 'Disabling IISAdmin and SPTimerV4.'
        Set-Service -Name IISAdmin -StartupType Disabled
        Set-Service -Name SPTimerV4 -StartupType Disabled
        Write-Host 'Stopping IISAdmin'
        Stop-Service IISAdmin
        Write-Host 'Stopping SPTimerV4'
        Stop-Service SPTimerV4
    }

    Write-Host "Stopping services on $ServerName..."

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $cred
}

function Start-RmSPServices
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $cred
    )

    $scriptBlock = {
        Write-Host 'Setting IISAdmin and SPTimerV4 to Automatic.'
        Set-Service -Name IISAdmin -StartupType Automatic
        Set-Service -Name SPTimerV4 -StartupType Automatic
        Write-Host 'Starting IISAdmin'
        Start-Service IISAdmin
        Write-Host 'Starting SPTimerV4'
        Start-Service SPTimerV4
        Start-Process 'iisreset.exe' -ArgumentList '/start' -Wait -PassThru -NoNewWindow
    }

    Write-Host "Starting services on $ServerName..."
    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $cred
}

function Invoke-RmStopPauseSearch
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [int]
        [Parameter(Mandatory=$true)]
        $Version,
        [bool]
        [Parameter(Mandatory=$true)]
        $Pause,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        param
        (
            [string]
            [Parameter(Mandatory=$true)]
            $ServerName,
            [int]
            [Parameter(Mandatory=$true)]
            $Version,
            [bool]
            [Parameter(Mandatory=$true)]
            $Pause
        )

        $service = Get-Service SPSearchHostController
        $service2 = Get-Service OSearch15

        if(($service.Status -eq 'Stopped') -or ($service2.Status -eq 'Stopped'))
        {
            break
        }

        Add-PSSnapin Microsoft.SharePoint.PowerShell

        foreach($ssa in Get-SPEnterpriseSearchServiceApplication)
        {
            if($Pause)
            {
                #Check if paused first
                if ($ssa.IsPaused() -eq 128)
                {
                    break
                }
                Write-Host "Pausing $($ssa.Name)"
                $ssa.Pause()

                if($ssa.IsPaused() -eq 128)
                {
                    Write-Host 'Search paused successfully.'
                }
                else
                {
                    Write-Host 'Trying once more...'
                    $ssa.Pause()
                }
            }
        }

        if($Version -eq 15 -or $Version -eq 16)
        {
            Write-Host 'Disabling SPSearchHostController'
            Set-Service -Name SPSearchHostController -StartupType Disabled
            Stop-Service SPSearchHostController
        }

        Write-Host "Stopping OSearch$Version"
        switch ($Version)
        {
            14 {Set-Service -Name OSearch14 -StartupType Disabled; Stop-Service OSearch14 }
            15 {Set-Service -Name OSearch15 -StartupType Disabled; Stop-Service OSearch15 }
            16 {Set-Service -Name OSearch16 -StartupType Disabled; Stop-Service OSearch16 }
            default {}
        }
        break
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $ServerName,$Version,$Pause -Authentication Credssp -Credential $cred
}

function Invoke-RmStartResumeSearch
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [int]
        [Parameter(Mandatory=$true)]
        $Version,
        [bool]
        [Parameter(Mandatory=$true)]
        $Pause,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        param
        (
            [string]
            [Parameter(Mandatory=$true)]
            $ServerName,
            [int]
            [Parameter(Mandatory=$true)]
            $Version,
            [bool]
            [Parameter(Mandatory=$true)]
            $Pause
        )

<#        $service = Get-Service SPSearchHostController
        $service2 = Get-Service OSearch15

        if(($service.Status -ne 'Stopped') -or ($service2.Status -ne 'Stopped'))
        {
            break
        }#>

        Add-PSSnapin Microsoft.SharePoint.PowerShell -EA 0

        Write-Host "Starting OSearch$Version"
        switch ($Version)
        {
            14 {Set-Service -Name OSearch14 -StartupType Manual; Start-Service OSearch14;
                    $service = Get-Service OSearch14
                    while($service.Status -ne 'Running')
                    {Sleep 1}}
            15 {Set-Service -Name OSearch15 -StartupType Manual; Start-Service OSearch15;
                    $service = Get-Service OSearch15
                    while($service.Status -ne 'Running')
                    {Sleep 1}}
            16 {Set-Service -Name OSearch16 -StartupType Manual; Start-Service OSearch16                     
                    $service = Get-Service OSearch16
                    while($service.Status -ne 'Running')
                    {Sleep 1}}
        }



        if($Version -eq 15 -or $Version -eq 16)
        {
            Write-Host 'Enabling SPSearchHostController'
            Set-Service -Name SPSearchHostController -StartupType Automatic
            Start-Service SPSearchHostController
            $sevice = Get-Service SPSearchHostController

            while($service.Status -ne 'Running')
            {
                Sleep 1
            }
        }

        foreach($ssa in Get-SPEnterpriseSearchServiceApplication)
        {
            if($Pause)
            {
                Write-Host "Resuming $($ssa.Name)"
                $ssa.Resume()

                if($ssa.IsPaused() -eq 0)
                {
                    Write-Host 'Resumed Search succesfully'
                }
                else
                {
                    Write-Host 'Trying one more time...'
                    $ssa.Resume()
                }
            }
        }
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $ServerName,$Version,$Pause -Authentication Credssp -Credential $cred
}

function Invoke-RmPatch
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [bool]
        [Parameter(Mandatory=$true)]
        $isCacheHost,
        [string]
        [Parameter(Mandatory=$true)]
        $Patch,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

     $scriptBlock = {
        param([string]
            [Parameter(Mandatory=$true)]
            $Patch,
            [string]
            [Parameter(Mandatory=$true)]
            $ServerName
            )

        [bool]$restart = $false
        Write-Host "Installing $patch"
        $p = Start-Process $Patch -ArgumentList '/quiet /norestart' -Wait -PassThru -NoNewWindow
        Write-Host "Completed installing $patch with an ExitCode of $($p.ExitCode)"
        if(!($p.ExitCode -eq 0) -and !($p.ExitCode -eq 3010) -and !($p.ExitCode -eq 17022)){
            throw [System.Configuration.Install.InstallException] "The patch failed to install. ExitCode: $($p.ExitCode)"
            Get-OfficeErrorCode $p.ExitCode
        }

        if(($p.ExitCode -eq 3010) -or ($p.ExitCode -eq 17022))
        {
            $restart = $true
            Write-Host "A restart of $ServerName is required."
            return $restart
        }
    }

    Write-Host "Beginning patching process on $ServerName..."

    $restart = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $Patch,$ServerName -Authentication Credssp -Credential $cred

    if($restart)
    {
        if($isCacheHost)
        {
            Update-RmStopDistributedCache $ServerName $cred
        }

        Write-Host "-Restarting $ServerName"
        Restart-Computer -Force -ComputerName $ServerName -For WinRM -Wait

        if($isCacheHost)
        {
            Update-RmStartDistributedCache $ServerName $cred
        }
    }
}

function Invoke-RmConfigWizard
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        $confWizard = '-cmd upgrade -inplace b2b -wait -cmd applicationcontent -install -cmd installfeatures -cmd secureresources'
        Add-PSSnapin Microsoft.SharePoint.PowerShell
        Measure-Command {
            $p = Start-Process 'psconfig.exe' -ArgumentList $confWizard -Wait -PassThru -NoNewWindow
        }
        Write-Host "ExitCode: $($p.ExitCode)"
        }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $cred
}

function Invoke-RmSPContentDatabaseUpgrade
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [bool]
        [Parameter(Mandatory=$true)]
        $ConcurentPatching,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        param
        (
            [bool]
            [Parameter(Mandatory=$true)]
            $ConcurrentPatching
        )
        Add-PSSnapin Microsoft.SharePoint.PowerShell
        Write-Host 'Beginning Content Database Upgrade.'

        if($ConcurrentPatching -eq $true)
        {
            foreach($db in Get-SPContentDatabase)
            {
                $scriptBlock = {
                    param
                    (
                        [string]
                        [Parameter(Mandatory=$true)]
                        $databaseName
                    )

                    Write-Host "Upgrading $databaseName..."
                    Measure-Command {
                        Add-PSSnapin Microsoft.SharePoint.PowerShell
                        Upgrade-SPContentDatabase $databaseName -Confirm:$false
                    }
                    Write-Host "Completed upgrading $databaseName."
                }
                    Start-Job -Name 'ContentDatabaseUpgrade' $scriptBlock -ArgumentList $db.Name
            }

            Write-Host -NoNewline 'Waiting to upgrade Content Databases concurrently.'

            While (Get-Job -Name 'ContentDatabaseUpgrade' | where { $_.State -eq 'Running' } )
            {
                Start-Sleep 1
                Write-Host -NoNewline '.'
            }
        
            Write-Host
            Write-Host 'Upgrade Content Databases concurrently has completed.'

        }
        else
        {
            foreach($db in Get-SPContentDatabase)
            {
                Write-Host "Upgrading $($db.Name)..."
                Measure-Command {
                    Upgrade-SPContentDatabase $db -Confirm:$false
                }
                Write-Host "Completed upgrading $($db.Name)."
            }
        }

        Write-Host 'All Content Databases have been upgraded.'
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $ConcurentPatching -Authentication Credssp -Credential $cred
}

function Update-RmStopDistributedCache
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        $startTime = Get-Date
        $currentTime = $startTime
        $elapsedTime = $currentTime - $startTime
        $timeOut = 900

        try
        {
            Add-PSSnapin Microsoft.SharePoint.PowerShell

            Use-CacheCluster
            $computer = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
            Write-Host "Shutting down Distributed Cache host $computer."

            try
            {
                $hostInfo = Stop-CacheHost -Graceful -CachePort 22233 -HostName $computer
            }
            catch [Microsoft.ApplicationServer.Caching.DataCacheException]
            {
                Write-Host 'Unable to gracefully stop cache host.'
                Stop-SPDistributedCacheServiceInstance
                break
            }

            $hostInfo = Stop-CacheHost -Graceful -CachePort 22233 -HostName $computer

            while($elapsedTime.TotalSeconds -le $timeOut-and $hostInfo.Status -ne 'Down')
            {
                Write-Host "Host Status : [$($hostInfo.Status)]"
                Start-Sleep(5)
                $currentTime = Get-Date
                $elapsedTime = $currentTime - $startTime
                Get-AFCacheClusterHealth
                $hostInfo = Get-CacheHost -HostName $computer -CachePort 22233
            }

            Write-Host 'Stopping distributed cache host was successful. Updating Service status in SharePoint.'
            Stop-SPDistributedCacheServiceInstance
        }
        catch [System.Exception]
        {
            Write-Host 'Unable to stop cache host within 15 minutes.'
        }
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Authentication Credssp -Credential $cred
}

function Rename-LoadBalancerFile
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [bool]
        [Parameter(Mandatory=$true)]
        $Revert,
        [string]
        [Parameter(Mandatory=$true)]
        $filePath,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        param
        (
            [bool]
            [Parameter(Mandatory=$true)]
            $Revert,
            [string]
            [Parameter(Mandatory=$true)]
            $filePath
        )

        if(Test-Path -IsValid $filePath)
        {
            if($Revert -eq $true)
            {
                $fileName = [IO.Path]::GetFileName($filePath)
                $directory = [IO.Path]::GetDirectoryName($filePath)

                Rename-Item -Path "$directory\TestFile.txt" -NewName $fileName
            }
            else
            {
                Rename-Item -Path $filePath -NewName 'TestFile.txt'
            }
            Sleep 10
        }
        else
        {
            break
        }
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $Revert, $filePath -Authentication Credssp -Credential $cred
}

function Update-RmStartDistributedCache
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName,
        [PSCredential]
        [Parameter(Mandatory=$false)]
        $cred
    )

    $scriptBlock = {
        param
        (
            [string]
            [Parameter(Mandatory=$true)]
            $ServerName
        )

        Add-PSSnapin Microsoft.SharePoint.PowerShell -EA 0
            $si = Get-SPServiceInstance -Server $ServerName | ?{$_.TypeName -match 'Distributed Cache'}
            Write-Host "Starting Distributed Cache on $ServerName."
            $si.Provision()
            Write-Host 'Completed.'
        }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ArgumentList $ServerName -Authentication Credssp -Credential $cred
}
function Start-RmSPUpdate
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $StopServices,
        [bool]
        [Parameter(Mandatory=$true)]
        $PauseSearch,
        [string]
        [Parameter(Mandatory=$true)]
        $PatchToApply,
        [string]
        [Parameter(Mandatory=$true)]
        $PrimaryHost,
        [bool]
        [Parameter(Mandatory=$false)]
        $ConcurrentPatching,
        [bool]
        [Parameter(Mandatory=$false)]
        $WaitBetweenHosts,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Cred,
        [string]
        [Parameter(Mandatory=$false)]
        $lbFileLocation
    )

    if(!(Test-Path $PatchToApply))
    {
        Write-Host -ForegroundColor Red 'Unable to access patch path.'
        break
    }

    [int]$Version = 0

    Write-Host 'Retreiving Farm version...'
    $Version = Get-RmFarmVersion $PrimaryHost $Cred

    if($Version -eq $null -or $Version -eq 0)
    {
        Write-Host -ForegroundColor Red 'Error occurred when attempting to retrieve the Farm version.'
        break
    }

    $servers = @()

    Write-Host 'Retreiving Farm member servers...'
    $servers = Get-RmFarmServers $PrimaryHost $Cred
    
    if($servers -eq $null -or ($servers.Count -eq 0))
    {
        Write-Host -ForegroundColor Red 'Error occurred when attempting to retrieve Farm member servers.'
        break
    }

    $distributedCacheHosts = Get-RmDistributedCacheHosts $PrimaryHost $Cred
    $searchServerHosts = Get-RmSearchServerHosts $PrimaryHost $Cred

    if($ConcurrentPatching -eq $true)
    {
        $module = Resolve-Path '.\ARSPPM.psm1'

#region Rename-LoadBalancerFile
        foreach($server in $servers.Name)
        {
            if(!([string]::IsNullOrEmpty($lbFileLocation)))
            {
                $scriptBlock =
                {
                    param
                    (
                        [string]
                        [Parameter(Mandatory=$true)]
                        $ServerName,
                        [bool]
                        [Parameter(Mandatory=$true)]
                        $Revert,
                        [string]
                        [Parameter(Mandatory=$true)]
                        $filePath,
                        [PSCredential]
                        [Parameter(Mandatory=$true)]
                        $cred
                    )

                    Rename-LoadBalancerFile -ServerName $ServerName -Revert $Revert -filePath $filePath -cred $Cred
                }

                Start-Job -Name 'Rename-LoadBalancerFile' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                    -ScriptBlock $scriptBlock -ArgumentList $server,$false,$lbFileLocation,$Cred | Out-Null
            }
        }

        if (!([string]::IsNullOrEmpty($lbFileLocation)))
        {
            Write-Host -NoNewline 'Waiting to complete function Rename-LoadBalancerFile.'

            While (Get-Job -Name 'Rename-LoadBalancerFile' | where { $_.State -eq 'Running' } )
            {
                Start-Sleep 1
                Write-Host -NoNewline '.'
            }
        
            Write-Host
            Write-Host 'Rename-LoadBalancerFile has completed.'
        }
#endregion

#region Invoke-RmStopPauseSearch
        foreach($server iN $servers.Name)
        {   
            [bool]$isSrs = $false
            
            if($searchServerHosts.Contains($server))
            {
                $isSrs = $true
            }
            else
            {
                $isSrs = $false
            }

            if($isSrs -eq $true)
            {
                Write-Host "Starting function Invoke-RmStopPauseSearch on $server."

                $scriptBlock =
                {
                    param
                    (
                        [string]
                        [Parameter(Mandatory=$true)]
                        $ServerName,
                        [int]
                        [Parameter(Mandatory=$true)]
                        $Version,
                        [bool]
                        [Parameter(Mandatory=$true)]
                        $PauseSearch,
                        [PSCredential]
                        [Parameter(Mandatory=$true)]
                        $cred
                    )

                Invoke-RmStopPauseSearch -ServerName $ServerName -Version $Version -Pause $PauseSearch -cred $cred
                }

                Start-Job -Name 'Invoke-RmStopPauseSearch' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                    -ScriptBlock $scriptBlock -ArgumentList $server,$Version,$PauseSearch,$Cred | Out-Null
            }
        }

        Write-Host -NoNewline 'Waiting to complete function Invoke-RmStopPauseSearch.'

        While (Get-Job -Name 'Invoke-RmStopPauseSearch' | where { $_.State -eq 'Running' } )
        {
            Start-Sleep 1
            Write-Host -NoNewline '.'
        }
        
        Write-Host
        Write-Host 'Invoke-RmStopPauseSearch has completed.'
#endregion

#region Stop-RmSPServices       
        foreach($server in $servers.Name)
        {
            if($StopServices -eq $true)
            {
                    $scriptBlock =
                    {
                        param
                        (
                            [string]
                            [Parameter(Mandatory=$true)]
                            $ServerName,
                            [PSCredential]
                            [Parameter(Mandatory=$true)]
                            $cred
                        )

                        Stop-RmSPServices -ServerName $ServerName -cred $cred
                    }

                    Start-Job -Name 'Stop-RmSPServices' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                        -ScriptBlock $scriptBlock -ArgumentList $server,$Cred | Out-Null
                }
            }

        Write-Host -NoNewline 'Waiting to complete function Stop-RmSPServices.'

        While (Get-Job -Name 'Stop-RmSPServices' | where { $_.State -eq 'Running' } )
        {
            Start-Sleep 1
            Write-Host -NoNewline '.'
        }
        
        Write-Host
        Write-Host 'Stop-RmSPServices has completed.'
#endregion

#region Invoke-RmPatch
        foreach($server in $servers.Name)
        {
            [bool]$isDcs = $false


            if($distributedCacheHosts.Contains($server))
            {
                $isDcs = $true
            }

            Write-Host "Starting function Invoke-RmPatch on $server."

            $scriptBlock =
            {
                param
                (
                    [string]
                    [Parameter(Mandatory=$true)]
                    $ServerName,
                    [bool]
                    [Parameter(Mandatory=$true)]
                    $IsCacheHost,
                    [string]
                    [Parameter(Mandatory=$true)]
                    $Patch,
                    [PSCredential]
                    [Parameter(Mandatory=$true)]
                    $cred
                )

                Invoke-RmPatch -ServerName $ServerName -isCacheHost $IsCacheHost -Patch $Patch -cred $cred
            }
                
            Start-Job -Name 'Invoke-RmPatch' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                -ScriptBlock $scriptBlock -ArgumentList $server,$isDcs,$PatchToApply,$Cred | Out-Null
        }

        Write-Host -NoNewline 'Waiting to complete function Invoke-RmPatch.'

        While (Get-Job -Name 'Invoke-RmPatch' | where { $_.State -eq 'Running' } )
        {
            Start-Sleep 1
            Write-Host -NoNewline '.'
        }
        
        Write-Host
        Write-Host 'Invoke-RmPatch has completed.'
#endregion

#region Start-RmSPServices       
        foreach($server in $servers.Name)
        {
            if($StopServices -eq $true)
            {
                    $scriptBlock =
                    {
                        param
                        (
                            [string]
                            [Parameter(Mandatory=$true)]
                            $ServerName,
                            [PSCredential]
                            [Parameter(Mandatory=$true)]
                            $cred
                        )

                        Write-Host "Starting function Start-RmSPServices on $server."
                        Start-RmSPServices -ServerName $ServerName -cred $cred
                    }

                    Start-Job -Name 'Start-RmSPServices' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                        -ScriptBlock $scriptBlock -ArgumentList $server,$Cred | Out-Null
                }
            }

        Write-Host -NoNewline 'Waiting to complete function Start-RmSPServices.'

        While (Get-Job -Name 'Start-RmSPServices' | where { $_.State -eq 'Running' } )
        {
            Start-Sleep 1
            Write-Host -NoNewline '.'
        }
        
        Write-Host
        Write-Host 'Start-RmSPServices has completed.'
#endregion

#region Invoke-RmStartResumeSearch
        foreach($server iN $servers.Name)
        {   
            [bool]$isSrs = $false
            
            if($searchServerHosts.Contains($server))
            {
                $isSrs = $true
            }
            else
            {
                $isSrs = $false
            }

            if($isSrs -eq $true)
            {
                Write-Host "Starting function Invoke-RmStartResumeSearch on $server."

                $scriptBlock =
                {
                    param
                    (
                        [string]
                        [Parameter(Mandatory=$true)]
                        $ServerName,
                        [int]
                        [Parameter(Mandatory=$true)]
                        $Version,
                        [bool]
                        [Parameter(Mandatory=$true)]
                        $PauseSearch,
                        [PSCredential]
                        [Parameter(Mandatory=$true)]
                        $cred
                    )

                Invoke-RmStartResumeSearch -ServerName $ServerName -Version $Version -Pause $PauseSearch -cred $cred
                }

                Start-Job -Name 'Invoke-RmStartResumeSearch' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                    -ScriptBlock $scriptBlock -ArgumentList $server,$Version,$PauseSearch,$Cred | Out-Null
            }
        }

        Write-Host -NoNewline 'Waiting to complete function Invoke-RmStartResumeSearch.'

        While (Get-Job -Name 'Invoke-RmStartResumeSearch' | where { $_.State -eq 'Running' } )
        {
            Start-Sleep 1
            Write-Host -NoNewline '.'
        }
        
        Write-Host
        Write-Host 'Invoke-RmStartResumeSearch has completed.'
        
#endregion

#region Rename-LoadBalancerFile
        foreach($server in $servers.Name)
        {
            if(!([string]::IsNullOrEmpty($lbFileLocation)))
            {
                $scriptBlock =
                {
                    param
                    (
                        [string]
                        [Parameter(Mandatory=$true)]
                        $ServerName,
                        [bool]
                        [Parameter(Mandatory=$true)]
                        $Revert,
                        [string]
                        [Parameter(Mandatory=$true)]
                        $filePath,
                        [PSCredential]
                        [Parameter(Mandatory=$true)]
                        $cred
                    )

                    Rename-LoadBalancerFile -ServerName $ServerName -Revert $Revert -filePath $filePath -cred $Cred
                }

                Write-Host "Starting function Rename-LoadBalancerFile on $server."
                Start-Job -Name 'Rename-LoadBalancerFile' -InitializationScript ([scriptblock]::Create("Import-Module $module")) `
                    -ScriptBlock $scriptBlock -ArgumentList $server,$true,$lbFileLocation,$Cred | Out-Null
            }
        }

        if (!([string]::IsNullOrEmpty($lbFileLocation)))
        {
            Write-Host -NoNewline 'Waiting to complete function Rename-LoadBalancerFile.'

            While (Get-Job -Name 'Rename-LoadBalancerFile' | where { $_.State -eq 'Running' } )
            {
                Start-Sleep 1
                Write-Host -NoNewline '.'
            }
        
            Write-Host
            Write-Host 'Rename-LoadBalancerFile has completed.'
        }
#endregion

    }
    else
    {   
#region No Concurrency Run 
        foreach($server in $servers.Name)
        {
            Write-Host "Starting process on $server..."
            Measure-Command {
                [bool]$isDcs1 = $false
                [bool]$isSrs1 = $false

                if($distributedCacheHosts.Contains($server))
                {
                    $isDcs1 = $true
                }

                if($searchServerHosts.Contains($server))
                {
                    $isSrs1 = $true
                }

                if(!([string]::IsNullOrEmpty($lbFileLocation)))
                {
                    Rename-LoadBalancerFile $ServerName $false $lbFileLocation $Cred
                }

                Stop-RmSPServices $server $Cred

                if($isSrs1 -eq $true)
                {
                    Invoke-RmStopPauseSearch $server $version $PauseSearch $Cred
                }

                Invoke-RmPatch $server $isDcs1 $PatchToApply $Cred
                Start-RmSPServices $server $Cred

                if($isSrs1 -eq $true)
                {
                    Invoke-RmStartResumeSearch $server $version $PauseSearch $Cred
                }

                if(!([string]::IsNullOrEmpty($lbFileLocation)))
                {
                    Rename-LoadBalancerFile $ServerName $true $lbFileLocation $cred
                }

                $isDcs1 = $false
                $isSrs1 = $false

                if($WaitBetweenHosts -eq $true)
                {
                    Read-Host "Completed patching $server. Press Enter to continue or Ctrl-C to stop execution."
                }
            }
        }
#endregion
    }

    Write-Host 'Upgrading Content Databases...'
    Invoke-RmSPContentDatabaseUpgrade $PrimaryHost $ConcurrentPatching $Cred

#region Invoke-RmConfigWizard
    foreach($server in $servers.Name)
    {

        if(!([string]::IsNullOrEmpty($lbFileLocation)))
        {
            Rename-LoadBalancerFile $server $true $lbFileLocation $Cred
        }

        Write-Host 'Running Config Wizard...'
        Invoke-RmConfigWizard $server $Cred
        #validate result is 0 before moving to the next host
        if(!([string]::IsNullOrEmpty($lbFileLocation)))
        {
            Rename-LoadBalancerFile $server $true $lbFileLocation $Cred
        }

        if($WaitBetweenHosts -eq $true)
        {
            Read-Host "Completed running psconfig on $server. Press Enter to continue or Ctrl-C to stop execution."
        }  
    }
#endregion
}
