$initialHost = '' #Get farm server information
$patchUnc = '' #folder containing patch
$patches = @() #array of patches (exe detection)
$fullPaths = ''
$confWizard = 'psconfig.exe -cmd upgrade -inplace b2b -wait -cmd applicationcontent -install -cmd installfeatures -cmd secureresources'

function Get-RmFarmVersion
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    $Version = Invoke-Command -Session $session -ScriptBlock { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell; 
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
        $ServerName
    )

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    $servers = Invoke-Command -Session $session -ScriptBlock { 
            Add-PSSnapin Microsoft.SharePoint.PowerShell; 
            Get-SPServer | ?{$_.Role -ne 'Invalid'} | Select Name,Role; 
        }

    $serverList = $servers | select Name,Role
    Remove-PSSession $session
    return $serverList
}
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
        $ServerName
    )

    $scriptBlock = {
        Start-Process 'iisreset.exe' -ArgumentList '/stop' -Wait -PassThru -NoNewWindow
        Set-Service -Name IISAdmin -StartupType Disabled
        Set-Service -Name SPTimerV4 -StartupType Disabled
        Stop-Service IISAdmin
        Stop-Service SPTimerV4
    }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
}

function Start-RmSPServices
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    $scriptBlock = {
        Set-Service -Name IISAdmin -StartupType Automatic
        Set-Service -Name SPTimerV4 -StartupType Automatic
        Start-Service IISAdmin
        Start-Service SPTimerV4
        Start-Process 'iisreset.exe' -ArgumentList '/start' -Wait -PassThru -NoNewWindow
    }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
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
        $Pause
    )

    $scriptBlock = {
        Add-PSSnapin Microsoft.SharePoint.PowerShell

        foreach($ssa in Get-SPEnterpriseSearchServiceApplication)
        {
            if($using:Pause)
            {
                [int]$i = 0

                $ssa.Pause()

                while($ssa.IsPaused() -ne 128)
                {
                    Sleep 10
                    ++$i

                    if(i -gt 24)
                    {
                        #timeout
                        break
                    }
                }
            }
        }

        if($using:Version -eq 15 -or $using:Version -eq 16)
        {
            Set-Service -Name SPSearchHostController -StartupType Disabled
            Stop-Service SPSearchHostController
        }

        switch ($using:Version)
        {
            14 {Set-Service -Name OSearch14 -StartupType Disabled; Stop-Service OSearch14 }
            15 {Set-Service -Name OSearch15 -StartupType Disabled; Stop-Service OSearch15 }
            16 {Set-Service -Name OSearch16 -StartupType Disabled; Stop-Service OSearch16 }
        }
    }
    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -ScriptBlock $scriptBlock -Session $session
    Remove-PSSession -Session $session
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
        $Pause
    )

    $scriptBlock = {
        Add-PSSnapin Microsoft.SharePoint.PowerShell -EA 0

        foreach($ssa in Get-SPEnterpriseSearchServiceApplication)
        {
            if($Pause)
            {
                $ssa.Resume()
                [int]$i = 0

                while($ssa.IsPaused() -eq 0)
                {
                    Sleep 10
                    ++$i

                    if(i -gt 24)
                    {
                        #timeout
                        break
                    }
                }
            }
        }

        switch ($Version)
        {
            14 {Set-Service -Name OSearch14 -StartupType Manual; Start-Service OSearch14 }
            15 {Set-Service -Name OSearch15 -StartupType Manual; Start-Service OSearch15 }
            16 {Set-Service -Name OSearch16 -StartupType Manual; Start-Service OSearch16 }
        }

        if($Version -eq 15 -or $Version -eq 16)
        {
            Set-Service -Name SPSearchHostController -StartupType Automatic
            Start-Service SPSearchHostController
        }
    }

    Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock
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
        $Patch
    )

    $scriptBlock = {
        param([string]
            [Parameter(Mandatory=$true)]
            $Patch
            )
        $p = Start-Process $Patch -ArgumentList '/quiet /norestart' -Wait -PassThru -NoNewWindow

        if(!($p.ExitCode -eq 0) -and !($p.ExitCode -eq 3010) -and !($p.ExitCode -eq 17022)){
            throw [System.Configuration.Install.InstallException] "The patch failed to install. ExitCode: $($p.ExitCode)" 
        }

        if(($p.ExitCode -eq 3010) -or ($p.ExitCode -eq 17022))
        {
            $restart = $true
        }
    }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    $restart = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Patch
    Remove-PSSession $session

    if($restart)
    {
        if($isCacheHost)
        {
            Update-RmStopDistributedCache $ServerName
        }

        Write-Host "-Restarting $ServerName"
        Restart-Computer -Force -ComputerName $ServerName -For WinRM -Wait

        if($isCacheHost)
        {
            Update-RmStartDistributedCache $ServerName
        }
    }
}

function Invoke-RmConfigWizard
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    #$session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    $scriptBlock = { $p = Start-Process $confWizard -Wait -PassThru -NoNewWindow }
    #what are $p return codes?
    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
}

function Invoke-RmSPContentDatabaseUpgrade
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    $scriptBlock = {
        Add-PSSnapin Microsoft.SharePoint.PowerShell
        
        foreach($db in Get-SPContentDatabase)
        {
            Upgrade-SPContentDatabase $db
        }
    }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
}

function Update-RmStopDistributedCache
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    #pulled from TN

    $scriptBlock = {
        $startTime = Get-Date
        $currentTime = $startTime
        $elapsedTime = $currentTime - $startTime
        $timeOut = 900

        try
        {
            Add-PSSnapin Microsoft.SharePoint.PowerShell
            Use-CacheCluster
            #Get-AFCacheClusterHealth
            $computer = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
            Write-Host "Shutting down distributed cache host."

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

            Write-Host "Stopping distributed cache host was successful. Updating Service status in SharePoint."
            Stop-SPDistributedCacheServiceInstance
            Write-Host "To start service, please use Central Administration site."
        }
        catch [System.Exception]
        {
            Write-Host 'Unable to stop cache host within 15 minutes.'
        }
    }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
}

function Update-RmStartDistributedCache
{
    param
    (
        [string]
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    #pulled from TN

    $scriptBlock = {
        Add-PSSnapin Microsoft.SharePoint.PowerShell -EA 0
            $si = Get-SPServiceInstance | ?{$_.TypeName -match 'Distributed'}
            $si.Provision()
        }

    $session = New-PSSession -ComputerName $ServerName -Authentication Credssp -Credential $cred
    Invoke-Command -Session $session -ScriptBlock $scriptBlock
    Remove-PSSession $session
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
        [Parameter(Mandatory=$true)]
        $PatchToApply,
        [string[]]
        [Parameter(Mandatory=$false)]
        $ServerOrder,
        [string[]]
        [Parameter(Mandatory=$false)]
        $DistCacheServers,
        [string[]]
        [Parameter(Mandatory=$false)]
        $FrontEnds,
        [string[]]
        [Parameter(Mandatory=$false)]
        $Applications,
        [string[]]
        [Parameter(Mandatory=$false)]
        $Search,
        [PSCredential]
        [Parameter(Mandatory=$true)]
        $Credential
    )

    $Version = Get-RmFarmVersion
    $servers = Get-RmFarmServers

    if($Version -eq 16)
    {
        $dcs = $servers | ?{$_.Role -eq 'DistributedCache'} | Select Name
    }
    elseif($version -eq 15)
    {
        if (!([string]::IsNullOrEmpty($DistCacheServers)))
        {
            $dcs = $DistCacheServers
        }
    }

    foreach($server in $servers)
    {
        [bool]$isDcs

        if($dcs -eq $server)
        {
            $isDcs = $true
        }

        Stop-RmSPServices $server
        Invoke-RmPatch $server $isDcs
        Start-RmSPServices $server
        
        $isDcs = $false         
    }

    Invoke-RmSPContentDatabaseUpgrade $server[0]

    foreach($server in $servers)
    {
        Invoke-RmConfigWizard $server
    }
}
