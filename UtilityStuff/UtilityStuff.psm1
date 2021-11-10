<#
.SYNOPSIS
    Sends a WOL packet.
.DESCRIPTION
    Sends a Wake-On-LAN packet that wakes up the target machine if it's configured properly. Can't send WOL packets to other VLANs.
.EXAMPLE
    PS C:\> Send-WOLPacket -MACAddress 00:11:22:AA:BB:CC
    Sends a WOL packet to the given MAC address.
.INPUTS
    Takes a list of MAC addresses.
.OUTPUTS
.NOTES
#>
function global:Send-WOLPacket {
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        #[Alias("MAC", "MACAddress")]
        [string[]]$MACAddress
    )

    Begin {
        $MACAddressRegex = "([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})"

        [scriptblock]$jobBlock = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )

            [Byte[]]$macBytes = $metaD.MAC -split "[:-]" | ForEach-Object -Process { [Byte]"0x$_" }
            [Byte[]]$WOLPacket = (, 0xFF * 6) + ($macBytes * 16)

            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Connect([System.Net.IPAddress]::Broadcast, 7)
            $udpClient.Send($WOLPacket, $WOLPacket.Length) | Out-Null
            $udpClient.Close()
            $udpClient.Dispose()
        }
    }
    Process {
        foreach ($mac in $MACAddress) {
            if ($mac -notmatch $MACAddressRegex) {
                Write-Error -Message "The specified MAC address is not valid." -Category InvalidArgument -RecommendedAction "Make sure you provide the right MAC address (AB:CD:EF:12:34:56)"
                continue
            }
            Write-Verbose "MAC Address: $mac"
            $metadata = New-Object psobject -Property @{
                MAC = $MAC
            }
            Invoke-Command $jobBlock -ArgumentList $metadata -Verbose
        }
    }
    End {

    }
}

function global:Set-AUSettings {
    
    <#
        .SYNOPSIS
        Changes the Auto Update settings on a specified computer.
        
        .EXAMPLE
        Set-AUSettings -ComputerName computerName -NoAutoUpdate 1 -AUOptions 1
        
        .DESCRIPTION
        Sets the settings corresponding for the windows updates to the specified values.

        Possible NoAutoUpdate:
        0 - AutoUpdates are Enabled
        1 - AutoUpdates are Disabled
        
        Possible AUOptions:
        0 - Enable auto updates
        1 - Disable auto updates
        2 - Notify before download
        3 - Automatically download and notify of install
        4 - Automatically download and schedule installation
        5 - Automatic updete is required and users can config it

        .INPUTS
        Takes a list of computers and the list of the settings that are needed to be changed.

        .OUTPUTS
        Returns result code.
    #>

    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 1)]
        [int]$NoAutoUpdate, #1 disables AU
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 4)]
        [int]$AUOptions, #1 disables au
        [ValidateRange(0, 7)]
        [int]$ScheduledInstallDay = 7, #0 - right after dling
        [ValidateRange(0, 23)]
        [int]$ScheduledInstallTime = 23, #24h format for the updates
        [switch]$AsJob
    )

    Begin {
        [scriptblock]$AUsb = {
            param(
                [string]$ComputerName,
                [int]$NoAutoUpdate,
                [int]$AUOptions,
                [int]$ScheduledInstallDay,
                [int]$ScheduledInstallTime
            )

            $session = New-PSSession -ComputerName $ComputerName -ErrorVariable sessionError
            if ($sessionError) {
                Write-Host "Error establishing the connection to the specified PC. $ComputerName" -ForegroundColor Red
                continue 
            }

            Invoke-Command -Session $session -ScriptBlock { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value $using:NoAutoUpdate -Force }
            Invoke-Command -Session $session -ScriptBlock { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value $using:AUOptions -Force }
            Invoke-Command -Session $session -ScriptBlock { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallDay -Value $using:ScheduledInstallDay -Force }
            Invoke-Command -Session $session -ScriptBlock { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallTime -Value $using:ScheduledInstallTime -Force }

            $session | Remove-PSSession
        }
    }
    Process {
        foreach ($pc in $ComputerName) {
            if ($AsJob) {
                Start-Job -ScriptBlock $AUsb -ArgumentList $pc, $NoAutoUpdate, $AUOptions, $ScheduledInstallDay, $ScheduledInstallTime
            }
            else {
                Invoke-Command -ScriptBlock $AUsb -ArgumentList $pc, $NoAutoUpdate, $AUOptions, $ScheduledInstallDay, $ScheduledInstallTime
            }
        }
    }
    End {
        
    }
}

function global:Add-SharedPrinter {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$PrinterName,
        [string[]]$ComputerName,
        #[Parameter(Mandatory = $true)]
        #[string]$DriverPath,
        #[string]$Name,
        #[Parameter(Mandatory = $true)]
        #[ValidateSet("RunDll32", "CimInstance")]
        #[string]$InstallMethod,
        [switch]$SetAsDefault,
        [switch]$AsJob
    )

    Begin {
        [scriptblock]$printerViaRunDLL = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )
            $session = New-PSSession -ComputerName $metaD.ComputerName -ErrorVariable sessionError
            if ($sessionError) {
                continue
            }

            if ($metaD.Default) {
                Invoke-Command -Session $session -ScriptBlock { Rundll32 printui.dll PrintUIEntry /ga /n$($args[0]) /z /y } -ArgumentList $metaD.PrinterName
            }
            else {
                Invoke-Command -Session $session -ScriptBlock { Rundll32 printui.dll PrintUIEntry /ga /n$($args[0]) /z } -ArgumentList $metaD.PrinterName
            }

            $session | Remove-PSSession
        }
    }
    Process {
        foreach ($pc in $ComputerName) {
            foreach ($printer in $PrinterName) {
                $metadata = New-Object psobject -Property @{
                    ComputerName = $pc
                    PrinterName  = $printer
                    DriverPath   = $DriverPath
                    Name         = $Name
                    Default      = $SetAsDefault
                }

                if ($AsJob) {
                    Start-Job -ScriptBlock $printerViaRunDLL -ArgumentList $metadata 
                }
                else {
                    Invoke-Command -ScriptBlock $printerViaRunDLL -ArgumentList $metadata
                }
            }
        }
    }
    End {
        
    }
}

function global:Set-IPAddress {
    #need to set the static IP address first and then specify the gateway address, otherwise the gateway gets erased
    #also, it's not needed to renew the ciminstance after setting the static IP (for some weird reason)
    [cmdletbinding(DefaultParameterSetName = "Normal")]
    param(
        [Parameter(ParameterSetName = "Normal", ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = "Reset")]
        [Parameter(ParameterSetName = "DHCP")]
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(ParameterSetName = "Normal")]
        [Parameter(ParameterSetName = "Reset")]
        [string]$IPAddress,
        [Parameter(ParameterSetName = "Normal")]
        [Parameter(ParameterSetName = "Reset")]
        #[ValidateSet("10.139.125.110", "10.139.125.7")]
        [string]$DefaultGateway = "10.139.126.129",
        [switch]$AsJob,
        [Parameter(ParameterSetName = "DHCP")]
        [switch]$EnableDHCP,
        [Parameter(ParameterSetName = "Reset")]
        [switch]$ForceReset
    )
    Begin {
        [scriptblock]$staticSB = {
            param(
                [string]$compName,
                [string]$ip,
                [string]$gateway,
                [switch]$reset = $false
            )
            $paddingLength = 50

            $networkAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $compName -Filter "IPEnabled = $true" -ErrorVariable cimInstanceError
            if ($cimInstanceError) {
                Write-Host "Couldn't retreive the specified CimInstance object." -ForegroundColor Red
                continue
            }
            if ($reset) {
                Write-Host "resetting the network adapter" -ForegroundColor Cyan
                $networkAdapter | Invoke-CimMethod -MethodName EnableDHCP -WarningAction SilentlyContinue | Out-Null
                #need to flush dns in order for your computer to be able to access the target computer using the new address
                ipconfig.exe /flushdns

                Start-Sleep -Seconds 20
                $networkAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $compName -Filter "IPEnabled = $true"
            }
            Write-Information "Current IP of $compName - $($networkAdapter.IPAddress)"
            
            Write-Host "Setting the DNS servers".PadRight($paddingLength, '.') -NoNewline -ForegroundColor Cyan
            $networkAdapter | Invoke-CimMethod -MethodName SetDNSServerSearchOrder -Arguments @{DNSServerSearchOrder = @("10.139.127.130", "10.139.206.16") }
            Write-Host "Done." -ForegroundColor Green
            Write-Host "Setting the IP address to `"$ip`"".PadRight($paddingLength, '.') -NoNewline -ForegroundColor Cyan
            $networkAdapter | Invoke-CimMethod -MethodName EnableStatic -Arguments @{IPAddress = @($ip); SubnetMask = @("255.255.255.128") } -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Write-Host "Done." -ForegroundColor Green
            
            ipconfig.exe /flushdns

            Write-Host "Setting the gateway to `"$gateway`"".PadRight($paddingLength, '.') -NoNewline -ForegroundColor Cyan
            $networkAdapter | Invoke-CimMethod -MethodName SetGateways -Arguments @{DefaultIPGateway = @($gateway) }
            Write-Host "Done." -ForegroundColor Green

            #$gatewayResult.ReturnValue
            #$dnsResult.ReturnValue
            #$ipResult.ReturnValue
        }

        [scriptblock]$dhcpSB = {
            param(
                [string]$compName
            )

            $networkAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $compName -Filter "IPEnabled = $true" -ErrorVariable cimInstanceError
            if ($cimInstanceError) {
                Write-Host "Couldn't retreive the specified CimInstance object." -ForegroundColor Red
                continue
            }
            $networkAdapter | Invoke-CimMethod -MethodName EnableDHCP -WarningAction Continue -ErrorAction Continue | Out-Null
            
            ipconfig.exe /flushdns
        }
    }
    Process {
        Write-Information "$ComputerName : $IPAddress : $DefaultGateway"
        if ($AsJob) {
            if ($EnableDHCP) {
                Start-Job -ScriptBlock $dhcpSB -ArgumentList $ComputerName
            }
            else {
                Start-Job -ScriptBlock $staticSB -ArgumentList $ComputerName, $IPAddress, $DefaultGateway, $ForceReset
            }
        }
        else {
            if ($EnableDHCP) {
                Invoke-Command -ScriptBlock $dhcpSB -ArgumentList $ComputerName
            }
            else {
                Invoke-Command -ScriptBlock $staticSB -ArgumentList $ComputerName, $IPAddress, $DefaultGateway, $ForceReset
            }
        }
    }
    End {

    }
}

function global:Get-PerformanceStatistic {
    param(
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $true)]
        [int]$Seconds = 300,
        [int]$MillisecondsDelay = 2000,
        [switch]$AsJob
    )

    Begin {
        [scriptblock]$performanceSB = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )
            $session = New-PSSession -ComputerName $metaD.ComputerName
            #no session? finish the execution
            $startTime = Get-Date

            $initialProcesses = Invoke-Command -Session $session -ScriptBlock { Get-Process }
            $proc = Invoke-Command -Session $session -ScriptBlock { Get-CimInstance -ClassName win32_processor }
            $ram = Invoke-Command -Session $session -ScriptBlock { Get-CimInstance -ClassName win32_operatingsystem }
            $processesList = New-Object System.Collections.Generic.List[psobject]

            $avgPerformance = [PSCustomObject]@{
                AvgCPUUsage    = $proc.LoadPercentage;
                #AvgFreeRAM = [Math]::Round(($ram.FreePhysicalMemory / $ram.TotalVisibleMemorySize) * 100, 2);
                AvgRAMUsage    = 100 - [Math]::Round(($ram.FreePhysicalMemory / $ram.TotalVisibleMemorySize) * 100, 2);
                'TotalRAM, GB' = [Math]::Round($ram.TotalVisibleMemorySize / 1mb); #weird stuff, the initial value is in kilobytes instead of bytes
            }

            foreach ($proc in $initialProcesses) {
                $processInfo = New-Object psobject -Property @{
                    ProcessName  = $proc.ProcessName;
                    ID           = $proc.ID;
                    WorkingSet64 = $proc.WorkingSet64;
                    CPUUsage     = [Math]::Round($proc.TotalProcessorTime.TotalSeconds, 2);
                    Description  = $proc.Description;
                }

                $processesList.Add($processInfo)
            }

            while (((Get-Date) - $startTime).TotalSeconds -lt $metaD.TimeSpan) {
                Start-Sleep -Milliseconds $metaD.Delay

                $processes = Invoke-Command -Session $session -ScriptBlock { Get-Process | Select-Object ID, WorkingSet64, TotalProcessorTime, Description, ProcessName } -ErrorVariable connectionError
                $proc = Invoke-Command -Session $session -ScriptBlock { Get-CimInstance -ClassName win32_processor } -ErrorVariable connectionError
                $ram = Invoke-Command -Session $session -ScriptBlock { Get-CimInstance -ClassName win32_operatingsystem } -ErrorVariable connectionError

                if ($connectionError) {
                    continue
                }
                #can't connect anymore? finish the execution of the script and return the existing values

                $avgPerformance.AvgCPUUsage = [Math]::Round(($avgPerformance.AvgCPUUsage + $proc.LoadPercentage) / 2, 2)
                #$avgPerformance.AvgFreeRAM = [Math]::Round(($avgPerformance.AvgFreeRAM + ($ram.FreePhysicalMemory / $ram.TotalVisibleMemorySize) * 100) / 2, 2)
                $avgPerformance.AvgRAMUsage = 100 - [Math]::Round(((100 - $avgPerformance.AvgRAMUsage + $ram.FreePhysicalMemory / $ram.TotalVisibleMemorySize * 100)) / 2, 2)

                foreach ($proc in $processes) {
                    $reqProcess = $processesList | Where-Object { $_.ID -eq $proc.ID }
                    if ($null -ne $reqProcess) {
                        $reqProcess.WorkingSet64 = ($reqProcess.WorkingSet64 + $proc.WorkingSet64) / 2
                        $reqProcess.CPUUsage = [Math]::Round($proc.TotalProcessorTime.TotalSeconds, 2);
                    }
                    else {
                        $processInfo = New-Object psobject -Property @{
                            ProcessName  = $proc.ProcessName;
                            ID           = $proc.ID;
                            WorkingSet64 = $proc.WorkingSet64;
                            CPUUsage     = [Math]::Round($proc.TotalProcessorTime.TotalSeconds, 2);
                            Description  = $proc.Description;
                        }

                        $processesList.Add($processInfo)
                    }
                }
            }
            #don't format the values until the very end
            #at the end go through all the items in the list and format it using "".ToString("F") or something like that
            <#foreach($proc in $processesList){
                $proc.WorkingSet64 = [Math]::Round($proc.WorkingSet64 / 1mb)
                $proc.CPUUsage = [Math]::Round($proc.CPUUsage)
            }#>

            return $avgPerformance
            #return ($processesList | Select-Object ID, ProcessName, CPUUsage, WorkingSet64 | Format-Table)
        }
    }
    Process {
        foreach ($pc in $ComputerName) {
            $metadata = New-Object psobject -Property @{
                ComputerName = $pc;
                TimeSpan     = $Seconds;
                Delay        = $MillisecondsDelay;
            }

            if ($AsJob) {
                Start-Job -ScriptBlock $performanceSB -ArgumentList $metadata -ErrorAction SilentlyContinue
            }
            else {
                Invoke-Command -ScriptBlock $performanceSB -ArgumentList $metadata -ErrorAction SilentlyContinue
            }
        }
    }
    End {
        
    }
}

<#
.SYNOPSIS
    Formats WinEvents into a more readable fashion.
.DESCRIPTION
    
.EXAMPLE

.INPUTS
    Takes a list of event entries from Get-WinEvent cmdlet.
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
function global:Format-ProcessEvents {
    #pass a Get-WinEvent entries to this cmdlet
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$EventLogEntries
    )

    Begin {
        $scriptblock = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )
            $eventEntries = $metaD.events | Where-Object { $_.ID -eq 4688 -or $_.ID -eq 4689 }

            $eventEntries | ForEach-Object -Begin { $briefEventsList = @() } -Process {
                $processFullName = $(($_.Message -split "`r`n" | Select-String "Имя.*процесса").Line.Split(':', 2)[1].Trim())
                $briefEventObject = New-Object pscustomobject -Property @{
                    PSTypeName       = 'windowsEventLogProcessObject'
                    TimeCreated      = $_.TimeCreated
                    Action           = $(if ($_.ID -eq 4688) { "Create" } elseif ($_.ID -eq 4689) { "Terminate" } else { "???" })
                    AccountName      = $(($_.Message -split "`r`n" | Select-String "Имя учетной записи").Line.split(':')[1].Trim())
                    ProcessName      = $processFullName.Substring($processFullName.LastIndexOf('\') + 1)
                    ProcessFullPath  = $processFullName
                    FullEventMessage = $_.Message
                }

                $briefEventsList += $briefEventObject
            }
            return $briefEventsList
        }
    }
    Process {
        $metadata = New-Object psobject -Property @{
            events = $EventLogEntries
        }
        Invoke-Command -ScriptBlock $scriptblock -ArgumentList $metadata -Verbose
    }
    End {
        
    }
}

<#
.SYNOPSIS
    Deploys an .msu file (aka msupdate) to the given pc.
.DESCRIPTION
    Copies an msu file, unzips it, and then installs the contents on a remote computer using built-in tools wusa.exe and dism.exe
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
function global:Install-MsuPackage {
    PARAM(
        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $True, HelpMessage = "Computers list.")]
        [Alias("PcName", "Computer")]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position = 0, HelpMessage = "Msu package path.")]
        [ValidateNotNullOrEmpty()]
        [string]$PackagePath,
        [switch]$Log,
        [switch]$AsJob
    )

    Begin {
        [scriptblock]$msuSB = {
            param(
                [string]$ComputerName,
                [string]$PackagePath,
                [switch]$Log
            )
            $cabRegEx = "(Windows.*KB\d*.*\.cab)"
            $packageName = $PackagePath.Substring($PackagePath.LastIndexOf('\') + 1)
            $serviceFolder = "C:\ServiceFolder"

            $session = New-PSSession -ComputerName $ComputerName -ErrorVariable sessionError
            if ($sessionError) {
                Write-Host "An Error occurred during establishing PS session." -ForegroundColor Red
                continue
            }
            $packageName = (Get-Item $PackagePath).Name
            Copy-Item -Path $PackagePath -Destination \\$ComputerName\c$\ServiceFolder
            
            Invoke-Command -Session $session -ScriptBlock { Start-Process wusa.exe -ArgumentList "$($args[0])\$($args[1]) /extract:$($args[0])\MSUpdate\" -Wait } -ArgumentList $serviceFolder, $packageName

            Invoke-Command -Session $session -ScriptBlock {
                $cabFiles = Get-ChildItem "$($args[0])\MSUpdate" | Where-Object { ($_.Name -match $args[1]) -and ($_.Name -notmatch "log") }
                foreach ($cab in $cabFiles) {
                    Write-Verbose "cab file: $($cab.FullName)"
                    if ($args[2]) {
                        Start-Process dism.exe -ArgumentList "/online /add-package /PackagePath:$($cab.FullName) /quiet /norestart /logpath:$($cab.FullName).log /loglevel:2" -Wait -PassThru
                    }
                    else {
                        Start-Process dism.exe -ArgumentList "/online /add-package /PackagePath:$($cab.FullName) /quiet /norestart" -Wait -PassThru
                    }
                }
                $cabFiles | Remove-Item -Force
            } -ArgumentList $serviceFolder, $cabRegEx, $Log

            $session | Remove-PSSession
        }
    }
    Process {
        foreach ($pc in $ComputerName) {
            if ($AsJob) {
                Start-Job -ScriptBlock $msuSB -ArgumentList $ComputerName, $PackagePath, $Log
            }
            else {
                Invoke-Command -ScriptBlock $msuSB -ArgumentList $ComputerName, $PackagePath, $Log
            }
        }
    }
    End {
        
    }
}

function global:Set-ScreenSaverTimer {
    [CmdletBinding(
        DefaultParameterSetName = "ComputerName")]
    PARAM(
        [Parameter(Position = 0, HelpMessage = "List of computers.", ValueFromPipelineByPropertyName = $True)]
        [Alias("PCName", "computer", "pc", "comp")]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position = 1, HelpMessage = "Time in minutes before screen goes black.")]
        [int]$Timer,
        [switch]$PassAfterTimer,
        [switch]$Win10
    )
    Begin {}
    Process {
        <#win 10 keys for screen saver are located in
    HKCU:\Control Panel\Desktop
    Keys:
    ScreenSaveActive
    ScreenSaverIsSecure
    ScreenSaveTimeOut
    #>
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $paths = Get-ChildItem -Path Registry::\Hkey_Users | 
            Where-Object { $_.name -notmatch "class" } | 
            Where-Object { $_.name -match "s-1-5-21" }
            foreach ($path in $paths) {
                Write-Verbose "Checking the branch at $path"
                if (-not (Test-Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop")) {
                    Write-Verbose "The needed branch doesn't exist. Creating it..."
                    New-Item -Path "Registry::\$path\software\policies\microsoft\windows" -Name "Control Panel" -ItemType String -ErrorAction SilentlyContinue
                    New-Item -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel" -Name "Desktop" -ItemType String -ErrorAction SilentlyContinue
                }
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose

                if ($PassAfterTimer) {
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 1 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                }
                else {
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 0 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                }
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -Value $($Timer * 60) #Время бездействия до погашения экрана в секундах.
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -Value 1    #Погашение экрана. 1 - включено.
            }
            cmd /c powercfg -change -monitor-timeout-ac $Timer #В минутах. Почему-то.
            cmd /c powercfg -change -standby-timeout-ac 0 #Отключает время для сна.
            Write-Verbose "Done. Timer has been set to $Timer minutes."
        }
        else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $paths = Get-ChildItem -Path Registry::\Hkey_Users | 
                Where-Object { $_.name -notmatch "class" } | 
                Where-Object { $_.name -match "s-1-5-21" }
                foreach ($path in $paths) {
                    Write-Verbose "Checking the branch at $path"
                    if (-not (Test-Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop")) {
                        Write-Verbose "The needed branch doesn't exist. Creating it..."
                        New-Item -Path "Registry::\$path\software\policies\microsoft\windows" -Name "Control Panel" -ItemType String -ErrorAction SilentlyContinue
                        New-Item -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel" -Name "Desktop" -ItemType String -ErrorAction SilentlyContinue
                    }
                    New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose
                    New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose
                    New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -PropertyType string -ErrorAction SilentlyContinue | Write-Verbose

                    if ($args[1]) {
                        Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 1 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                    }
                    else {
                        Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 0 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                    }
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -Value $($args[0] * 60) #Время бездействия до погашения экрана в секундах.
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -Value 1    #Погашение экрана. 1 - включено.
                }
                cmd /c powercfg -change -monitor-timeout-ac $args[0] #В минутах. Почему-то.
                cmd /c powercfg -change -standby-timeout-ac 0 #Отключает время для сна.
            } -ArgumentList $Timer, $PassAfterTimer
            Write-Verbose "Done. Timer has been set to $Timer minutes."
        }
    }
    End {}
}

<#
    .SYNOPSIS
        Sets a process' priority
    .EXAMPLE

    .EXAMPLE

    .EXAMPLE

    .DESCRIPTION

    .INPUTS

    .OUTPUTS
    #>
function Set-ProcessPriority {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $true)]
        [string]$ProcessName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Low", "BelowNormal", "Normal", "AboveNormal", "High", "Realtime")]
        [string]$PriorityLevel,
        [switch]$AsJob
    )
    Begin {
        [hashtable]$priorities = @{
            "Low"         = 64;
            "BelowNormal" = 16384;
            "Normal"      = 32;
            "AboveNormal" = 32768;
            "High"        = 128;
            "Realtime"    = 256
        }

        [scriptblock]$sb = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$meta
            )
            $cimsession = New-CimSession -ComputerName $meta.Target
            Get-CimInstance -CimSession $cimsession -ClassName Win32_Process | 
            Where-Object { $_.Name -match $meta.Process } | 
            ForEach-Object -Process { $_ | Invoke-CimMethod -MethodName SetPriority -Arguments @{Priority = $meta.Priority } }

            Remove-CimSession $cimsession
        }
    }
    Process {
        foreach ($pc in $ComputerName) {
            [psobject]$metaData = @{
                Target   = $pc;
                Priority = $priorities["$PriorityLevel"];
                Process  = $ProcessName;
            }
            if ($AsJob) {
                Start-Job -Name "SetPrio$($pc.Substring($pc.Length - 3))" -ScriptBlock $sb -ArgumentList $metaData
            }
            else {
                Invoke-Command -ScriptBlock $sb -ArgumentList $metaData
            }
        }
    }
    End {

    }
}

<#
.Synopsis
   Creates a .lnk item
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-Link {
    [CmdletBinding()]
    [OutputType(Type)]
    Param
    (
        #
        [Parameter(ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string[]]
        $ComputerName,

        #
        [string]
        $Path,

        # 
        [string]
        $TargetPath
    )

    Begin {
        
    }
    Process {
        foreach ($pc in $ComputerName) {
            

            $shell = New-Object -ComObject ("WScript.Shell")
            $shortcut = $shell.CreateShortcut($Path)
            $shortcut.TargetPath = $TargetPath
            $shortcut.Save()

            $shortcut = $null
            $shell = $null
        }
    }
    End {

    }
}