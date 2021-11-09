function global:Get-PowerShellVersion{
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = $env:COMPUTERNAME
    )
    Begin{
        
    }
    Process{
        foreach($pc in $ComputerName){
            $version = Invoke-Command -ComputerName $pc -ScriptBlock {$PSVersionTable.PSVersion} -ErrorAction SilentlyContinue -ErrorVariable error
            return $version
        }
    }
    End{
        
    }
}

#Displays PS version with some colors involved
function global:Show-PowerShellVersion{
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = $env:COMPUTERNAME
    )
    
    Begin{

    }
    Process{
        foreach($pc in $ComputerName){
            $version = Get-PowerShellVersion -ComputerName $pc
            Write-Host "$pc : " -NoNewline
            #Write-Verbose $version
            if($null -eq $version){
                Write-Host 
            }
            else{
                switch -Wildcard ($version){
                    "2.0*" {
                        Write-Host $version -ForegroundColor Red
                        break
                    }
                    "5.1*" {
                        Write-Host $version -ForegroundColor Green
                        break
                    }
                    default {
                        Write-Host $version -ForegroundColor Gray
                        break
                    }
                }
            }
            <#if($version -match "2.0"){
                Write-Host $version -ForegroundColor Red
            }
            elseif($version -match "5.1"){
                Write-Host $version -ForegroundColor Green
            }
            else {
                Write-Host $version -ForegroundColor Gray
            }#>
        }
    }
    End{
        
    }
}

function global:Get-InstalledAppInfo{
    <#
        .SYNOPSIS
        
        .EXAMPLE

        .EXAMPLE
        
        .EXAMPLE
        
        .DESCRIPTION

        .INPUTS
        Takes a list of computer names and the name of the app.

        .OUTPUTS
        Returns 
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = "TargetName", Position = 0)]
        [string[]]$ComputerName,
        [Parameter(ParameterSetName = "TargetSession", Position = 0)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "TargetName")]
        [Parameter(ParameterSetName = "TargetSession")]
        [string]$Name,
        [Parameter(Position = 2, ParameterSetName = "TargetName")]
        [Parameter(ParameterSetName = "TargetSession")]
        [switch]$ViaRegistry
        #IE Version is at HKLM:\Software\Microsoft\Internet Explorer\Version and svcVersion
        #Version 9.x is IE 10 and above
        #svcVersion is the real version but is not presented in the older IE installations
    )

    Begin{
        if($null -eq $ComputerName -or $ComputerName -eq [string]::Empty){
            $ComputerName = $env:COMPUTERNAME
        }
    }
    Process{
        foreach($pc in $ComputerName){
            [bool]$removePSSession = $false

            [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            [string]$RegPathWow6432Node = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

            if($null -eq $Session){
                $Session = New-PSSession -ComputerName $pc -ErrorAction Stop
                $removePSSession = $true
            }

            $AppInfo = $null

            if($ViaRegistry){
                $AppInfo = Invoke-Command -Session $Session -ScriptBlock {$l1 = (Get-ChildItem $using:RegPath <#| Get-ItemProperty | Where-Object {$_.DisplayName -match $using:Name}#>) 
                    $l2 = (Get-ChildItem $using:RegPathWow6432Node <#| Get-ItemProperty | Where-Object {$_.DisplayName -match $using:Name}#>)
                    $l1 + $l2 | Get-ItemProperty | Where-Object {$_.DisplayName -match $using:Name} | Sort-Object DisplayName
                }
            }
            else{
                $AppInfo = Invoke-Command -Session $Session -ScriptBlock {Get-Package | Where-Object {$_.name -match $using:Name}}
            }

            if($removePSSession){
                $session | Remove-PSSession
            }

            return $AppInfo
        }
    }
    End{
        
    }
}

function global:Uninstall-App{ #hueta
    <#
        .SYNOPSIS
        Uninstalls the selected application from the specified list of computers.
        
        .EXAMPLE
        Uninstall-App -ComputerName "Name1" -AppName "winrar" -UsingMsiexec
        Uninstalls WinRar from the specified computer.

        .EXAMPLE
        Uninstall-App -ComputerName "Name1" -AppName "winrar" -UsingMsiexec -AsJob
        Creates a job that does the job in background process.

        .DESCRIPTION
        Finds and uninstalls the first program that matches the specified AppName. At least, it tries to do so...

        .INPUTS
        Takes a list of computer names.

        .OUTPUTS
        Returns nothing or a job object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName,
        [Parameter(Mandatory = $true)]
        [Alias("App", "Program", "AppInfo")]
        [string]$AppName,
        [switch]$UsingMsiexec,
        [switch]$AsJob
    )
    
    Begin{
        [scriptblock]$jobScriptblock = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )
            $uninstallationResult

            $session = New-PSSession -ComputerName $metaD.ComputerName -ErrorVariable sessionError
            if($sessionError){
                Write-Host "$($metaD.ComputerName) - PSSession error. Finishing the execution of the script..." -ForegroundColor Red
                continue
            }

            while((Invoke-Command -Session $session -ScriptBlock {(Get-Process).Name} -ErrorAction Stop) -contains "msiexec"){
                Write-Verbose "$(get-date) -- Waiting for another msiexec process to stop..."
                Start-Sleep -Seconds 60
            }

            if($metaD.UsingMsiexec){
                $appInfo = Get-InstalledAppInfo -Session $session -Name $metaD.AppName -ViaRegistry | Select-Object -First 1
                if($null -eq $appInfo -or $appInfo.length -eq 0){
                    continue
                }
                Invoke-Command -Session $session -ScriptBlock {Start-Process msiexec.exe -ArgumentList "/x$($args[0].PSChildName) /quiet" -Wait} -ArgumentList $appInfo -WarningAction SilentlyContinue
            }
            else{
                $appInfo = Get-InstalledAppInfo -Session $session -Name $metaD.AppName
                if($null -eq $appInfo -or $appInfo.length -eq 0){
                    continue
                }
                $uninstallationResult = Invoke-Command -Session $session -ScriptBlock {Get-Package $($args[0].Name) | Uninstall-Package -Force} -ArgumentList $appInfo -WarningAction SilentlyContinue
            }

            $session | Remove-PSSession

            $result = [PSCustomObject]@{
                PSTypeName = 'UninstallationInfoObject'
                ComputerName = $metaD.ComputerName
                Name = $uninstallationResult.Name
                Version = $uninstallationResult.Version
                Status = $uninstallationResult.Status
            }

            return $result
        }
    }
    Process{
        foreach($pc in $ComputerName){
            $metadata = New-Object psobject -Property @{
                ComputerName = $pc;
                AppName = $AppName;
                UsingMsiexec = $UsingMsiexec;
            }

            if($AsJob){
                $job = Start-Job -Name "UnInst$pc" -ScriptBlock $jobScriptblock -InitializationScript {Import-Module InstallationStuff} -ArgumentList $metadata
                return $job
            }
            else{
                Invoke-Command -ScriptBlock $jobScriptblock -ArgumentList $metadata
                <#
                $session = New-PSSession -ComputerName $pc
                while((Invoke-Command -Session $session -ScriptBlock {(Get-Process).Name} -ErrorAction Stop) -contains "msiexec"){
                    Write-Verbose "$(get-date) -- Waiting for another msiexec process to stop..."
                    Start-Sleep -Seconds 60
                }
                if($UsingMsiexec){
                    $appInfo = Get-InstalledAppInfo -Session $session -Name $AppName -ViaRegistry | Select-Object -First 1
                    Invoke-Command -Session $session -ScriptBlock {Start-Process msiexec.exe -ArgumentList "/x$($($using:appInfo).PSChildName) /quiet" -Wait}
                }
                else{
                    $appInfo = Get-InstalledAppInfo -Session $session -Name $AppName
                    Write-Verbose "App name - $($appInfo.Name)"
                    Invoke-Command -Session $session -ScriptBlock {Uninstall-Package $($using:appInfo).Name -Force} -Verbose
                }
                $session | Remove-PSSession
                #>
            }
        }
    }
}

function global:Install-App{
    <#
        .SYNOPSIS
        Copies the specified MSI file to the specified computers and executes its installation.
        
        .EXAMPLE
        Install-App -ComputerName "PCName1" -InstallerPath \\serverName\sharedFolder\file.msi
        This command installs the application 'file.msi' on the computer named 'PCName1'
        .EXAMPLE
        Install-App -ComputerName "PCName1", "PCName2", "PCName3" -InstallerPath \\serverName\sharedFolder\file.msi -Notification -RemoveJunk -AsJob
        This command installs the application on multiple computers and whenever the installation finishes, sends the notification about that to the remote computer. Also it removes the installer when it's not needed anymore.
        .EXAMPLE
        "PCName1", "PCName2", "PCName3" | Install-App -InstallerPath \\serverName\sharedFolder\file.msi
        This one gets the list of computers from the pipeline and executes the installation on all the specified computers.
        
        .DESCRIPTION
        Installs the specified MSI file using built-in cmdlet Install-Package. Removes the MSI file from the temp folder and sends a notification to the user when the installation is finished, if needed.
        Custom file types to be added.

        .INPUTS
        Takes a list of computer names and the path to the MSI file.

        .OUTPUTS
        Returns nothing or the error if the installation has been executed incorrectly.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("PCName", "Computer", "TargetName")]
        [string[]]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [switch]$AsJob,
        [Parameter(HelpMessage = "Remove the installation file after the installation finishes.")]
        [switch]$Cleanup,
        [Parameter(HelpMessage = "Notify the user after the installation finishes.")]
        [switch]$Notification
        #[Parameter(HelpMessage = "Uses msiexec.exe to install the app.")]
        #[switch]$Legacy,
    )
    
    Begin{
        #$installerName = $FilePath.Substring($FilePath.LastIndexOf('\') + 1)

        [scriptblock]$sb = {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$metaD
            )

            $session = New-PSSession -ComputerName $metaD.ComputerName -ErrorVariable sessionError
            
            if($sessionError){
                Write-Host "$($metaD.ComputerName) - PSSession error. Finishing the execution of the script..." -ForegroundColor Red
                continue
            }

            $folderName = Invoke-Command -Session $session -ScriptBlock {New-TemporaryFile}
            Write-Verbose "folder name: $($folderName.BaseName)"
            Write-Verbose "unsupported file path: \\$($metaD.ComputerName)\admin$\temp\"
            $tempFolderUNC = New-Item -Path "\\$($metaD.ComputerName)\admin$\temp\" -Name $folderName.BaseName -ItemType Directory -Force
            Write-Verbose "Created directory $($tempFolderUNC.FullName)"

            $packageLocalPath = "C:\windows\Temp\" + $tempFolderUNC.Name + "\" + $metaD.PackageName
            Write-Verbose -Message "Copying from `"$($metaD.FilePath)`" to `"$($tempFolderUNC.FullName)`""
            Copy-Item $metaD.FilePath -Destination $tempFolderUNC.FullName -Force
            #is this the place?
            while((Invoke-Command -Session $session -ScriptBlock {(Get-Process).Name}) -contains "msiexec"){
                Write-Information "$(get-date) -- Waiting for another msiexec process to stop..."
                Start-Sleep -Seconds 60
            }
            $installationResult = Invoke-Command -Session $session -ScriptBlock {Install-Package $args[0] -Force} -ErrorVariable myErrorVar -ArgumentList $packageLocalPath

            #
                if($metaD.Notification){
                    Invoke-Command -Session $session -ScriptBlock {cmd /c msg * /time:1000 "Установка $($args[0]) завершена."} -ArgumentList $metaD.AppName
                }
                if($metaD.Cleanup){
                    Start-Sleep -Seconds 30
                    Remove-Item $tempFolderUNC -Force -Recurse
                }
            #

            $session | Remove-PSSession

            $result = [PSCustomObject]@{
                PSTypeName = 'InstallationInfoObject'
                ComputerName = $metaD.ComputerName
                Name = $installationResult.Name
                Version = $installationResult.Version
                Status = $installationResult.Status
            }

            return $result
        }
    }

    Process{
        foreach($pc in $ComputerName){
            $metaData = New-Object psobject -Property @{
                ComputerName = $pc;
                PackageName = $FilePath.Substring($FilePath.LastIndexOf('\') + 1);
                AppName = (Get-MSIFileInfo -Path $FilePath).ProductName;
                AppVersion = (Get-MSIFileInfo -Path $FilePath).ProductVersion;
                #ServiceFolderUNC = "\\$pc\" + $ServiceFolder.Replace(':', '$');
                FilePath = $FilePath;
                #PackageLocalPath = "C:\windows\temp\" + $FilePath.Substring($FilePath.LastIndexOf('\') + 1);
                #PackageEndPath = "\\$pc\" + $ServiceFolder.Replace(':', '$') + $FilePath.Substring($FilePath.LastIndexOf('\') + 1);
                Cleanup = $Cleanup;
                Notification = $Notification;
            }
            
            Write-Verbose $metaData

            if($AsJob){
                Write-Verbose "Copying and installing the package..."
                Start-Job -ScriptBlock $sb -ArgumentList $metaData -InitializationScript {Import-Module InstallationStuff} #$($metaData.ServiceFolderLocalPath), $($metaData.ServiceFolderUNC), $FilePath, $($metaData.PackageName), $ComputerName
            }
            else{
                Write-Verbose "Copying and installing the package..."
                Invoke-Command -ScriptBlock $sb -ArgumentList $metaData
                Write-Verbose "Finished with the installation."
            }
        }
    }
    End{

    }
}

function GetTempFolderName{
    param(
        [string]$FilePath
    )

    $hash = Get-FileHash -Path $FilePath -Algorithm MD5

    return "install-$($hash)"
}

function global:New-ServiceFolder{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName,
        [string]$Path = "C:\",
        [string]$FolderName = "ServiceFolder"
    )

    Begin{
        if($null -eq $ComputerName -or $ComputerName -eq [string]::Empty){
            $ComputerName = $env:COMPUTERNAME
        }
    }
    Process{
        foreach($pc in $ComputerName){
            $UNCpath = "\\$pc\" + ("$($Path.Replace(':', '$'))\$FolderName").Replace("\\", '\')

            if((Test-Path $UNCpath) -and (Get-Item $UNCpath -Force | Select-Object Attributes) -match "Directory"){
                Write-Information "The service folder already exists."
            }
            elseif(-not (Test-Path $UNCpath)){
                $f = New-Item -Path \\$pc\$($Path.Replace(':', '$')) -Name $FolderName -ItemType Directory | Set-ItemProperty -Name Attributes -Value "System, Hidden"
                return $f
            }
            elseif((Test-Path $UNCpath) -and (Get-Item $UNCpath -Force | Select-Object Attributes) -notmatch "Directory"){
                Remove-Item $UNCpath -Force
                $f = New-Item -Path \\$pc\$($Path.Replace(':', '$')) -Name $FolderName -ItemType Directory | Set-ItemProperty -Name Attributes -Value "System, Hidden"
                return $f
            }
            else{
                Write-Verbose "$ComputerName - Something weird happened during creation of the service folder."
                return 1
            }
        }
    }
    End{

    }
}

function global:Get-MSIFileInfo{
    <#
        .SYNOPSIS
        Gets information about the specified MSI file.
        
        .DESCRIPTION
        Creates a new custom PSObject with information on specified MSI file. Contains properties ProductCode, ProductVersion, ProductName, Manufacturer, ProductLanguage, FullVersion.

        .INPUTS
        Takes the patch to the MSI file.

        .OUTPUTS
        Returns custom PSObject.
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path
        #[parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
        #[ValidateSet("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")]
        #[string]$Property
    )

    Process {
        try {
            #read the needed property from MSI database
            $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
            $MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $WindowsInstaller, @($Path.FullName, 0))

            $props = @("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")
            $msiInfo = New-Object psobject

            foreach($prop in $props){
                #$Value
                #Write-Verbose $prop
                $Query = "SELECT Value FROM Property WHERE Property = '$prop'"
                $View = $MSIDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $MSIDatabase, ($Query))
                $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
                $Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
                if($null -ne $Record){
                    $Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $null, $Record, 1)
                }
                else{
                    $Value = $null
                }
                $msiInfo | Add-Member -MemberType NoteProperty -Name $prop -Value $Value
                $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)
            }
            #Commit database and close view
            $MSIDatabase.GetType().InvokeMember("Commit", "InvokeMethod", $null, $MSIDatabase, $null)
            #$View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)
            $MSIDatabase = $null
            $View = $null

            return $msiInfo
        }
        catch {
            Write-Warning -Message $_.Exception.Message
            break
        }
    }
    End {
        #Run garbage collection and release ComObject
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null
        [System.GC]::Collect()
    }
}