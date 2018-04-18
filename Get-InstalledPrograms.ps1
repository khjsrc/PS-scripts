function global:Get-InstalledPrograms{
    [CmdletBinding(
    DefaultParameterSetName = "ComputerName")]
    PARAM(
        [Parameter(Position = 0, HelpMessage = "Gets the list of installed programs on the specified computer.", ValueFromPipelineByPropertyName = $True)]
        [Alias("PCName")]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [switch]$All,
        [string[]]$ComputersListPath = '.\computerNames.txt'
    )

    #$programs = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -notmatch "microsoft"} | Select-Object displayname, displayversion | Format-Table -AutoSize
    Begin
    {
        [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        [string]$RegPathWow6432Node = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

        #Internet Explorer info is located in "HKLM:\Software\Microsoft\Internet Explorer". Property - Version (or svcVersion?)
    }
    Process
    {
        if($All){
            foreach($computer in (Get-Content $ComputersListPath))
            {
                $ComputerObject = New-Object psobject 
                $ComputerObject | Add-Member -MemberType NoteProperty -Name ComputerName -Value $computer
                if(Test-Connection $computer -Count 1)
                {
                    Write-Debug "Working with $computer"
                    if(Invoke-Command -ComputerName $computer -ScriptBlock {Test-Path "HKLM:\SOFTWARE\Wow6432Node"})
                    {
                        Write-Verbose "Working with $computer"
                        $winVer = (Get-WmiObject -Class win32_computersystem -ComputerName $computer | Select-Object SystemType)
                        $ComputerObject | Add-Member -MemberType NoteProperty -Name OSType -Value $winVer
                        Invoke-Command -ComputerName $computer -ScriptBlock {
                        Get-ItemProperty -Name $args[0] -Filter * | 
                        Where-Object {$_.displayname -ne '`n'} | 
                        Sort-Object -Property displayname} -Verbose -ArgumentList $RegPathWow6432Node
                        Write-Verbose "Done with $computer"
                    }
                    else
                    {
                        Write-Verbose "Working with $computer"
                        $winVer = (Get-WmiObject -Class win32_computersystem -ComputerName $computer | Select-Object SystemType)
                        $ComputerObject | Add-Member -MemberType NoteProperty -Name OSType -Value $winVer
                        Invoke-Command -ComputerName $computer -ScriptBlock {
                        Get-ItemProperty -Name $args[0] -Filter * | 
                        Where-Object {$_.displayname -ne '`n'} | 
                        Sort-Object -Property displayname} -Verbose -ArgumentList $RegPath
                        Write-Verbose "Done with $computer"
                    }
                }
            }
        }
        else
        {
            foreach($computer in $ComputerName)
            {
                if(Invoke-Command -ComputerName $computer -ScriptBlock {Test-Path "HKLM:\SOFTWARE\Wow6432Node"})
                {
                    Write-Verbose "Working with $computer"
                    $winVer = Get-WmiObject -Class win32_computersystem -ComputerName $computer
                    $winVer = $winVer.SystemType
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                    Get-ItemProperty $args[0] | 
                    Where-Object {$_.displayname -ne '`n'} | 
                    Sort-Object -Property displayname} -ArgumentList $RegPathWow6432Node #-ErrorAction SilentlyContinue | Out-File -FilePath ".\Computers software\$computer($winVer).txt"
                    Write-Verbose "Done with $computer"
                }
                else
                {
                    Write-Verbose "Working with $computer"
                    $winVer = Get-WmiObject -Class win32_computersystem -ComputerName $computer
                    $winVer = $winVer.SystemType
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                    Get-ItemProperty $args[0] | 
                    Where-Object {$_.displayname -ne '`n'} | 
                    Sort-Object -Property displayname} -ArgumentList $RegPath #-ErrorAction SilentlyContinue | Out-File -FilePath ".\Computers software\$computer($winVer).txt"
                    Write-Verbose "Done with $computer"
                }
            }
        }
    }
    End{} 
}
#Invoke-Command -ComputerName $computer -ScriptBlock {Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
#Where-Object {$_.Displayname -notmatch "office"} | 
#Where-Object {$_.displayname -ne '`n'} | 
#Sort-Object -Property displayname | 
#Select-Object displayname, displayversion | 
#Format-Table -AutoSize} >.\programsList.txt

#{
#    foreach($computer in $computers){
#        if (Test-Connection -ComputerName $computer -Count 1 -ErrorAction SilentlyContinue){
#            Write-Host "$computer is online."
#            Add-Content -Value $computer -Path .\onlineComputers.txt
#            $i++
#        }
#        else {
#            Write-Host "$computer is not online."
#        }
#    }
#
#    $date = (Get-Date).DateTime
#    Write-Host `n$date`nTotal computers: $i
#    Add-Content -Path .\compsMonitor.txt -Value "$date : $i computers out of " + $computers.Length + " have been pinged successfully."
#}


#uninstall an app: Invoke-Command i3925-w34000099 -ScriptBlock {Start-Process msiexec.exe -ArgumentList "/x{11557519-E84D-400B-8B59-1C645E96341E} /quiet" -wait}