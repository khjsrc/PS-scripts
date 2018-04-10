#get list of pcs that need an update
$pcList = Read-Host -Prompt "path to the file with PCs"
[regex]$appName = Read-Host -Prompt "app that needs the update (regular expression)" #intentionally don't want to avoid errors here, will do it in the future
$msiPath = Read-Host -Prompt "path to the program installer"

#Java requires some other shenanigans, so it's impossible to update it with this script
foreach($pc in $pcList){
    $msiFinalPath = "C:\ServiceFolder\" + $msiPath.Substring($msiPath.LastIndexOf('\') + 1)
    if(Test-Connection -ComputerName $pc -Count 1){
        $ieVersion = Get-ItemProperty -Name "HKLM:\SOFTWARE\microsoft\Internet Explorer" | Select-Object Version
        $uninstallString = Get-InstalledPrograms -ComputerName $pc | Where-Object {$_.displayname -match $appName} | Select-Object uninstallstring
        Copy-Item -Path $msiPath -Destination \\$pc\c$\ServiceFolder\
        Invoke-Command -ComputerName $pc -ScriptBlock {Start-Process msiexec.exe -ArgumentList "$($args[0]) /quiet" -Wait} -ArgumentList $uninstallString #delete the previous version of a program (find the string to pass as an argument via Get-InstalledPrograms cmdlet)
        Invoke-Command -ComputerName $pc -ScriptBlock {Start-Process msiexec.exe -ArgumentList "/package $($args[0]) /quiet" -Wait} -AsJob -ArgumentList $msiFinalPath
    }
}