#get list of pcs that needs an update
$pcList = Read-Host -Prompt "path to the file with PCs"
[regex]$appName = Read-Host -Prompt "app that needs the update (regular expression)" #intentionally don't want to avoid errors here, will do in the future
$msiPath = Read-Host -Prompt "path to the program installer"

foreach($pc in $pcList){
    $msiFinalPath = "C:\ServiceFolder\" + $msiPath.Substring($msiPath.LastIndexOf('\') + 1)
    if(Test-Connection -ComputerName $pc -Count 1){
        Copy-Item -Path $msiPath -Destination \\$pc\c$\ServiceFolder\
        Invoke-Command -ComputerName $pc -ScriptBlock {Start-Process msiexec.exe -ArgumentList $(args[0]) -Wait} -ArgumentList #delete the previous version of a program (find the string to pass as an argument via Get-InstalledPrograms cmdlet)
        Invoke-Command -ComputerName $pc -ScriptBlock {Start-Process msiexec.exe -ArgumentList "/package $(args[0]) /quiet" -Wait} -AsJob -ArgumentList $msiFinalPath
    }
}