#cmdlet Get-OnlinePCs(Path $path) {
$computers = Get-Content .\computerNames.txt
Clear-Content .\onlineComputers.txt
$i = 0

foreach($computer in $computers){
    if (Test-Connection -ComputerName $computer -Count 1 -ErrorAction SilentlyContinue){
        Write-Host "$computer is online."
        Add-Content -Value $computer -Path .\onlineComputers.txt
        $i++
    }
    else {
        Write-Host "$computer is not online."
    }
}

$date = (Get-Date).DateTime
Write-Host `n$date`nTotal computers: $i
Add-Content -Path .\compsMonitor.txt -Value "$date : $i computers have been pinged successfully."
#}