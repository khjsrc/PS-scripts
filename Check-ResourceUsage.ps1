$table = @()
$table = for($i = 0; $i -le 120; $i++){
    $proc = Invoke-Command -ComputerName i3925-w04000399 -ScriptBlock {Get-WmiObject -Class win32_processor}
    $ram = Invoke-Command -ComputerName i3925-w04000399 -ScriptBlock {Get-WmiObject -Class win32_operatingsystem}

    #$proc = Get-CimInstance -ComputerName i3925-w04000399 -Class win32_processor
    #$ram = Get-CimInstance -ComputerName i3925-w04000399 -ClassName win32_operatingsystem

    $ram | Select-Object @{Name = "Time";Expression = {Get-Date}}, 
    @{Name = "CPU usage, %"; Expression = {$proc.LoadPercentage}},
    @{Name = "RAM usage, %"; Expression = {[Math]::Round(($ram.FreePhysicalMemory / $ram.TotalVisibleMemorySize) * 100, 2)}},
    @{Name = "Total RAM, GB"; Expression = {[Math]::Round($ram.TotalVisibleMemorySize / 1mb)}}
    #Out-File -FilePath '.\Desktop\temp\i3925-w04000195 monitor.txt' -Append
    #Write-Host $i
    Start-Sleep 5
}
$table | Format-Table -AutoSize | Out-File -FilePath '.\Desktop\temp\i3925-w04000399 monitor.txt' -Append