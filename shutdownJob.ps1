$adminCred = Get-Credential
Get-PSSession | ForEach-Object -Process {
    Invoke-Command -Session $_ -ScriptBlock {
        Get-ScheduledJob | Unregister-ScheduledJob
        $trigger = New-JobTrigger -At "22:00:00" -DaysOfWeek Friday -Weekly
        $option = New-ScheduledJobOption -RunElevated -HideInTaskScheduler -DoNotAllowDemandStart
        $scriptblock = {
            #clears temp files older than 14 days before shutting down the computer
            Get-ChildItem C:\Users\ |
            ForEach-Object -Process {Get-ChildItem "$($_.FullName)\AppData\Local\Temp" -File | 
            Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-14))} | 
            Remove-Item -Force -ErrorAction SilentlyContinue} 
            Stop-Computer -Force
        }
        Register-ScheduledJob -ScriptBlock $scriptblock -Name "WeeklyShutdown" -Trigger $trigger -ScheduledJobOption $option -Credential $args[0]
    } -ArgumentList $adminCred -AsJob
}