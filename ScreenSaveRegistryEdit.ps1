$response = Read-Host "Choose the option: `n1. All computers. `n2. Less than all.`nChoose one"
if($response -eq "1")
{
    ForEach ($computer in (Get-Content .\onlineComputers.txt))
    {
        Invoke-Command -ComputerName $computer -ScriptBlock {
            $paths = Get-ChildItem -Path Registry::\Hkey_Users | 
            Where-Object {$_.name -notmatch "class"} | 
            Where-Object {$_.name -match "s-1-5-21"}
            foreach($path in $paths)
            {
                Write-Host "Creating a new branch at $computer at $path"
                New-Item -Path "Registry::\$path\software\policies\microsoft\windows" -Name "Control Panel" -ItemType String -ErrorAction SilentlyContinue
                New-Item -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel" -Name "Desktop" -ItemType String -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -PropertyType string -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -PropertyType string -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -PropertyType string -ErrorAction SilentlyContinue

                Write-Host "Setting new values..."
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 0 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -Value 322 #Время бездействия до погашения экрана в секундах.
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -Value 1    #Погашение экрана. 1 - включено.
            }
            cmd /c powercfg -change -monitor-timeout-ac 5 #В минутах. Почему-то.
            cmd /c powercfg -change -standby-timeout-ac 0 #Отключает время для сна.
        } -AsJob
    }
}
elseif($response -eq "2")
{
    [Array]$computers = (Read-Host "Computer names separated with commas").Replace(' ', '').Split(',')
    $time = Read-Host "Time in minutes"
    [bool]$pass = if((Read-Host "Pass after wake-up(1 - yes, 0 - no)") -match "1") {$true} else {$false} 
    foreach($computer in $computers)
    {
        Invoke-Command -ComputerName $computer -ScriptBlock {
            $paths = Get-ChildItem -Path Registry::\Hkey_Users | 
            Where-Object {$_.name -notmatch "class"} | 
            Where-Object {$_.name -match "s-1-5-21"}
            foreach($path in $paths)
            {
                Write-Host "Creating a new branch at $computer at $path"
                New-Item -Path "Registry::\$path\software\policies\microsoft\windows" -Name "Control Panel" -ItemType String -ErrorAction SilentlyContinue
                New-Item -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel" -Name "Desktop" -ItemType String -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -PropertyType string -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -PropertyType string -ErrorAction SilentlyContinue
                New-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -PropertyType string -ErrorAction SilentlyContinue

                if($args[1])
                {
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 1 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                }
                else
                {
                    Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 0 #Пароль после погашения экрана. 1 - есть, 0 - нет.
                }
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -Value ($args[0]*60) #Время бездействия до погашения экрана в секундах.
                Set-ItemProperty -Path "Registry::\$path\software\policies\microsoft\windows\Control Panel\Desktop" -Name ScreenSaveActive -Value 1    #Погашение экрана. 1 - включено.
            }
            cmd /c powercfg -change -monitor-timeout-ac $args[0] #В минутах. Почему-то.
            cmd /c powercfg -change -standby-timeout-ac 0 #Отключает время для сна.
            Write-Host Done. Timer has been set to $args[0] minutes.
        } -ArgumentList $time, $pass
    }
}

#i3925-w34000113 индивидуально поставить выключение монитора через 10 минут.