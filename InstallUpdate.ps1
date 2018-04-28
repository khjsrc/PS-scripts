function global:Install-Update{
[CmdletBinding(DefaultParameterSetName = "PackageName")]
    PARAM(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, Position = 0)]
        [Alias("ComputerName", "PCName", "Server")]
        [string[]]$Targets,
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,
        [switch]$AsJob
    )

    # afaik, wusa.exe doesn't install *.msu packages remotely due to security settings or something like that, but it can be done via dism.exe using *.cab files from *.msu packages

    Begin{
        if($PackagePath -notmatch "(\**.msu)") {
            Write-Host "You should specify an *.msu file." -ForegroundColor Red
            return
        }
        $PackageName = $PackagePath.Substring($PackagePath.LastIndexOf('\') + 1)
    }
    
    Process{
        Write-Debug "$($_.ComputerName) $PackageName"
        Copy-Item $PackagePath -Destination ("\\" + $_.ComputerName + "\c$\ServiceFolder\") -Force

        if($AsJob){ # experimental shit, better not to use it until I test it
            Start-Job -ScriptBlock{
                $session = New-PSSession -ComputerName $_.ComputerName
                Invoke-Command -Session $session -ScriptBlock {Start-Process wusa.exe -ArgumentList "C:\ServiceFolder\$($args[0]) /extract:C:\ServiceFolder\updates\$($args[0])\"} -ArgumentList $PackageName
                $cabNames = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem "C:\ServiceFolder\updates\$($args[0])" | Where-Object {$_.Name -match "(.*\.cab)"} | Select-Object Name} -ArgumentList $PackageName 
                foreach($cabName in $cabNames){
                    Invoke-Command -Session $session -ScriptBlock {Start-Process dism.exe -ArgumentList "/online /add-package /PackagePath:C:\ServiceFolder\updates\$($args[0])\$($args[1])" -Wait -PassThru} -ArgumentList $PackageName, $cabNames
                }
            }
        }
        else
        {
            $session = New-PSSession -ComputerName $_.ComputerName
            # unpack
            Invoke-Command -Session $session -ScriptBlock {Start-Process wusa.exe -ArgumentList "C:\ServiceFolder\$($args[0]) /extract:C:\ServiceFolder\updates\$($args[0])\"} -ArgumentList $PackageName
            # install
            $cabNames = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem "C:\ServiceFolder\updates\$($args[0])" | Where-Object {$_.Name -match "(.*\.cab)"} | Select-Object Name} -ArgumentList $PackageName 
            # $cabNames = Get-ChildItem \\$_.ComputerName\c$\ServiceFolder\updates\ | Where-Object {$_.name -match ".cab"} | Select-Object name
            foreach($cabName in $cabNames){
                Invoke-Command -Session $session -ScriptBlock {Start-Process dism.exe -ArgumentList "/online /add-package /PackagePath:C:\ServiceFolder\updates\$($args[0])\$($args[1])" -Wait -PassThru} -ArgumentList $PackageName, $cabNames
            }
            # ...
            # profit
            # Invoke-Command -Session $session -ScriptBlock {wusa.exe C:\ServiceFolder\$($args[0]) /quiet /norestart} -ArgumentList $PackageName -Verbose -Debug
        }
        $session | Disconnect-PSSession | Remove-PSSession
    }

    End{

    }
}