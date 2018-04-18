function global:Get-ComputerStatus{
[CmdletBinding(DefaultParameterSetName = "ComputerName")]
    PARAM(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, Position = 0)]
        [Alias("ComputerName", "PCName", "Server")]
        [string[]]$ComputerName,
        [string]$LogFilePath,
        [switch]$AsJob
    )

    Begin{
    }
    Process{
        $ping = (Test-Connection -ComputerName $_ -Quiet)
        if($ping)
        {
            $CompSystem = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $_ -ErrorAction SilentlyContinue
            $ComputerObject = New-Object psobject -Property @{ComputerName = $_; OSType = ($CompSystem | Select-Object SystemType); Online = $ping}
            
            if($CompSystem -eq $null)
            {
                Write-Verbose "$_ isn't accessible by Get-CimInstance. Probably, the firewall is turned on."
                $ComputerObject = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"; Online = $ping}
            }

            return $ComputerObject
        }
        else 
        {
            Write-Verbose "$_ isn't available for ping command. Check if PC is turned on or take a look at its firewall settings."
            $ComputerObject = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"; Online = $ping}
            return $ComputerObject
        }
    }
    End{
        #$CustomProperties = @{BadList = "$bads"; GoodList = "$goods"}
    }
}