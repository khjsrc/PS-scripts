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
        if(Test-Connection $_ -Count 1 -ErrorAction SilentlyContinue)
        {
            $CompSystem = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $_ -ErrorAction SilentlyContinue
            $out = New-Object psobject -Property @{ComputerName = $_; OSType = ($CompSystem | Select-Object SystemType)}
            
            if($CompSystem -eq $null)
            {
                Write-Verbose "$_ isn't accessible by Get-CimInstance. Probably, the firewall is turned on."
                $out = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"}
            }

            return $out
        }
        else 
        {
            Write-Verbose "$_ isn't available for ping command. Check if PC is turned on or take a look at its firewall settings."
            $out = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"}
            return $out
        }
    }
    End{
        #$CustomProperties = @{BadList = "$bads"; GoodList = "$goods"}
    }
}