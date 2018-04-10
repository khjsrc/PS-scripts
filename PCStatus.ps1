function global:Install-Update{
[CmdletBinding(DefaultParameterSetName = "PackageName")]
    PARAM(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, Position = 0)]
        [Alias("ComputerName", "PCName", "Server")]
        [string[]]$InstallTargets,
        [string]$PackageName,
        [Parameter(Mandatory = $true)]
        [string]$FullPackageName,
        [string]$ErrorsFileOutput,
        [switch]$AsJob
    )

    Begin
    {
        if($PackageName -eq $null)
        {
            $PackageName = $FullPackageName.Substring($FullPackageName.LastIndexOf('\') + 1)
        }
    }
    Process
    {
        if(Test-Connection $_ -Count 1 -ErrorAction SilentlyContinue)
        {
            $CompSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $_ -ErrorAction SilentlyContinue
            if(($CompSystem | Select-Object SystemType) -match "86")
            {
                Write-Verbose "$_ is x86"
                $out = New-Object psobject -Property @{ComputerName = $_; OSType = "x86"}
                return $out
            }
            elseif(($CompSystem | Select-Object SystemType) -match "64")
            {
                Write-Verbose "$_ is x64"
                $out = New-Object psobject -Property @{ComputerName = $_; OSType = "x64"}
                return $out
            }
            else
            {
                Write-Verbose "$_ isn't accessible by Get-WmiObject. Probably, the firewall is turned on."
                $out = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"}
                return $out
            }
        }
        else 
        {
            Write-Verbose "$_ isn't available for ping command. Check PC status or look at its firewall settings."
            $out = New-Object psobject -Property @{ComputerName = $_; OSType = "n/a"}
            return $out
        }
    }
    End
    {
        #region works for now
        #$CustomProperties = @{BadList = "$bads"; GoodList = "$goods"}
        #$out = New-Object PSObject #-Property @{Name = "BadList"; Expression = $i} @{Name = "GoodList"; Expression = "123"}
        #$out | Add-Member -MemberType NoteProperty -Name GoodList -Value $goods
        #$out | Add-Member -MemberType NoteProperty -Name BadList -Value $bads
        #return $out
        #endregion
    }
}