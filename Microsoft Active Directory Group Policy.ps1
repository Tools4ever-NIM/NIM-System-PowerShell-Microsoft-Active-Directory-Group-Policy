#
# Microsoft Active Directory Group Policy.ps1 - Microsoft Active Directory Group Policy
#
# Requirement
# Install-WindowsFeature -Name GPMC, RSAT-AD-PowerShell
#

$Log_MaskableKeys = @(
    'Password',
    "proxy_password"
)

$Global:PolicyObjects = [System.Collections.ArrayList]@()
$Global:Links = [System.Collections.ArrayList]@()
$Global:Permissions = [System.Collections.ArrayList]@()

$Properties = @{
    PolicyObject = @(
        @{ name = 'Id'; options = @('default', 'key') }    
        @{ name = 'DisplayName'; options = @('default') }    
        @{ name = 'DomainName'; options = @('default') }    
        @{ name = 'DC'; options = @('default') }  
        @{ name = 'Owner'; options = @('default') }    
        @{ name = 'GpoStatus'; options = @('default') }    
        @{ name = 'Description'; options = @('default') }
        @{ name = 'CreationTime'; options = @('default') }
        @{ name = 'ModificationTime'; options = @('default') }
        @{ name = 'UserVersion'; options = @('default') }
        @{ name = 'ComputerVersion'; options = @('default') }
        @{ name = 'WmiFilter'; options = @('default') }
    )
    Link         = @(
        @{ name = 'Id'; options = @('default', 'key') }    
        @{ name = 'PolicyId'; options = @('default') }    
        @{ name = 'SOMName'; options = @('default') }    
        @{ name = 'SOMPath'; options = @('default') }    
        @{ name = 'Enabled'; options = @('default') }    
        @{ name = 'NoOverride'; options = @('default') }    
    )
    Permission   = @(
        @{ name = 'PolicyId'; options = @('default') }    
        @{ name = 'ApplyTo'; options = @('default') }    
    )
}

#
# System functions
#
function Idm-SystemInfo {
    param (
        # Operations
        [switch] $Connection,
        [switch] $TestConnection,
        [switch] $Configuration,
        # Parameters
        [string] $ConnectionParams
    )

    Log info "-Connection=$Connection -TestConnection=$TestConnection -Configuration=$Configuration -ConnectionParams='$ConnectionParams'"

    if ($Connection) {
        @(
            @{
                name        = 'nr_of_sessions'
                type        = 'textbox'
                label       = 'Max. number of simultaneous sessions'
                description = ''
                value       = 1
            }
            @{
                name        = 'sessions_idle_timeout'
                type        = 'textbox'
                label       = 'Session cleanup idle time (minutes)'
                description = ''
                value       = 1
            }
        )
    }

    if ($TestConnection) {
        
    }

    if ($Configuration) {
        @()
    }

    Log info "Done"
}

function Idm-OnUnload {
}

#
# Object CRUD functions
#

function Idm-PolicyObjectsRead {
    param (
        # Mode
        [switch] $GetMeta,    
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams

    )
    $system_params = ConvertFrom-Json2 $SystemParams
    $function_params = ConvertFrom-Json2 $FunctionParams
    $Class = 'PolicyObject'
        
    if ($GetMeta) {
        Get-ClassMetaData -SystemParams $SystemParams -Class $Class
            
    }
    else {

        if (     $Global:PolicyObjects.count -lt 1 ) {   

            $forest = Get-ADForest
            $allDomains = $forest.Domains
                
            foreach ($domain in $allDomains) {
                Log info ("Processing domain: {0}" -f $domain)

                # Get domain controller for this domain
                $dc = (Get-ADDomainController -DomainName $domain -Discover -NextClosestSite).HostName[0]

                # Get all GPOs in this domain
                [void]$Global:PolicyObjects.AddRange( @() + (Get-GPO -All -Domain $domain -Server $dc | ForEach-Object {
                            $_ | Add-Member -NotePropertyName 'DC' -NotePropertyValue $dc -PassThru
                        }))
            }
        }
            
        $properties = ($Global:Properties.$Class).name
        $hash_table = [ordered]@{}

        foreach ($prop in $properties.GetEnumerator()) {
            $hash_table[$prop] = ""
        }

        foreach ($rowItem in $Global:PolicyObjects) {
            $row = New-Object -TypeName PSObject -Property $hash_table
            $row.DC = $dc

            foreach ($prop in $rowItem.PSObject.properties) {
                if (!$properties.contains($prop.Name)) { continue }
                        
                $row.($prop.Name) = $prop.Value                        
            }

            $row
        }
            
    }
}

function Idm-PolicyLinksRead {
    param (
        # Mode
        [switch] $GetMeta,    
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams

    )
    $system_params = ConvertFrom-Json2 $SystemParams
    $function_params = ConvertFrom-Json2 $FunctionParams
    $Class = 'Link'
        
    if ($GetMeta) {
        Get-ClassMetaData -SystemParams $SystemParams -Class $Class
            
    }
    else {

        if ( $Global:PolicyObjects.count -lt 1 ) { Idm-PolicyObjectsRead -SystemParams $SystemParams -FunctionParams $FunctionParams | Out-Null }

        # Run Get-GPOReport calls in parallel via a runspace pool (PS 5.1 compatible)
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
        $runspacePool.Open()

        $scriptBlock = {
            param($GpoId, $DomainName, $DC)
            @{ GpoId = $GpoId; ReportXml = (Get-GPOReport -Guid $GpoId -ReportType Xml -Domain $DomainName -Server $DC) }
        }

        $jobs = foreach ($gpo in $Global:PolicyObjects) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $runspacePool
            [void]$ps.AddScript($scriptBlock).AddParameter('GpoId', $gpo.Id).AddParameter('DomainName', $gpo.DomainName).AddParameter('DC', $gpo.DC)
            [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Gpo = $gpo }
        }

        foreach ($job in $jobs) {
            try {
                $result = $job.PS.EndInvoke($job.Handle)[0]
                [xml]$report = $result.ReportXml
                $gpo = $job.Gpo

                # --- Get GPO Links (OUs, Domain root, Sites) ---
                $report.GPO.LinksTo | ForEach-Object { $somKey = if ($_.SOMPath) { $_.SOMPath } elseif ($_.SOMName) { $_.SOMName } else { $null }; if ($somKey) { [void]$Global:Links.Add( @{ Id = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(("{0}.{1}" -f $gpo.Id, $somKey)) ); PolicyId = $gpo.Id; SOMName = $_.SOMName; SOMPath = $_.SOMPath; Enabled = $_.Enabled; NoOverride = $_.NoOverride }) } }

                # --- Get Security Filtering (who it applies to) ---
                $report.GPO.SecurityDescriptor.Permissions.TrusteePermissions |
                Where-Object { $_.Standard.GPOGroupedAccessEnum -eq 'Apply Group Policy' } |
                ForEach-Object { [void]$Global:Permissions.Add( @{ PolicyId = $gpo.Id; ApplyTo = $_.Trustee.Name.'#text' }) }
            }
            finally {
                $job.PS.Dispose()
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }
            
    $properties = ($Global:Properties.$Class).name

    foreach ($rowItem in $Global:Links) {
        $props = [ordered]@{}
        foreach ($prop in $properties) {
            $props[$prop] = $rowItem[$prop]
        }
        [PSCustomObject]$props
    }
            
}

function Idm-PolicyPermissionsRead {
    param (
        # Mode
        [switch] $GetMeta,    
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams

    )
    $system_params = ConvertFrom-Json2 $SystemParams
    $function_params = ConvertFrom-Json2 $FunctionParams
    $Class = 'Permission'
        
    if ($GetMeta) {
        Get-ClassMetaData -SystemParams $SystemParams -Class $Class
            
    }
    else {

        if ( $Global:PolicyPermissions.count -lt 1 ) { Idm-PolicyLinksRead -SystemParams $SystemParams -FunctionParams $FunctionParams | Out-Null }

        $properties = ($Global:Properties.$Class).name

        foreach ($rowItem in $Global:Permissions) {
            $props = [ordered]@{}
            foreach ($prop in $properties) {
                $props[$prop] = $rowItem[$prop]
            }
            [PSCustomObject]$props
        }      
    }
}

function Get-ClassMetaData {
    param (
        [string] $SystemParams,
        [string] $Class
    )

    @(
        @{
            name  = 'properties'
            type  = 'grid'
            label = 'Properties'
            table = @{
                rows          = @( $Global:Properties.$Class | ForEach-Object {
                        @{
                            name       = $_.name
                            usage_hint = @( @(
                                    foreach ($opt in $_.options) {
                                        if ($opt -notin @('default', 'idm', 'key')) { continue }

                                        if ($opt -eq 'idm') {
                                            $opt.Toupper()
                                        }
                                        else {
                                            $opt.Substring(0, 1).Toupper() + $opt.Substring(1)
                                        }
                                    }
                                ) | Sort-Object) -join ' | '
                        }
                    })
                settings_grid = @{
                    selection  = 'multiple'
                    key_column = 'name'
                    checkbox   = $true
                    filter     = $true
                    columns    = @(
                        @{
                            name         = 'name'
                            display_name = 'Name'
                        }
                        @{
                            name         = 'usage_hint'
                            display_name = 'Usage hint'
                        }
                    )
                }
            }
            value = ($Global:Properties.$Class | Where-Object { $_.options.Contains('default') }).name
        }
    )
}
