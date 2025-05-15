# ftflstwd-tools.psm1
function Get-PublicIP {
    <#
    .SYNOPSIS
        Retrieves public IP address information using the IPinfo API.
    .DESCRIPTION
        Fetches IPv4 and IPv6 information for the current machine or specified IP addresses using IPinfo's v4/v6 Lite API.
    .PARAMETER IPAddress
        Optional IP address(es) (IPv4 or IPv6) to query. Accepts multiple IPs via pipeline or array. If omitted, retrieves public IPv4 and IPv6 information for the current machine.
    .EXAMPLE
        Get-PublicIP
        Retrieves public IPv4 and IPv6 information for the current machine.
    .EXAMPLE
        Get-PublicIP -IPAddress "8.8.8.8"
        Retrieves information for the specified IPv4 address.
    .EXAMPLE
        "8.8.8.8", "2001:4860:4860::8888" | Get-PublicIP
        Retrieves information for multiple IP addresses via pipeline.
    .NOTES
        Requires IPINFO_API_KEY environment variable to be set with a valid IPinfo API token.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({ $_ -eq '' -or [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [AllowEmptyString()]
        [string[]]$IPAddress
    )

    begin {
        # Validate API token early
        $apiToken = $env:IPINFO_API_KEY
        if (-not $apiToken) {
            throw "IPINFO_API_KEY environment variable is not set."
        }

        # Define constants
        $baseUriV4 = "https://v4.api.ipinfo.io/lite"
        $baseUriV6 = "https://v6.api.ipinfo.io/lite"
        $apiTokenQuery = "?token=$apiToken"

        # Helper function for API requests
        function Invoke-ApiRequest {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]$Uri,
                [Parameter(Mandatory = $true)]
                [string]$Context
            )
            try {
                Write-Verbose "Querying API: $Uri"
                return Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop
            }
            catch {
                $errorMessage = "Failed to fetch $Context from $Uri`: $($_.Exception.Message)"
                if ($_.Exception.Response) {
                    $errorMessage += " (HTTP $($_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription))"
                }
                Write-Error $errorMessage
                return $null
            }
        }

        # Initialize results collection
        $results = [System.Collections.Generic.List[pscustomobject]]::new()
    }

    process {
        # Handle no IP address provided (fetch "me" information)
        if (-not $IPAddress -or $IPAddress.Count -eq 0 -or ($IPAddress.Count -eq 1 -and [string]::IsNullOrEmpty($IPAddress[0]))) {
            Write-Verbose "No IP address provided. Fetching IPv4 and IPv6 information."
            $requests = @(
                @{ Uri = "$baseUriV4/me$apiTokenQuery"; Context = "IPv4 'me'" }
                @{ Uri = "$baseUriV6/me$apiTokenQuery"; Context = "IPv6 'me'" }
            )

            foreach ($req in $requests) {
                if ($result = Invoke-ApiRequest -Uri $req.Uri -Context $req.Context) {
                    $results.Add($result)
                }
            }
        }
        else {
            # Process each IP address
            foreach ($ip in $IPAddress) {
                if ([string]::IsNullOrEmpty($ip)) {
                    continue  # Skip empty strings in array
                }
                Write-Verbose "Querying specific IP: $ip"
                try {
                    $parsedIP = [System.Net.IPAddress]::Parse($ip)
                    $baseUri = switch ($parsedIP.AddressFamily) {
                        ([System.Net.Sockets.AddressFamily]::InterNetwork) { $baseUriV4 }
                        ([System.Net.Sockets.AddressFamily]::InterNetworkV6) { $baseUriV6 }
                        default { throw "Unsupported IP address family for '$ip'." }
                    }
                    $uri = "$baseUri/$ip$apiTokenQuery"
                    if ($result = Invoke-ApiRequest -Uri $uri -Context "IP '$ip'") {
                        $results.Add($result)
                    }
                }
                catch {
                    Write-Error "Invalid IP address: $ip. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        return $results
    }
}

# Export the function
Export-ModuleMember -Function Get-PublicIP
