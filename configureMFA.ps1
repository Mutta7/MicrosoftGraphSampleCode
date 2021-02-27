Param(
    # microsoft graph reource url
    [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
    [String]
    $resource = "https://graph.microsoft.com",
    # tenantId
    [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
    [String]
    $tenantId = "<tenantId>",
    # clientId
    [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
    [String]
    $clientId = "<clientId>",
    # certificateThumbprint
    [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
    [String]
    $thumbprint = "<thumbprint>"
)

# create assertion
$appEndPoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$jwtStartTimeUnix = ([System.DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeSeconds()
$jwtEndTimeUnix = ([System.DateTimeOffset](Get-Date).AddHours(1).ToUniversalTime()).ToUnixTimeSeconds()
$jwtId = [guid]::NewGuid().guid

$cert = Get-ChildItem -Path Cert:\CurrentUser\My | where {$_.Subject -eq "CN=SelfSignedCert_configureMFA"}

$decJwtHeader = @{
    alg = "RS256";
    typ = "JWT";
    x5t = [System.Convert]::ToBase64String($cert.GetCertHash())
} | ConvertTo-Json -Compress

$decJwtPayLoad = @{
    aud = $appEndPoint;
    exp = $jwtEndTimeUnix;
    iss = $clientId;
    jti = $jwtId;
    nbf = $jwtStartTimeUnix;
    sub = $clientId
} | ConvertTo-Json -Compress

$encJwtHeaderBytes = [system.text.encoding]::UTF8.GetBytes($decJwtHeader)
$encHeader = [system.convert]::ToBase64String($encJwtHeaderBytes) -replace '\+','-' -replace '/','_' -replace '='

$encJwtPayLoadBytes = [system.text.encoding]::UTF8.GetBytes($decJwtPayLoad)
$encPayLoad = [system.Convert]::ToBase64String($encJwtPayLoadBytes) -replace '\+','-' -replace '/','_' -replace '='

$jwtToken = $encHeader + '.' + $encPayLoad
$toSign = [system.text.encoding]::UTF8.GetBytes($jwtToken)

$RSACryptoSP = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
$HashAlgo = [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
$sha256oid = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256")

$RSACryptoSP.FromXmlString($cert.PrivateKey.ToXmlString($true))
$hashBytes = $HashAlgo.ComputeHash($toSign)
$signedBytes = $RSACryptoSP.SignHash($hashBytes, $sha256oid)
$signature = [convert]::ToBase64String($signedBytes) -replace '\+','-' -replace '/','_' -replace '='

$signedJwtToken = $jwtToken + '.' + $signature
$signedJwtToken

$tokenRequestBody = @{
    client_id = $clientId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion = $signedJwtToken
    scope = "$resource/.default"
    grant_type = "client_credentials"
}

$oauth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $tokenRequestBody
$oauth | fl

$headers = @{
    "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
}

$UPN = "<userPrincipalName>"

$body = @{
    "`$select" = "displayName,id,userPrincipalName,companyName,department,jobTitle"
}

$response_user = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Method Get -Headers $headers -Body $body -Verbose
$userlist = $response_user.value

while ($null -ne $response_user.'@odata.netLink') {
    $response_user = Invoke-RestMethod -Uri $response_user.'@odata.nextLink' -Method Get -Headers $headers -Verbose
    $userlist += $response_user.value
}

$targetUser = $userlist | Where-Object {$_.userPrincipalName -match $UPN}
$objectId = $targetUser.id
$targetUser | fl
$objectId

$reqUri = "$resource/beta/users/{$objectId}/authentication/phoneMethods"
#$reqUri_mobile = "$resource/beta/users/{$objectId}/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7"

$response = Invoke-RestMethod -Uri $reqUri -Method Get -Headers $headers -ContentType "application/json" -Verbose
$result=$response.value

while ($null -ne $response.'@odata.netLink') {
    $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $headers -Verbose
    $result += $response.value
}

$phoneMethods = $result

$phoneMethods | fl