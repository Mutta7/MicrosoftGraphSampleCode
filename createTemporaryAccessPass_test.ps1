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
    $thumbprint = "<thumbprint>",
    # application Secret
    [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
    [string]
    $clientSecret = "<secret>"

)

# create assertion
$appEndPoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$jwtStartTimeUnix = ([System.DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeSeconds()
$jwtEndTimeUnix = ([System.DateTimeOffset](Get-Date).AddHours(1).ToUniversalTime()).ToUnixTimeSeconds()
$jwtId = [guid]::NewGuid().guid

$cert = Get-ChildItem -Path Cert:\CurrentUser\My | where {$_.Subject -eq "CN=<sertificateCN>"}

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
# $signedJwtToken

$tokenRequestBody = @{
    client_id = $clientId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion = $signedJwtToken
    scope = "$resource/.default"
    grant_type = "client_credentials"
}

$oauth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $tokenRequestBody
# $oauth | fl

$headers = @{
    "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
}

$UPN = "<userPrincipalName>"

$reqUri_Get = "$resource/beta/users/$($UPN)/authentication/temporaryAccessPassMethods/"
$reqUri_Create = "$resource/beta/users/$($UPN)/authentication/temporaryAccessPassMethods"


$response = Invoke-WebRequest -UseBasicParsing -Uri $reqUri_Get -Method Get -Headers $headers -ContentType "application/json"

$tapJsonValue = ($response.Content | ConvertFrom-Json).value

if ($null -eq $tapJsonValue){
    Write-Host "tapJsonValue is null."
    Write-Host "create Temporary Access Pass"
    $body = '{
        "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethod",
        "lifetimeInMinutes": 60,
        "isUsableOnce": false
      }'
    $response = Invoke-RestMethod -Uri $reqUri_Create -Method Post -Body $body -Headers $headers -ContentType "application/json" -Verbose
    $response | fl
} elseif ($null -ne $tapJsonValue) {
    Write-Host "tapJsonValue is NOT null"
    Write-Host "STOP creating Temporary Access Pass"
}
