param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("linux", "windows")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
$branch = "secure-dotnet-probes-20260925"
$ref = "origin/" + $branch
$base = "secure-payload/" + $Target
$resultDir = Join-Path $env:RUNNER_TEMP "secure-result"
New-Item -ItemType Directory -Force -Path $resultDir | Out-Null

$rsa = [System.Security.Cryptography.RSA]::Create(3072)
$privatePem = $rsa.ExportRSAPrivateKeyPem()
$publicPem = $rsa.ExportSubjectPublicKeyInfoPem()

Write-Host ("===EPHEMERAL_PUBLIC_KEY_" + $Target + "_BEGIN===")
Write-Host $publicPem
Write-Host ("===EPHEMERAL_PUBLIC_KEY_" + $Target + "_END===")

$found = $false
for ($i = 0; $i -lt 96; $i++) {
    git fetch origin $branch --quiet
    $payloadSpec = $ref + ":" + $base + "/payload.b64"
    $keySpec = $ref + ":" + $base + "/key.b64"
    git cat-file -e $payloadSpec 2>$null
    if ($LASTEXITCODE -eq 0) {
        git cat-file -e $keySpec 2>$null
        if ($LASTEXITCODE -eq 0) {
            $found = $true
            break
        }
    }
    Start-Sleep -Seconds 5
}

if (-not $found) {
    throw "Encrypted payload was not supplied."
}

$parts = @{}
foreach ($name in @("payload.b64", "key.b64", "nonce.b64", "tag.b64")) {
    $spec = $ref + ":" + $base + "/" + $name
    $parts[$name] = (git show $spec | Out-String).Trim()
}

$encKey = [Convert]::FromBase64String($parts["key.b64"])
$key = $rsa.Decrypt($encKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
$nonce = [Convert]::FromBase64String($parts["nonce.b64"])
$tag = [Convert]::FromBase64String($parts["tag.b64"])
$cipher = [Convert]::FromBase64String($parts["payload.b64"])
$plain = New-Object byte[] $cipher.Length

$aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
$aes.Decrypt($nonce, $cipher, $tag, $plain)

$probePath = Join-Path $env:RUNNER_TEMP "probe.ps1"
$resultPath = Join-Path $env:RUNNER_TEMP "probe-result.txt"
[IO.File]::WriteAllBytes($probePath, $plain)

try {
    & pwsh -NoLogo -NoProfile -NonInteractive -File $probePath *> $resultPath
    $probeExit = $LASTEXITCODE
    Add-Content $resultPath ([Environment]::NewLine + "SECURE_PROBE_EXIT=" + $probeExit)
}
finally {
    Remove-Item $probePath -Force -ErrorAction SilentlyContinue
    $privatePem = $null
}

if (-not (Test-Path $resultPath)) {
    "No result file was produced." | Set-Content $resultPath
}

$resultPublicPem = @'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1PROdRyG1mxDnYkBZJOf
6q5u6UyqkpEQFUKGxnmUCR5NmR3npwwWaagNins/wRG4Be/h0STFfPXqVVTzGw8A
Z9iR81FO60ZTE1OoejPftdtSoeVyI7hVgVipbrljegU9n4A7ltg6H5+2sPnbpDq3
JOaSC2fp95kHHi6mS7h/R7KShuk8P9HqsxWI6/gV4F96749o9ueYM+MNNurnAOMW
koY7uOI12/NXUCePTxJAhAL8pfGeiI2PVcig/Qn156/DNPCqkX3TT+xO1yQSC8Jk
9RUFuurx+LHOm7jTXZ4ASZXkQSgNwLW8iWzDlGGaH+X2FpfuJowDnCJjyhX9VNZ7
nmXgArnZU4T1ohFpbwm+Jba2vHJ7sW1N7HrTr7TfiiEmcLif5+GJexhrnWbJU8fC
stMgm+LNB3Vkj31FtQyWlmPABhddtaIWJsZjcEfbpEEto+SiL0bWvEV2mPPswuav
8r1yOxmSRYv1vdSMk4NmCcCYWXED2PlPeZSDRnNoE90xAgMBAAE=
-----END PUBLIC KEY-----
'@

$resultRsa = [System.Security.Cryptography.RSA]::Create()
$resultRsa.ImportFromPem($resultPublicPem)
$resultKey = New-Object byte[] 32
$resultNonce = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Fill($resultKey)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($resultNonce)

$resultPlain = [IO.File]::ReadAllBytes($resultPath)
$resultCipher = New-Object byte[] $resultPlain.Length
$resultTag = New-Object byte[] 16
$resultAes = [System.Security.Cryptography.AesGcm]::new($resultKey, 16)
$resultAes.Encrypt($resultNonce, $resultPlain, $resultCipher, $resultTag)
$resultEncKey = $resultRsa.Encrypt($resultKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

[IO.File]::WriteAllText((Join-Path $resultDir "result-key.b64"), [Convert]::ToBase64String($resultEncKey))
[IO.File]::WriteAllText((Join-Path $resultDir "result-nonce.b64"), [Convert]::ToBase64String($resultNonce))
[IO.File]::WriteAllText((Join-Path $resultDir "result-tag.b64"), [Convert]::ToBase64String($resultTag))
[IO.File]::WriteAllText((Join-Path $resultDir "result-payload.b64"), [Convert]::ToBase64String($resultCipher))

Remove-Item $resultPath -Force -ErrorAction SilentlyContinue
Write-Host ("SECURE_EXECUTION_COMPLETE_" + $Target)
