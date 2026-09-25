param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("linux", "windows")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
$branch = "registry-auth-cache-secure-20260925"
$ref = "origin/" + $branch
$base = "secure-payload/" + $Target + "/" + $env:GITHUB_RUN_ID
$resultDir = Join-Path $env:RUNNER_TEMP "secure-result"
New-Item -ItemType Directory -Force -Path $resultDir | Out-Null

$rsa = [System.Security.Cryptography.RSA]::Create(3072)
$privatePem = $rsa.ExportRSAPrivateKeyPem()
$publicPem = $rsa.ExportSubjectPublicKeyInfoPem()

Write-Host ("===EPHEMERAL_PUBLIC_KEY_" + $Target + "_BEGIN===")
Write-Host $publicPem
Write-Host ("===EPHEMERAL_PUBLIC_KEY_" + $Target + "_END===")

# Publish only the ephemeral PUBLIC key on a one-run branch so the orchestrator
# can encrypt the payload while this job is waiting. The private key never leaves this runner.
$keyBranch = "secure-key-" + $Target + "-" + $env:GITHUB_RUN_ID
git config user.name "secure-probe-runner"
git config user.email "secure-probe-runner@users.noreply.github.com"
git checkout -b $keyBranch | Out-Null
New-Item -ItemType Directory -Force -Path "secure-key" | Out-Null
[IO.File]::WriteAllText("secure-key/public.pem", $publicPem)
git add secure-key/public.pem
git commit -m ("Publish ephemeral public key for " + $Target) | Out-Null
git push origin ("HEAD:" + $keyBranch) --quiet
git checkout $branch | Out-Null

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
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1ypshdRx7Y00QyYQ7vfG
d+yyHLI9f382aXHe4U5Iimn9t/m9zMr8cBmcnUs58Uz1C9dyRZ3yu3Zd7p+rySAA
oLb9c+qZ7PwJ2njwt5afKKAWyi4flOJIm00qG5NuFaegYIiBmirwvOkuu2vriIKk
4It0Dswr9tkSTOl6+Kd0WwEyBtgfzvuvGNF+c9wJ4alfMnOKdP/Iw9iwwiQgw2vG
hBP4ZxoCcm+xJP9qrg2AKQOO6VoFbbnnpuRXicBjbcrmmCeIezWiWUCt1M0X6dbd
CoEvUWoMNHG622/v06uPI5NRc9nhJRDH9RypF3BtslA6VPDqXnElqemkqQ2lgdTl
58d/Hz4kiu9spQ4mIykng0KL2kCBJnjIu17aTn7Cw5Ke2zDrxXZzVKcTP7AglNZl
DWne49yhBn9j4gL08C+dA9yuBQcwvtJjMeREmfm0wwFx6IQyWZjgcvJ386jyLTfl
cMqOYbl1cKzJ9OXsBIwIUn3iLb4B8Fp8B9DhTM1EeIoRAgMBAAE=
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
