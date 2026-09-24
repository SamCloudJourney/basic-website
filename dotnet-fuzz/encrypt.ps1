param(
  [Parameter(Mandatory=$true)][string]$InputDirectory,
  [Parameter(Mandatory=$true)][string]$OutputDirectory,
  [Parameter(Mandatory=$true)][string]$PublicKeyPath
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$zip = Join-Path $OutputDirectory "results.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $InputDirectory "*") -DestinationPath $zip -Force

$key = New-Object byte[] 32
$iv = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

$outPath = Join-Path $OutputDirectory "results.zip.enc"
$input = [System.IO.File]::OpenRead($zip)
$output = [System.IO.File]::Create($outPath)
try {
  $output.Write($iv, 0, $iv.Length)
  $encryptor = $aes.CreateEncryptor()
  $crypto = New-Object System.Security.Cryptography.CryptoStream($output, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
  try { $input.CopyTo($crypto); $crypto.FlushFinalBlock() } finally { $crypto.Dispose() }
} finally {
  $input.Dispose()
  $output.Dispose()
  $aes.Dispose()
}

$rsa = [System.Security.Cryptography.RSA]::Create()
try {
  $pem = Get-Content -Raw $PublicKeyPath
  $rsa.ImportFromPem($pem)
  $wrapped = $rsa.Encrypt($key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  [System.IO.File]::WriteAllBytes((Join-Path $OutputDirectory "key.bin.enc"), $wrapped)
} finally {
  $rsa.Dispose()
  [Array]::Clear($key, 0, $key.Length)
}
Remove-Item $zip -Force
