# Downloads ForceBindIP 1.32 (freeware by Richard Stanway, https://r1ch.net/projects/forcebindip)
# into this folder. It is optional: NetSplit's pinning service routes pinned apps without it.
$ErrorActionPreference = 'Stop'
$url = 'https://r1ch.net/assets/forcebindip/ForceBindIP-1.32.zip'
$sha256 = '9E52A88262093D3A50C19A5B46ECC22D9F4A95BCC7C2E968FADD5C5942024B1A'
$zip = Join-Path $env:TEMP 'ForceBindIP-1.32.zip'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($actual -ne $sha256) { Remove-Item $zip; throw "Checksum mismatch: expected $sha256, got $actual" }

Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
Remove-Item $zip
Get-ChildItem $PSScriptRoot -Include *.exe, *.dll -Recurse | ForEach-Object { $_.Name }
Write-Host 'ForceBindIP installed.'
