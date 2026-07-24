$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

function Read-EnvFile($Path) {
	if (!(Test-Path -LiteralPath $Path)) {
		return
	}

	Get-Content -LiteralPath $Path | ForEach-Object {
		$Line = $_.Trim()
		if (!$Line -or $Line.StartsWith("#")) {
			return
		}
		$Separator = $Line.IndexOf("=")
		if ($Separator -le 0) {
			return
		}
		$Name = $Line.Substring(0, $Separator).Trim()
		$Value = $Line.Substring($Separator + 1).Trim().Trim('"').Trim("'")
		if ($Name -and !(Test-Path "Env:$Name")) {
			Set-Item -Path "Env:$Name" -Value $Value
		}
	}
}

function Get-ActiveLanIp {
	$Address = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
		Where-Object {
			$_.IPAddress -notlike "127.*" -and
			$_.IPAddress -notlike "169.254.*" -and
			$_.PrefixOrigin -ne "WellKnown"
		} |
		Sort-Object InterfaceMetric |
		Select-Object -First 1 -ExpandProperty IPAddress

	if ($Address) {
		return $Address
	}

	$IpConfig = ipconfig | Select-String -Pattern "IPv4"
	if ($IpConfig) {
		return (($IpConfig[0].ToString() -split ":")[1]).Trim()
	}

	return "<PC-LAN-IP>"
}

Read-EnvFile (Join-Path $ProjectRoot ".env.local")

if (!$env:HTTPS_PORT) {
	$env:HTTPS_PORT = "3443"
}

if (!$env:HTTPS_CERT_PATH) {
	$env:HTTPS_CERT_PATH = "certs/local-cert.pem"
}

if (!$env:HTTPS_KEY_PATH) {
	$env:HTTPS_KEY_PATH = "certs/local-key.pem"
}

if (!$env:LOCAL_LAN_IP) {
	$env:LOCAL_LAN_IP = Get-ActiveLanIp
}

$CertPath = Join-Path $ProjectRoot $env:HTTPS_CERT_PATH
$KeyPath = Join-Path $ProjectRoot $env:HTTPS_KEY_PATH

if (!(Test-Path -LiteralPath $CertPath)) {
	throw "Missing HTTPS certificate: $CertPath. Run: npm run cert:local"
}

if (!(Test-Path -LiteralPath $KeyPath)) {
	throw "Missing HTTPS private key: $KeyPath. Run: npm run cert:local"
}

Write-Host ""
Write-Host "Local HTTPS:"
Write-Host "https://localhost:$($env:HTTPS_PORT)/#/"
Write-Host ""
Write-Host "LAN HTTPS:"
Write-Host "https://$($env:LOCAL_LAN_IP):$($env:HTTPS_PORT)/#/"
Write-Host ""

npm run dev:https
