<#
.SYNOPSIS
Build a Python-free Windows x64 FLNetwork portable package and optional installer.
.DESCRIPTION
Use official PyPI only. Real project configuration is never copied into the bundle.
The optional Microsoft WebView2 bootstrapper must have a valid Microsoft signature.
#>
[CmdletBinding()]
param(
    [Alias("PythonExecutable")]
    [string]$Python = "",
    [string]$IsccPath = "",
    [string]$WebView2Bootstrapper = "",
    [string]$WebView2Standalone = "",
    [string]$SigningCertificateThumbprint = "",
    [string]$SignToolPath = "",
    [string]$TimestampUrl = "",
    [switch]$RequireSigning,
    [switch]$SkipDependencies,
    [switch]$SkipSelfTest,
    [switch]$RequireInstaller
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$buildRoot = Join-Path $projectRoot ".build\windows"
$distributionRoot = Join-Path $projectRoot "dist"
$bundleRoot = Join-Path $distributionRoot "GNetwork"
$releaseRoot = Join-Path $projectRoot "release"
$appVersion = "0.4.0"
$releaseConfig = Get-Content -LiteralPath (Join-Path $projectRoot 'packaging\release-config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($RequireSigning -or $releaseConfig.channel -eq 'stable') {
    if (-not $SigningCertificateThumbprint -or -not $SignToolPath -or -not $TimestampUrl) { throw 'Stable release requires a publisher-owned signing certificate, SignTool and timestamp URL.' }
    if (-not $releaseConfig.publisher -or -not $releaseConfig.website_url -or -not $releaseConfig.update_manifest_url -or -not $releaseConfig.support_url) { throw 'Stable release identity, HTTPS download/update and support addresses are incomplete.' }
    if ($SigningCertificateThumbprint -notin @($releaseConfig.signer_thumbprints)) { throw 'Update publisher pins must contain the signing certificate thumbprint.' }
    if (Select-String -LiteralPath (Join-Path $projectRoot 'packaging\APP-LICENSE.txt') -Pattern '发行准备稿' -Quiet) { throw 'Replace the application license preparation draft before a stable release.' }
    if ($SkipSelfTest) { throw 'Stable release cannot skip frozen self-test.' }
}
if ($SigningCertificateThumbprint -and (-not $SignToolPath -or -not $TimestampUrl)) { throw 'Signing requires SignTool and a trusted timestamp URL.' }

if ($env:OS -ne "Windows_NT") {
    throw "Windows packages must be built on Windows."
}
if (-not $Python) {
    $Python = Join-Path $projectRoot "venv\Scripts\python.exe"
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Python executable not found: $Python. Use -Python to select a Python 3.11 x64 build environment."
}
$Python = (Resolve-Path -LiteralPath $Python).Path
& $Python -c "import sys; assert sys.version_info[:2] == (3,11), 'Use Python 3.11'; assert sys.maxsize > 2**32, 'Use x64 Python'"
if ($LASTEXITCODE -ne 0) { throw "Python 3.11 x64 build environment check failed." }
$metadataVersion = & $Python -c "import sys; sys.path.insert(0,sys.argv[1]); from app_metadata import APP_VERSION; print(APP_VERSION)" $projectRoot
if ($LASTEXITCODE -ne 0 -or $metadataVersion -ne $appVersion) { throw 'Version mismatch between desktop identity and build script.' }
foreach ($requiredRelative in @("desktop_app.py", "packaging\fl-network.ico", "packaging\fl-network.spec")) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $requiredRelative) -PathType Leaf)) {
        throw "Required build input is missing: $requiredRelative"
    }
}
foreach ($targetPath in @($buildRoot, $distributionRoot, $releaseRoot)) {
    [System.IO.Directory]::CreateDirectory($targetPath) | Out-Null
}

Push-Location -LiteralPath $projectRoot
try {
    $applicationLicense = [IO.File]::ReadAllText((Join-Path $projectRoot 'packaging\APP-LICENSE.txt'), [Text.Encoding]::UTF8)
    $runtimeLicense = [IO.File]::ReadAllText((Join-Path $projectRoot 'packaging\WEBVIEW2-LICENSE.txt'), [Text.Encoding]::UTF8)
    $combinedLicense = $applicationLicense + "`r`n`r`nMicrosoft WebView2 Runtime 许可条款（安装和使用该组件须遵守以下条款）`r`n`r`n" + $runtimeLicense
    [IO.File]::WriteAllText((Join-Path $projectRoot 'packaging\installer-license.txt'), $combinedLicense, [Text.UTF8Encoding]::new($true))
    if (-not $SkipDependencies) {
        & $Python -m pip install --index-url https://pypi.org/simple -r requirements-desktop.txt
        if ($LASTEXITCODE -ne 0) { throw "Desktop dependency installation failed." }
    }
    & $Python -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Desktop dependency compatibility check failed." }
    & $Python -m PyInstaller --noconfirm --clean --workpath $buildRoot --distpath $distributionRoot packaging\fl-network.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

    $executablePath = Join-Path $bundleRoot "GNetwork.exe"
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) { throw "Build did not produce GNetwork.exe." }
    $privateNames = @("servers.json", "settings.json", "node-routing.json", "clash-profiles.json", "known_hosts", "known_hosts.lock", "xray_result.json", ".env", "id_rsa", "id_ed25519")
    $privateFiles = @(Get-ChildItem -LiteralPath $bundleRoot -Recurse -File | Where-Object { $_.Name -in $privateNames })
    if ($privateFiles.Count -gt 0) {
        throw "Distribution contains private configuration. Packaging stopped: $($privateFiles.Name -join ', ')"
    }

    $selfTestReport = Join-Path $buildRoot "self-test-report.json"
    if (-not $SkipSelfTest) {
        if (Test-Path -LiteralPath $selfTestReport) { Remove-Item -LiteralPath $selfTestReport -Force }
        $selfTestProcess = Start-Process -FilePath $executablePath -ArgumentList @("--self-test", ('"' + $selfTestReport + '"')) -WindowStyle Hidden -PassThru
        if (-not $selfTestProcess.WaitForExit(60000)) {
            Stop-Process -Id $selfTestProcess.Id -ErrorAction SilentlyContinue
            throw "Frozen application self-test timed out."
        }
        $selfTestProcess.Refresh()
        if ($selfTestProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $selfTestReport -PathType Leaf)) {
            throw "Frozen application self-test failed; inspect $selfTestReport and the application log."
        }
        $selfTestResult = Get-Content -LiteralPath $selfTestReport -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($selfTestResult.app -ne "G-Network" -or $selfTestResult.status -ne "passed" -or $selfTestResult.data_isolated -ne $true -or
            @($selfTestResult.checks | Where-Object { $_.passed -ne $true }).Count -gt 0 -or @($selfTestResult.checks).Count -eq 0) {
            throw "Frozen application reported a failed or incomplete self-test: $selfTestReport"
        }
    } else {
        Write-Warning "Frozen application self-test was skipped; this package still needs validation."
    }

    if ($SigningCertificateThumbprint) {
        & (Join-Path $PSScriptRoot 'sign_windows.ps1') -File $executablePath -CertificateThumbprint $SigningCertificateThumbprint -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl
    }
    $portablePath = Join-Path $releaseRoot "G-Network-$appVersion-windows-x64.zip"
    Compress-Archive -LiteralPath $bundleRoot -DestinationPath $portablePath -CompressionLevel Optimal -Force

    if (-not $IsccPath) {
        $compilerCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($compilerCommand) { $IsccPath = $compilerCommand.Source }
    }
    if (-not $IsccPath) {
        foreach ($compilerDirectory in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, (Join-Path $env:LOCALAPPDATA "Programs"))) {
            if ($compilerDirectory) {
                $compilerCandidate = Join-Path $compilerDirectory "Inno Setup 6\ISCC.exe"
                if (Test-Path -LiteralPath $compilerCandidate -PathType Leaf) { $IsccPath = $compilerCandidate; break }
            }
        }
    }

    $installerPath = $null
    if ($IsccPath) {
        if (-not (Test-Path -LiteralPath $IsccPath -PathType Leaf)) { throw "Inno Setup compiler not found: $IsccPath" }
        $installerArgs = @("/DAppVersion=$appVersion", "/DBuildDir=$bundleRoot", "/DReleaseDir=$releaseRoot")
        if ($WebView2Bootstrapper) {
            $bootstrapperPath = (Resolve-Path -LiteralPath $WebView2Bootstrapper).Path
            $bootstrapperSignature = Get-AuthenticodeSignature -LiteralPath $bootstrapperPath
            if ($bootstrapperSignature.Status -ne "Valid" -or $bootstrapperSignature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
                throw "WebView2 bootstrapper must have a valid Microsoft Corporation signature."
            }
            $installerArgs += "/DWebView2Bootstrapper=$bootstrapperPath"
        }
        $installerArgs += (Join-Path $projectRoot "packaging\fl-network.iss")
        & $IsccPath @installerArgs
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup installer compilation failed. Portable ZIP is available: $portablePath" }
        $installerPath = Join-Path $releaseRoot "G-Network-$appVersion-windows-x64-Setup.exe"
        if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw "Installer compiler did not produce Setup.exe." }
        if ($SigningCertificateThumbprint) {
            & (Join-Path $PSScriptRoot 'sign_windows.ps1') -File $installerPath -CertificateThumbprint $SigningCertificateThumbprint -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl
        }
    } else {
        Write-Warning "Inno Setup is unavailable. Portable ZIP was built; no Setup.exe installer was produced. Supply -IsccPath to build the installer."
    }

    $fullInstallerPath = $null
    if ($WebView2Standalone) {
        if (-not $IsccPath) { throw 'Offline full installer requires Inno Setup.' }
        $standalonePath = (Resolve-Path -LiteralPath $WebView2Standalone).Path
        $standaloneSignature = Get-AuthenticodeSignature -LiteralPath $standalonePath
        if ($standaloneSignature.Status -ne 'Valid' -or $standaloneSignature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'Offline WebView2 installer must have a valid Microsoft signature.' }
        if ([IO.Path]::GetFileName($standalonePath) -ne 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe') { throw 'Use the official x64 Evergreen Standalone Installer.' }
        & $IsccPath "/DAppVersion=$appVersion" "/DBuildDir=$bundleRoot" "/DReleaseDir=$releaseRoot" '/DOutputSuffix=-Full' "/DWebView2Standalone=$standalonePath" (Join-Path $projectRoot 'packaging\fl-network.iss')
        if ($LASTEXITCODE -ne 0) { throw 'Offline full installer compilation failed.' }
        $fullInstallerPath = Join-Path $releaseRoot "G-Network-$appVersion-windows-x64-Full-Setup.exe"
        if ($SigningCertificateThumbprint) {
            & (Join-Path $PSScriptRoot 'sign_windows.ps1') -File $fullInstallerPath -CertificateThumbprint $SigningCertificateThumbprint -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl
        }
    }

    $hashFiles = @($portablePath)
    if ($installerPath) { $hashFiles += $installerPath }
    if ($fullInstallerPath) { $hashFiles += $fullInstallerPath }
    $hashLines = foreach ($hashFile in $hashFiles) {
        $hash = Get-FileHash -LiteralPath $hashFile -Algorithm SHA256
        "$($hash.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($hashFile))"
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $releaseRoot "SHA256SUMS.txt") -Encoding UTF8
    [ordered]@{
        version = $appVersion
        app = 'G-Network'
        publisher = $releaseConfig.publisher
        channel = $releaseConfig.channel
        platform = "windows-x64"
        portable = $portablePath
        installer = $installerPath
        full_installer = $fullInstallerPath
        signed = [bool]$SigningCertificateThumbprint
        installer_built = [bool]$installerPath
        self_test_passed = -not [bool]$SkipSelfTest
        self_test_report = $(if ($SkipSelfTest) { $null } else { $selfTestReport })
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releaseRoot "build-manifest.json") -Encoding UTF8

    Write-Host "Portable: $portablePath"
    if ($installerPath) { Write-Host "Installer: $installerPath" }
    if ($fullInstallerPath) { Write-Host "Offline full installer: $fullInstallerPath" }
    Write-Host "Checksums: $(Join-Path $releaseRoot 'SHA256SUMS.txt')"
    if ($RequireInstaller -and -not $installerPath) { throw "Installer was required but Inno Setup is unavailable. Portable ZIP remains available." }
} finally {
    Pop-Location
}
