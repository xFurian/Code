<#
Disclaimer
The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties
including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts
be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption,
loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or
documentation, even if Microsoft has been advised of the possibility of such damages.
#>
# Get-RoleAssignments-Guided.ps1
# Version: 3.0
#
# Purpose:
#   Guided Microsoft security stack role assignment export using one App Registration
#   and one certificate-based app-only authentication model.
#
# Supports:
#   - Entra ID directory role assignments
#   - PIM eligible role assignments
#   - Microsoft Sentinel workspace RBAC
#   - Defender for Cloud subscription RBAC
#   - Microsoft Purview / Security & Compliance role groups
#   - Defender XDR Advanced Hunting identity role query
#   - Service principal / app registration security permission review
#
# Authentication model:
#   One App Registration + one certificate.
#
# Important:
#   This is one app/certificate identity, not one shared token.
#   Microsoft Graph, Az PowerShell, Purview PowerShell, and Defender APIs each create
#   their own service-specific connection or token, but use the same app/certificate identity.
#
# HOW TO RUN
#
# Guided menu:
#   .\Get-RoleAssignments-Guided.ps1 -GuidedStart
#
# Fully non-interactive:
#   .\Get-RoleAssignments-Guided.ps1 `
#       -AppClientId "00000000-0000-0000-0000-000000000000" `
#       -TenantId "11111111-1111-1111-1111-111111111111" `
#       -Organization "contoso.onmicrosoft.com" `
#       -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12" `
#       -IncludePIM `
#       -IncludePurview `
#       -IncludeXDRRBAC `
#       -ScanDefenderForCloud `
#       -RunExportNow `
#       -NonInteractiveStrict
#
# One initial certificate prompt, then seamless:
#   .\Get-RoleAssignments-Guided.ps1 `
#       -AppClientId "00000000-0000-0000-0000-000000000000" `
#       -TenantId "11111111-1111-1111-1111-111111111111" `
#       -Organization "contoso.onmicrosoft.com" `
#       -IncludePIM `
#       -IncludePurview `
#       -IncludeXDRRBAC `
#       -ScanDefenderForCloud `
#       -GuidedStart
#
# Required app permissions / roles:
#
# Microsoft Graph application permissions with admin consent:
#   RoleManagement.Read.All
#   Directory.Read.All
#   User.Read.All
#   Group.Read.All
#   Application.Read.All
#   AppRoleAssignment.Read.All
#   PrivilegedAccess.Read.AzureADGroup    # Required for PIM-for-Groups expansion
#
# Office 365 Exchange Online application permission with admin consent:
#   Exchange.ManageAsApp
#
# Purview / Security & Compliance RBAC:
#   Assign the service principal/app the required RBAC permissions for:
#     Get-RoleGroup
#     Get-RoleGroupMember
#
# Azure RBAC:
#   Assign Reader, Security Reader, or other required RBAC to the app/service principal
#   at the required subscription/resource group/workspace scope.
#
# Defender / Microsoft Threat Protection API permissions:
#   Microsoft Threat Protection:
#     AdvancedHunting.Read.All
#   WindowsDefenderATP:
#     Machine.Read.All
#     SecurityConfiguration.Read.All
#     AdvancedQuery.Read.All

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Array of Sentinel workspace definitions: @{ WorkspaceId=''; ResourceGroup=''; SubscriptionId='' }")]
    [hashtable[]]$SentinelWorkspaces = @(),

    [Parameter(HelpMessage = "Output folder path.")]
    [string]$OutputPath = ".\RoleAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(HelpMessage = "Export format: CSV, JSON, or Both.")]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",

    [Parameter(HelpMessage = "Target Entra role display names to include.")]
    [string[]]$TargetRoleNames = @(
        "Global Administrator",
        "Security Administrator",
        "Security Operator",
        "Security Reader",
        "Global Reader",
        "Compliance Administrator",
        "Compliance Data Administrator",
        "Information Protection Administrator",
        "Helpdesk Administrator",
        "Intune Administrator"
    ),

    [Parameter(HelpMessage = "Include PIM eligible role assignments.")]
    [switch]$IncludePIM,

    [Parameter(HelpMessage = "Scan all accessible subscriptions for Defender for Cloud RBAC.")]
    [switch]$ScanDefenderForCloud,

    [Parameter(HelpMessage = "Export Purview compliance role groups and members.")]
    [switch]$IncludePurview,

    [Parameter(HelpMessage = "Export Defender XDR RBAC / Advanced Hunting identity audit.")]
    [switch]$IncludeXDRRBAC,

    [Parameter(HelpMessage = "App Registration Client ID.")]
    [string]$AppClientId,

    [Parameter(HelpMessage = "Tenant ID for app-only authentication.")]
    [string]$TenantId,

    [Parameter(HelpMessage = "Primary tenant domain for Exchange/Purview app-only auth, for example contoso.onmicrosoft.com.")]
    [string]$Organization,

    [Parameter(HelpMessage = "Certificate thumbprint from CurrentUser or LocalMachine certificate store.")]
    [string]$CertificateThumbprint,

    [Parameter(HelpMessage = "Optional PFX path. If provided, the certificate is loaded and imported into CurrentUser\My for module compatibility.")]
    [string]$CertificateFilePath,

    [Parameter(HelpMessage = "Optional PFX password. If not provided with CertificateFilePath, script prompts once unless -NonInteractiveStrict is used.")]
    [securestring]$CertificatePassword,

    [Parameter(HelpMessage = "Launch the guided multi-layer start menu.")]
    [switch]$GuidedStart,

    [Parameter(HelpMessage = "Skip guided menu and run export directly.")]
    [switch]$RunExportNow,

    [Parameter(HelpMessage = "Show structured run instructions and examples.")]
    [switch]$ShowRunInstructions,

    [Parameter(HelpMessage = "Show structured run instructions only, then exit.")]
    [switch]$ShowRunInstructionsOnly,

    [Parameter(HelpMessage = "Export structured run instructions to JSON in the output folder.")]
    [switch]$ExportRunInstructions,

    [Parameter(HelpMessage = "Do not prompt. Fail if required values are missing.")]
    [switch]$NonInteractiveStrict
)

# =============================================================================
# Basic helpers
# =============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "  >> $Text" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [WARN] $Text" -ForegroundColor DarkYellow
}

function Stop-Script {
    param([string]$Message)
    Write-Error $Message
    throw $Message
}

function Export-Results {
    param(
        [object[]]$Data,
        [string]$FileName,
        [string]$Format
    )

    if (-not $Data -or @($Data).Count -eq 0) {
        Write-Warn "No data to export for: $FileName"
        return
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    if ($Format -in @("CSV", "Both")) {
        $Data | Export-Csv -Path (Join-Path $OutputPath "$FileName.csv") -NoTypeInformation -Encoding UTF8
        Write-OK "Exported $(@($Data).Count) rows -> $FileName.csv"
    }

    if ($Format -in @("JSON", "Both")) {
        $Data | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "$FileName.json") -Encoding UTF8
        Write-OK "Exported $(@($Data).Count) rows -> $FileName.json"
    }
}

function Read-RequiredValue {
    param(
        [string]$CurrentValue,
        [string]$Prompt,
        [string]$Name
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        return $CurrentValue
    }

    if ($NonInteractiveStrict) {
        Stop-Script "$Name is required. Provide it as a parameter or run without -NonInteractiveStrict to allow a one-time prompt."
    }

    $value = Read-Host $Prompt

    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-Script "$Name is required."
    }

    return $value
}

function ConvertTo-PlainText {
    param([securestring]$SecureString)

    if (-not $SecureString) {
        return $null
    }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# =============================================================================
# Guided menu / layered user experience
# =============================================================================

function Get-MenuRunInstructions {
    param([string]$ScriptName = ".\Get-RoleAssignments-Guided.ps1")

    return [PSCustomObject][ordered]@{
        Title = "Microsoft Security Stack Role Assignment Export"
        Purpose = "Exports role assignments and security-related access data from Entra ID, PIM, Sentinel, Defender for Cloud, Purview, Defender XDR, and service principals."
        RecommendedAuthentication = "Single App Registration + single certificate-based app-only authentication."
        PromptModel = "One initial certificate prompt if certificate details are not supplied. Fully non-interactive when all required values are passed with -NonInteractiveStrict."
        ImportantNote = "The script uses one app/certificate identity, but each service still creates its own connection context."

        FullyNonInteractiveExample = @"
$ScriptName `
    -AppClientId "00000000-0000-0000-0000-000000000000" `
    -TenantId "11111111-1111-1111-1111-111111111111" `
    -Organization "contoso.onmicrosoft.com" `
    -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12" `
    -IncludePIM `
    -IncludePurview `
    -IncludeXDRRBAC `
    -ScanDefenderForCloud `
    -RunExportNow `
    -NonInteractiveStrict
"@

        OneInitialPromptExample = @"
$ScriptName `
    -AppClientId "00000000-0000-0000-0000-000000000000" `
    -TenantId "11111111-1111-1111-1111-111111111111" `
    -Organization "contoso.onmicrosoft.com" `
    -IncludePIM `
    -IncludePurview `
    -IncludeXDRRBAC `
    -ScanDefenderForCloud `
    -GuidedStart
"@

        PurviewOnlyExample = @"
$ScriptName `
    -AppClientId "00000000-0000-0000-0000-000000000000" `
    -TenantId "11111111-1111-1111-1111-111111111111" `
    -Organization "contoso.onmicrosoft.com" `
    -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12" `
    -IncludePurview `
    -RunExportNow `
    -NonInteractiveStrict
"@

        RequiredAppConfiguration = @(
            "Upload the public certificate to the app registration.",
            "Ensure the private key is available on the machine running the script.",
            "Grant Microsoft Graph application permissions and admin consent.",
            "Grant Office 365 Exchange Online application permission Exchange.ManageAsApp and admin consent when using Purview.",
            "Assign the app/service principal the required Exchange/Purview RBAC permissions for Get-RoleGroup and Get-RoleGroupMember.",
            "Assign Azure RBAC access if Sentinel or Defender for Cloud sections are enabled.",
            "Grant Microsoft Threat Protection / Defender API permissions if Defender XDR Advanced Hunting is enabled."
        )

        SuggestedValidation = @(
            'Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My | Where-Object Thumbprint -eq "<thumbprint>" | Select Subject, Thumbprint, HasPrivateKey, NotAfter',
            "Validate Graph app-only auth using Connect-MgGraph with the app and certificate.",
            "Validate Azure access using Connect-AzAccount with service principal certificate authentication.",
            "Validate Purview access using Connect-IPPSSession with app-only certificate authentication and then run Get-RoleGroup.",
            "Use -NonInteractiveStrict for scheduled runs to ensure the script fails instead of prompting."
        )
    }
}

function Show-TitleLayer {
    Clear-Host
    Write-Host ""
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host "  Microsoft Security Stack Role Assignment Export" -ForegroundColor Cyan
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Hello. This guided menu can help you review how to run the script,"
    Write-Host "  confirm prerequisites, understand the authentication model, or start the export."
    Write-Host ""
    Write-Host "  Main Menu" -ForegroundColor Yellow
    Write-Host "  ---------"
    Write-Host "   1. How to run"
    Write-Host "   2. Tips and tricks"
    Write-Host "   3. How this works"
    Write-Host "   4. Authentication and permission checklist"
    Write-Host "   5. Actually run the export"
    Write-Host "   6. Export run instructions to JSON"
    Write-Host "   0. End"
    Write-Host ""
}

function Read-ReturnOrEnd {
    Write-Host ""
    Write-Host "Next action:" -ForegroundColor Yellow
    Write-Host "  R. Return to start menu"
    Write-Host "  E. End"
    Write-Host ""

    while ($true) {
        $choice = (Read-Host "Select R or E").Trim().ToUpperInvariant()

        switch ($choice) {
            "R" { return "Return" }
            "E" { return "End" }
            default { Write-Warn "Invalid selection. Enter R to return or E to end." }
        }
    }
}

function Show-HowToRunLayer {
    param([pscustomobject]$Instructions)

    Clear-Host
    Write-Header "How to Run"

    Write-Host ""
    Write-Host "Purpose:" -ForegroundColor Cyan
    Write-Host "  $($Instructions.Purpose)"
    Write-Host ""
    Write-Host "Recommended authentication:" -ForegroundColor Cyan
    Write-Host "  $($Instructions.RecommendedAuthentication)"
    Write-Host ""
    Write-Host "Prompt model:" -ForegroundColor Cyan
    Write-Host "  $($Instructions.PromptModel)"
    Write-Host ""
    Write-Host "Important note:" -ForegroundColor Cyan
    Write-Host "  $($Instructions.ImportantNote)"

    Write-Host ""
    Write-Host "Example 1 - Fully non-interactive:" -ForegroundColor Yellow
    Write-Host $Instructions.FullyNonInteractiveExample

    Write-Host ""
    Write-Host "Example 2 - One initial certificate prompt, then seamless execution:" -ForegroundColor Yellow
    Write-Host $Instructions.OneInitialPromptExample

    Write-Host ""
    Write-Host "Example 3 - Purview-only validation/export:" -ForegroundColor Yellow
    Write-Host $Instructions.PurviewOnlyExample

    return Read-ReturnOrEnd
}

function Show-TipsAndTricksLayer {
    param([pscustomobject]$Instructions)

    Clear-Host
    Write-Header "Tips and Tricks"

    Write-Host ""
    Write-Host "Tips:" -ForegroundColor Yellow
    Write-Host "  1. Use -NonInteractiveStrict for scheduled tasks so missing inputs fail fast instead of prompting."
    Write-Host "  2. Prefer certificate thumbprint when the certificate is already installed on the execution host."
    Write-Host "  3. Use a PFX only when the script is allowed to load/import the certificate at runtime."
    Write-Host "  4. Do not hardcode PFX passwords. Use a secure store or approved automation secret mechanism."
    Write-Host "  5. Validate Purview separately with -IncludePurview before enabling every section."
    Write-Host "  6. If Azure sections return no subscriptions, validate Azure RBAC for the app/service principal."
    Write-Host "  7. If PIM group expansion returns warnings, validate PrivilegedAccess.Read.AzureADGroup application permission and admin consent."

    Write-Host ""
    Write-Host "Suggested validation:" -ForegroundColor Yellow
    foreach ($item in $Instructions.SuggestedValidation) {
        Write-Host "  - $item"
    }

    return Read-ReturnOrEnd
}

function Show-HowThisWorksLayer {
    Clear-Host
    Write-Header "How This Works"

    Write-Host ""
    Write-Host "High-level flow:" -ForegroundColor Cyan
    Write-Host "  1. The script collects or receives app/certificate authentication inputs."
    Write-Host "  2. It resolves the certificate from the certificate store or from a PFX file."
    Write-Host "  3. It connects to Microsoft Graph using the app/certificate identity."
    Write-Host "  4. If Azure sections are enabled, it connects to Azure using service principal certificate authentication."
    Write-Host "  5. If Purview is enabled, it connects to Security & Compliance PowerShell using app-only certificate authentication."
    Write-Host "  6. If Defender XDR is enabled, it requests an app-only token using the certificate and calls Advanced Hunting."
    Write-Host "  7. It exports CSV/JSON outputs and writes a manifest."

    Write-Host ""
    Write-Host "Important design point:" -ForegroundColor Yellow
    Write-Host "  This is one app/certificate identity, not one shared token."
    Write-Host "  Each service still has its own connection context and permission model."

    Write-Host ""
    Write-Host "Why this meets the customer goal:" -ForegroundColor Yellow
    Write-Host "  After the initial certificate input, there should be no browser sign-in, no MFA prompt,"
    Write-Host "  and no delegated user authentication flow for the supported app-only sections."

    return Read-ReturnOrEnd
}

function Show-AuthChecklistLayer {
    param([pscustomobject]$Instructions)

    Clear-Host
    Write-Header "Authentication and Permission Checklist"

    Write-Host ""
    Write-Host "Before running, confirm:" -ForegroundColor Cyan

    $i = 1
    foreach ($item in $Instructions.RequiredAppConfiguration) {
        Write-Host "  $i. $item"
        $i++
    }

    Write-Host ""
    Write-Host "Certificate requirements:" -ForegroundColor Yellow
    Write-Host "  - Certificate must not be expired."
    Write-Host "  - Certificate must contain a private key on the execution host."
    Write-Host "  - Public certificate must be uploaded to the app registration."
    Write-Host "  - Thumbprint must match the certificate uploaded to the app registration."

    return Read-ReturnOrEnd
}

function Export-RunInstructionsLayer {
    param(
        [pscustomobject]$Instructions,
        [string]$OutputPath
    )

    Clear-Host
    Write-Header "Export Run Instructions"

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $path = Join-Path $OutputPath "00_RunInstructions.json"

    try {
        $Instructions | ConvertTo-Json -Depth 12 | Out-File $path -Encoding UTF8
        Write-OK "Run instructions exported to: $path"
    }
    catch {
        Write-Warn "Failed to export run instructions. Error: $_"
    }

    return Read-ReturnOrEnd
}

function Confirm-RunExportLayer {
    Clear-Host
    Write-Header "Run Export"

    Write-Host ""
    Write-Host "The export will run using the parameters currently provided to the script." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "If required authentication values are missing and -NonInteractiveStrict is not used,"
    Write-Host "the script may prompt once for missing app/certificate inputs."
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  Y. Run the export"
    Write-Host "  R. Return to start menu"
    Write-Host "  E. End"
    Write-Host ""

    while ($true) {
        $choice = (Read-Host "Select Y, R, or E").Trim().ToUpperInvariant()

        switch ($choice) {
            "Y" { return "RunExport" }
            "R" { return "Return" }
            "E" { return "End" }
            default { Write-Warn "Invalid selection. Enter Y, R, or E." }
        }
    }
}

function Start-GuidedStartMenu {
    param(
        [pscustomobject]$Instructions,
        [string]$OutputPath
    )

    while ($true) {
        Show-TitleLayer
        $choice = (Read-Host "Select an option").Trim()

        switch ($choice) {
            "1" {
                $next = Show-HowToRunLayer -Instructions $Instructions
                if ($next -eq "End") { return "End" }
            }
            "2" {
                $next = Show-TipsAndTricksLayer -Instructions $Instructions
                if ($next -eq "End") { return "End" }
            }
            "3" {
                $next = Show-HowThisWorksLayer
                if ($next -eq "End") { return "End" }
            }
            "4" {
                $next = Show-AuthChecklistLayer -Instructions $Instructions
                if ($next -eq "End") { return "End" }
            }
            "5" {
                $next = Confirm-RunExportLayer
                if ($next -eq "RunExport") { return "RunExport" }
                if ($next -eq "End") { return "End" }
            }
            "6" {
                $next = Export-RunInstructionsLayer -Instructions $Instructions -OutputPath $OutputPath
                if ($next -eq "End") { return "End" }
            }
            "0" {
                return "End"
            }
            default {
                Write-Warn "Invalid menu selection. Select 1, 2, 3, 4, 5, 6, or 0."
                Start-Sleep -Seconds 1
            }
        }
    }
}

# =============================================================================
# Certificate / token helpers
# =============================================================================

function Get-CertificateFromStore {
    param([string]$Thumbprint)

    $cleanThumbprint = ($Thumbprint -replace "\s", "").ToUpperInvariant()

    $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $cleanThumbprint } |
        Select-Object -First 1

    if (-not $cert) {
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $cleanThumbprint } |
            Select-Object -First 1
    }

    return $cert
}

function Get-AuthCertificate {
    Write-Step "Resolving certificate for app-only authentication..."

    if (-not [string]::IsNullOrWhiteSpace($CertificateFilePath)) {
        if (-not (Test-Path $CertificateFilePath)) {
            Stop-Script "CertificateFilePath does not exist: $CertificateFilePath"
        }

        if (-not $CertificatePassword) {
            if ($NonInteractiveStrict) {
                Stop-Script "CertificatePassword is required when using CertificateFilePath with -NonInteractiveStrict."
            }

            $script:CertificatePassword = Read-Host "Enter PFX password" -AsSecureString
        }

        $plainPassword = ConvertTo-PlainText -SecureString $script:CertificatePassword

        try {
            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
                -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $CertificateFilePath,
                $plainPassword,
                $flags
            )
        }
        catch {
            Stop-Script "Failed to load PFX certificate. Error: $_"
        }

        if (-not $cert.HasPrivateKey) {
            Stop-Script "The PFX certificate does not contain a private key."
        }

        if ($cert.NotAfter -lt (Get-Date)) {
            Stop-Script "The certificate is expired. Thumbprint: $($cert.Thumbprint)"
        }

        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
            $store.Open("ReadWrite")
            $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Select-Object -First 1
            if (-not $existing) {
                $store.Add($cert)
                Write-OK "Imported PFX certificate into CurrentUser\My for module compatibility."
            }
            $store.Close()
        }
        catch {
            Write-Warn "Could not import certificate into CurrentUser\My. Some modules may require the certificate to be in the certificate store. Error: $_"
        }

        $script:CertificateThumbprint = $cert.Thumbprint
        Write-OK "Loaded certificate from PFX. Thumbprint: $($cert.Thumbprint)"
        return $cert
    }

    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        if ($NonInteractiveStrict) {
            Stop-Script "CertificateThumbprint or CertificateFilePath is required."
        }

        Write-Host ""
        Write-Host "Certificate authentication options:" -ForegroundColor Cyan
        Write-Host "  1. Use certificate thumbprint from certificate store"
        Write-Host "  2. Use PFX certificate file"
        Write-Host ""

        $choice = Read-Host "Enter 1 or 2"

        switch ($choice) {
            "1" {
                $script:CertificateThumbprint = Read-Host "Enter certificate thumbprint"
            }
            "2" {
                $script:CertificateFilePath = Read-Host "Enter full PFX file path"
                $script:CertificatePassword = Read-Host "Enter PFX password" -AsSecureString
                return Get-AuthCertificate
            }
            default {
                Stop-Script "Invalid certificate authentication choice."
            }
        }
    }

    $certFromStore = Get-CertificateFromStore -Thumbprint $script:CertificateThumbprint

    if (-not $certFromStore) {
        Stop-Script "Certificate with thumbprint '$script:CertificateThumbprint' was not found in CurrentUser\My or LocalMachine\My."
    }

    if (-not $certFromStore.HasPrivateKey) {
        Stop-Script "Certificate '$script:CertificateThumbprint' was found, but it does not have a private key."
    }

    if ($certFromStore.NotAfter -lt (Get-Date)) {
        Stop-Script "Certificate '$script:CertificateThumbprint' is expired."
    }

    Write-OK "Resolved certificate from store. Thumbprint: $($certFromStore.Thumbprint)"
    return $certFromStore
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-ClientAssertion {
    param(
        [string]$ClientId,
        [string]$TenantId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $now = [DateTimeOffset]::UtcNow
    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = ConvertTo-Base64Url -Bytes $Certificate.GetCertHash()
    } | ConvertTo-Json -Compress

    $payload = @{
        aud = $aud
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().Guid
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $encodedHeader = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($header))
    $encodedPayload = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($payload))
    $unsignedJwt = "$encodedHeader.$encodedPayload"

    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        $signature = $rsa.SignData(
            [Text.Encoding]::UTF8.GetBytes($unsignedJwt),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    catch {
        Stop-Script "Failed to sign client assertion with certificate private key. Error: $_"
    }

    $encodedSignature = ConvertTo-Base64Url -Bytes $signature
    return "$unsignedJwt.$encodedSignature"
}

function Get-AppOnlyAccessToken {
    param(
        [string]$Scope,
        [string]$ClientId,
        [string]$TenantId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $clientAssertion = New-ClientAssertion -ClientId $ClientId -TenantId $TenantId -Certificate $Certificate
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        client_id             = $ClientId
        scope                 = $Scope
        grant_type            = "client_credentials"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $clientAssertion
    }

    try {
        $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -Body $body -ErrorAction Stop
        return $response.access_token
    }
    catch {
        Write-Warn "Token request failed for scope '$Scope'. Error: $_"
        return $null
    }
}

# =============================================================================
# Module setup and connection
# =============================================================================

function Initialize-RequiredModules {
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Applications"
    )

    if ($IncludePIM) {
        $requiredModules += "Microsoft.Graph.Identity.Governance"
    }

    if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
        $requiredModules += "Az.Accounts", "Az.Resources"
    }

    if ($ScanDefenderForCloud) {
        $requiredModules += "Az.Security"
    }

    if ($IncludePurview) {
        $requiredModules += "ExchangeOnlineManagement"
    }

    $requiredModules = $requiredModules | Sort-Object -Unique

    Write-Step "Checking and loading required modules..."

    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Step "Installing missing module: $mod"
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-OK "Installed: $mod"
            }
            catch {
                Stop-Script "Failed to install module '$mod'. Run manually: Install-Module $mod -Scope CurrentUser -Force -AllowClobber"
            }
        }

        try {
            Import-Module -Name $mod -Force -ErrorAction Stop
            Write-OK "Imported: $mod"
        }
        catch {
            Stop-Script "Failed to import module '$mod'. Error: $_"
        }
    }

    if ($IncludePurview) {
        $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if (-not $exoModule) {
            Stop-Script "ExchangeOnlineManagement module is required for Purview / Security & Compliance PowerShell."
        }

        if ($exoModule.Version -lt [version]"3.0.0") {
            Stop-Script "ExchangeOnlineManagement version 3.0.0 or later is required for app-only Connect-IPPSSession. Current version: $($exoModule.Version)"
        }

        Write-OK "ExchangeOnlineManagement version validated: $($exoModule.Version)"
    }
}

function Initialize-AuthenticationInputs {
    Write-Header "Authentication Configuration"

    $script:AppClientId = Read-RequiredValue `
        -CurrentValue $AppClientId `
        -Prompt "Enter App Registration Client ID" `
        -Name "AppClientId"

    $script:TenantId = Read-RequiredValue `
        -CurrentValue $TenantId `
        -Prompt "Enter Tenant ID" `
        -Name "TenantId"

    if ($IncludePurview) {
        $script:Organization = Read-RequiredValue `
            -CurrentValue $Organization `
            -Prompt "Enter tenant organization domain for Purview, for example contoso.onmicrosoft.com" `
            -Name "Organization"
    }
    else {
        $script:Organization = $Organization
    }

    $script:AuthCertificate = Get-AuthCertificate
}

function Connect-AllRequiredServices {
    Write-Header "Connecting to Microsoft Graph"

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

        Connect-MgGraph `
            -ClientId $script:AppClientId `
            -TenantId $script:TenantId `
            -Certificate $script:AuthCertificate `
            -NoWelcome `
            -ErrorAction Stop

        $mgCtx = Get-MgContext

        if (-not $mgCtx) {
            Stop-Script "Microsoft Graph connection did not return a context."
        }

        Write-OK "Connected to Microsoft Graph."
        Write-OK "Graph AuthType: $($mgCtx.AuthType)"
        Write-OK "Graph ClientId: $($mgCtx.ClientId)"
        Write-OK "Graph TenantId: $($mgCtx.TenantId)"
    }
    catch {
        Stop-Script "Microsoft Graph connection failed: $_"
    }

    if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
        Write-Header "Connecting to Azure"

        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

            Connect-AzAccount `
                -ServicePrincipal `
                -ApplicationId $script:AppClientId `
                -Tenant $script:TenantId `
                -CertificateThumbprint $script:AuthCertificate.Thumbprint `
                -ErrorAction Stop | Out-Null

            Write-OK "Connected to Azure using service principal certificate authentication."
        }
        catch {
            Stop-Script "Azure connection failed. Confirm certificate store access and Azure RBAC for the app. Error: $_"
        }
    }

    if ($IncludePurview) {
        Write-Header "Connecting to Purview / Security & Compliance PowerShell"

        try {
            Connect-IPPSSession `
                -AppId $script:AppClientId `
                -Certificate $script:AuthCertificate `
                -Organization $script:Organization `
                -ErrorAction Stop

            Write-OK "Connected to Purview / Security & Compliance PowerShell using app-only certificate authentication."
        }
        catch {
            Stop-Script "Purview connection failed. Confirm Exchange.ManageAsApp, admin consent, and RBAC assignments. Error: $_"
        }
    }
}

# =============================================================================
# Query helpers
# =============================================================================

function Resolve-GraphPrincipal {
    param([string]$PrincipalId)

    $user = Get-MgUser -UserId $PrincipalId `
        -Property "Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,Department,JobTitle" `
        -ErrorAction SilentlyContinue

    if ($user) {
        return [PSCustomObject]@{
            Type           = "User"
            Id             = $user.Id
            DisplayName    = $user.DisplayName
            UPN            = $user.UserPrincipalName
            Mail           = $user.Mail
            AccountEnabled = $user.AccountEnabled
            UserType       = $user.UserType
            Department     = $user.Department
            JobTitle       = $user.JobTitle
            AppId          = ""
        }
    }

    $group = Get-MgGroup -GroupId $PrincipalId `
        -Property "Id,DisplayName,Mail,GroupTypes" `
        -ErrorAction SilentlyContinue

    if ($group) {
        return [PSCustomObject]@{
            Type           = "Group"
            Id             = $group.Id
            DisplayName    = $group.DisplayName
            UPN            = $group.Mail
            Mail           = $group.Mail
            AccountEnabled = ""
            UserType       = "Group"
            Department     = ""
            JobTitle       = ""
            AppId          = ""
        }
    }

    $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId `
        -Property "Id,DisplayName,AppId,ServicePrincipalType" `
        -ErrorAction SilentlyContinue

    if ($sp) {
        return [PSCustomObject]@{
            Type           = "ServicePrincipal"
            Id             = $sp.Id
            DisplayName    = $sp.DisplayName
            UPN            = ""
            Mail           = ""
            AccountEnabled = ""
            UserType       = "ServicePrincipal"
            Department     = ""
            JobTitle       = ""
            AppId          = $sp.AppId
        }
    }

    return [PSCustomObject]@{
        Type           = "Unknown"
        Id             = $PrincipalId
        DisplayName    = $PrincipalId
        UPN            = ""
        Mail           = ""
        AccountEnabled = ""
        UserType       = "Unknown"
        Department     = ""
        JobTitle       = ""
        AppId          = ""
    }
}

function Get-PimGroupEligibleMembers {
    param(
        [string]$GroupId,
        [string]$GroupDisplayName
    )

    $results = @()

    try {
        $uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$GroupId'"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        $schedules = @($response.value)

        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -ErrorAction SilentlyContinue
            $schedules += @($response.value)
        }

        foreach ($s in $schedules) {
            if ($s.accessId -and $s.accessId -ne "member") {
                continue
            }

            $principal = Resolve-GraphPrincipal -PrincipalId $s.principalId

            $results += [PSCustomObject]@{
                MemberDisplayName = $principal.DisplayName
                MemberUPN         = $principal.UPN
                MemberMail        = $principal.Mail
                AccountEnabled    = $principal.AccountEnabled
                Department        = $principal.Department
                JobTitle          = $principal.JobTitle
                MemberType        = "$($principal.Type) (PIM-eligible via Group: $GroupDisplayName)"
                ScheduleExpiry    = $s.scheduleInfo.expiration.endDateTime
                ExpiryType        = $s.scheduleInfo.expiration.type
            }
        }

        Write-OK "PIM-for-Groups expansion '$GroupDisplayName': $(@($results).Count) eligible member(s)"
    }
    catch {
        Write-Warn "Could not query PIM eligibility schedules for group '$GroupDisplayName'. Ensure PrivilegedAccess.Read.AzureADGroup application permission is granted. Error: $_"
    }

    return $results
}

# =============================================================================
# Export sections
# =============================================================================

function Export-EntraDirectoryRoles {
    Write-Header "1/7 Entra ID - Directory Role Assignments"

    $rows = @()

    try {
        $activeRoles = Get-MgDirectoryRole -All -ErrorAction Stop |
            Where-Object { $_.DisplayName -in $TargetRoleNames }

        Write-OK "Found $(@($activeRoles).Count) active target role(s)."

        foreach ($role in $activeRoles) {
            Write-Step "Processing role: $($role.DisplayName)"

            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue

            foreach ($member in $members) {
                $memberType = ($member.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", "")
                $principal = Resolve-GraphPrincipal -PrincipalId $member.Id

                $rows += [PSCustomObject]@{
                    RoleName          = $role.DisplayName
                    RoleId            = $role.Id
                    RoleDescription   = $role.Description
                    MemberType        = $principal.Type
                    MemberDisplayName = $principal.DisplayName
                    MemberUPN         = $principal.UPN
                    MemberMail        = $principal.Mail
                    MemberDepartment  = $principal.Department
                    MemberJobTitle    = $principal.JobTitle
                    AccountEnabled    = $principal.AccountEnabled
                    UserType          = $principal.UserType
                    MemberId          = $principal.Id
                    AppId             = $principal.AppId
                    AssignmentType    = "Active"
                    RawMemberType     = $memberType
                    ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }

                if ($principal.Type -eq "Group") {
                    $directMembers = Get-MgGroupMember -GroupId $principal.Id -All -ErrorAction SilentlyContinue

                    foreach ($dm in $directMembers) {
                        $dmPrincipal = Resolve-GraphPrincipal -PrincipalId $dm.Id

                        $rows += [PSCustomObject]@{
                            RoleName          = $role.DisplayName
                            RoleId            = $role.Id
                            RoleDescription   = $role.Description
                            MemberType        = "$($dmPrincipal.Type) (via Group: $($principal.DisplayName))"
                            MemberDisplayName = $dmPrincipal.DisplayName
                            MemberUPN         = $dmPrincipal.UPN
                            MemberMail        = $dmPrincipal.Mail
                            MemberDepartment  = $dmPrincipal.Department
                            MemberJobTitle    = $dmPrincipal.JobTitle
                            AccountEnabled    = $dmPrincipal.AccountEnabled
                            UserType          = $dmPrincipal.UserType
                            MemberId          = $dmPrincipal.Id
                            AppId             = $dmPrincipal.AppId
                            AssignmentType    = "Active via Group"
                            RawMemberType     = ""
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    if ($IncludePIM) {
                        $pimGroupMembers = Get-PimGroupEligibleMembers -GroupId $principal.Id -GroupDisplayName $principal.DisplayName

                        foreach ($pgm in $pimGroupMembers) {
                            $rows += [PSCustomObject]@{
                                RoleName          = $role.DisplayName
                                RoleId            = $role.Id
                                RoleDescription   = $role.Description
                                MemberType        = $pgm.MemberType
                                MemberDisplayName = $pgm.MemberDisplayName
                                MemberUPN         = $pgm.MemberUPN
                                MemberMail        = $pgm.MemberMail
                                MemberDepartment  = $pgm.Department
                                MemberJobTitle    = $pgm.JobTitle
                                AccountEnabled    = $pgm.AccountEnabled
                                UserType          = "User"
                                MemberId          = ""
                                AppId             = ""
                                AssignmentType    = "PIM-Eligible via Group"
                                RawMemberType     = ""
                                ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            }
                        }
                    }
                }
            }
        }

        Export-Results -Data $rows -FileName "1_Entra_Security_Roles" -Format $ExportFormat
    }
    catch {
        Write-Error "Failed to retrieve Entra ID roles: $_"
    }

    return $rows
}

function Export-PimEligibleRoles {
    Write-Header "2/7 Entra ID - PIM Eligible Role Assignments"

    $rows = @()

    if (-not $IncludePIM) {
        Write-Warn "PIM eligible assignments skipped. Use -IncludePIM to include them."
        return $rows
    }

    try {
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
        Write-OK "Total PIM eligible assignments found: $(@($eligibleAssignments).Count). Filtering to target roles only."

        foreach ($assignment in $eligibleAssignments) {
            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition `
                -UnifiedRoleDefinitionId $assignment.RoleDefinitionId `
                -ErrorAction SilentlyContinue

            if (-not $roleDef -or $roleDef.DisplayName -notin $TargetRoleNames) {
                continue
            }

            $principal = Resolve-GraphPrincipal -PrincipalId $assignment.PrincipalId

            $rows += [PSCustomObject]@{
                RoleName          = $roleDef.DisplayName
                RoleId            = $assignment.RoleDefinitionId
                MemberType        = $principal.Type
                MemberDisplayName = $principal.DisplayName
                MemberUPN         = $principal.UPN
                MemberMail        = $principal.Mail
                MemberDepartment  = $principal.Department
                MemberJobTitle    = $principal.JobTitle
                MemberId          = $principal.Id
                AppId             = $principal.AppId
                AssignmentType    = "PIM-Eligible"
                ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                MembershipType    = $assignment.MemberType
                Status            = $assignment.Status
                ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        Export-Results -Data $rows -FileName "2_EntraID_PIM_EligibleRoles" -Format $ExportFormat
    }
    catch {
        Write-Warn "PIM data retrieval failed. Confirm Entra ID P2 and Graph permissions. Error: $_"
    }

    return $rows
}

function Export-SentinelWorkspaceRbac {
    Write-Header "3/7 Microsoft Sentinel - Workspace RBAC"

    $rows = @()

    if ($SentinelWorkspaces.Count -eq 0) {
        Write-Warn "Sentinel workspace roles skipped. Use -SentinelWorkspaces to provide workspace definitions."
        return $rows
    }

    $sentinelRoleNames = @(
        "Microsoft Sentinel Contributor",
        "Microsoft Sentinel Reader",
        "Microsoft Sentinel Responder",
        "Microsoft Sentinel Automation Contributor",
        "Log Analytics Contributor",
        "Log Analytics Reader"
    )

    foreach ($ws in $SentinelWorkspaces) {
        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) {
            Write-Warn "Workspace skipped because WorkspaceId, ResourceGroup, or SubscriptionId is missing."
            continue
        }

        try {
            Set-AzContext -SubscriptionId $ws.SubscriptionId -Tenant $script:TenantId -ErrorAction Stop | Out-Null

            $sentinelScope = "/subscriptions/$($ws.SubscriptionId)/resourceGroups/$($ws.ResourceGroup)"

            $workspaceRoles = Get-AzRoleAssignment -Scope $sentinelScope -ErrorAction Stop |
                Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames } |
                ForEach-Object {
                    [PSCustomObject]@{
                        WorkspaceId    = $ws.WorkspaceId
                        ResourceGroup  = $ws.ResourceGroup
                        SubscriptionId = $ws.SubscriptionId
                        RoleName       = $_.RoleDefinitionName
                        PrincipalName  = $_.DisplayName
                        PrincipalType  = $_.ObjectType
                        PrincipalId    = $_.ObjectId
                        SignInName     = $_.SignInName
                        Scope          = $_.Scope
                        ExportedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

            $rows += @($workspaceRoles)
            Write-OK "Found $(@($workspaceRoles).Count) Sentinel role assignment(s) for workspace $($ws.WorkspaceId)."
        }
        catch {
            Write-Warn "Failed to retrieve Sentinel roles for workspace $($ws.WorkspaceId). Error: $_"
        }
    }

    Export-Results -Data $rows -FileName "3_Sentinel_Workspace_Roles" -Format $ExportFormat
    return $rows
}

function Export-DefenderForCloudRbac {
    Write-Header "4/7 Defender for Cloud - Subscription RBAC"

    $scanRows = @()
    $rbacRows = @()

    if (-not $ScanDefenderForCloud) {
        Write-Warn "Defender for Cloud scan skipped. Use -ScanDefenderForCloud to enable."
        return [PSCustomObject]@{
            ScanRows = $scanRows
            RbacRows = $rbacRows
        }
    }

    try {
        $allSubscriptions = Get-AzSubscription -TenantId $script:TenantId -ErrorAction Stop
        Write-OK "Found $(@($allSubscriptions).Count) accessible subscription(s)."

        $mdcTargetRoles = @("Owner", "Contributor", "Security Admin", "Security Reader")

        foreach ($sub in $allSubscriptions) {
            try {
                Set-AzContext -SubscriptionId $sub.Id -Tenant $script:TenantId -ErrorAction Stop | Out-Null

                $pricingTiers = Get-AzSecurityPricing -ErrorAction SilentlyContinue
                $enabledPlans = @($pricingTiers | Where-Object { $_.PricingTier -eq "Standard" } | Select-Object -ExpandProperty Name)
                $isMDCEnabled = ($enabledPlans.Count -gt 0)

                $scanRows += [PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    TenantId         = $sub.TenantId
                    MDCEnabled       = $isMDCEnabled
                    EnabledPlanCount = $enabledPlans.Count
                    EnabledPlans     = ($enabledPlans -join "; ")
                    ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }

                $subScope = "/subscriptions/$($sub.Id)"
                $assignments = Get-AzRoleAssignment -Scope $subScope -ErrorAction SilentlyContinue

                foreach ($ra in $assignments) {
                    if ($ra.RoleDefinitionName -in $mdcTargetRoles) {
                        $rbacRows += [PSCustomObject]@{
                            SubscriptionId   = $sub.Id
                            SubscriptionName = $sub.Name
                            MDCEnabledPlans  = ($enabledPlans -join "; ")
                            RoleName         = $ra.RoleDefinitionName
                            PrincipalName    = $ra.DisplayName
                            PrincipalType    = $ra.ObjectType
                            PrincipalId      = $ra.ObjectId
                            SignInName       = $ra.SignInName
                            Scope            = $ra.Scope
                            ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
            }
            catch {
                Write-Warn "Could not process subscription $($sub.Name). Error: $_"
            }
        }

        Export-Results -Data $scanRows -FileName "4_MDC_Subscription_Scan" -Format $ExportFormat
        Export-Results -Data $rbacRows -FileName "4_MDC_RBAC_Assignments" -Format $ExportFormat
    }
    catch {
        Write-Error "Defender for Cloud scan failed: $_"
    }

    return [PSCustomObject]@{
        ScanRows = $scanRows
        RbacRows = $rbacRows
    }
}

function Export-PurviewRoleGroups {
    Write-Header "5/7 Microsoft Purview - Compliance Role Groups"

    $rows = @()

    if (-not $IncludePurview) {
        Write-Warn "Purview export skipped. Use -IncludePurview to enable."
        return $rows
    }

    try {
        $allRoleGroups = Get-RoleGroup -ErrorAction Stop
        Write-OK "Found $(@($allRoleGroups).Count) compliance role group(s)."

        foreach ($rg in $allRoleGroups) {
            Write-Step "Processing Purview role group: $($rg.Name)"

            try {
                $members = Get-RoleGroupMember -Identity $rg.Name -ErrorAction SilentlyContinue

                $roleList = ""
                try {
                    $roleList = ($rg.Roles | ForEach-Object {
                        if ($_ -is [string]) {
                            ($_ -split "/")[-1]
                        }
                        elseif ($_.Name) {
                            $_.Name
                        }
                        else {
                            ($_.ToString() -split "/")[-1]
                        }
                    }) -join "; "
                }
                catch {
                    $roleList = ($rg.Roles -join "; ")
                }

                if (-not $members -or @($members).Count -eq 0) {
                    $rows += [PSCustomObject]@{
                        RoleGroupName        = $rg.Name
                        RoleGroupDescription = $rg.Description
                        RoleGroupType        = $rg.RoleGroupType
                        AssignedRoles        = $roleList
                        MemberDisplayName    = "(No members)"
                        MemberUPN            = ""
                        MemberMail           = ""
                        MemberType           = ""
                        ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }
                else {
                    foreach ($m in $members) {
                        $rows += [PSCustomObject]@{
                            RoleGroupName        = $rg.Name
                            RoleGroupDescription = $rg.Description
                            RoleGroupType        = $rg.RoleGroupType
                            AssignedRoles        = $roleList
                            MemberDisplayName    = $m.DisplayName
                            MemberUPN            = if ($m.WindowsLiveId) { $m.WindowsLiveId } elseif ($m.PrimarySmtpAddress) { $m.PrimarySmtpAddress } else { $m.Name }
                            MemberMail           = $m.PrimarySmtpAddress
                            MemberType           = $m.RecipientTypeDetails
                            ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
            }
            catch {
                Write-Warn "Could not process Purview role group '$($rg.Name)'. Error: $_"
            }
        }

        Export-Results -Data $rows -FileName "5_Purview_RoleGroups" -Format $ExportFormat
    }
    catch {
        Write-Error "Purview data retrieval failed. Confirm Exchange.ManageAsApp, admin consent, and RBAC permissions. Error: $_"
    }

    return $rows
}

function Export-DefenderXdrIdentityRoleQuery {
    Write-Header "6/7 Defender XDR - Advanced Hunting Identity Role Query"

    $rows = @()

    if (-not $IncludeXDRRBAC) {
        Write-Warn "XDR RBAC export skipped. Use -IncludeXDRRBAC to enable."
        return $rows
    }

    $secToken = Get-AppOnlyAccessToken `
        -Scope "https://api.security.microsoft.com/.default" `
        -ClientId $script:AppClientId `
        -TenantId $script:TenantId `
        -Certificate $script:AuthCertificate

    if (-not $secToken) {
        Write-Warn "Could not acquire Defender XDR token. Ensure Microsoft Threat Protection AdvancedHunting.Read.All application permission is granted."
        return $rows
    }

    try {
        $roleList = ($TargetRoleNames | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ","

        $kqlQuery = @"
let XdrRoles = dynamic([$roleList]);
IdentityInfo
| where isnotempty(AssignedRoles)
| mv-expand AssignedRole = AssignedRoles
| where AssignedRole in (XdrRoles)
| summarize arg_max(Timestamp, *) by AccountObjectId
| project AccountUpn, AccountDisplayName, AccountObjectId, Department, JobTitle,
          IsAccountEnabled, AssignedRoles, GroupMembership, RiskLevel, BlastRadius, IdentityEnvironment
| order by AccountDisplayName asc
"@

        $body = @{ Query = $kqlQuery } | ConvertTo-Json
        $headers = @{
            Authorization  = "Bearer $secToken"
            "Content-Type" = "application/json"
        }

        $ahResult = Invoke-RestMethod `
            -Method POST `
            -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
            -Headers $headers `
            -Body $body `
            -ErrorAction Stop

        foreach ($identity in @($ahResult.Results)) {
            $rolesStr = if ($identity.AssignedRoles) { ($identity.AssignedRoles | ForEach-Object { $_ }) -join "; " } else { "" }
            $groupsStr = if ($identity.GroupMembership) { ($identity.GroupMembership | ForEach-Object { $_ }) -join "; " } else { "" }

            $rows += [PSCustomObject]@{
                IdentityType         = if ($identity.AccountUpn) { "User" } else { "ServicePrincipalOrApp" }
                AccountUPN           = $identity.AccountUpn
                DisplayName          = $identity.AccountDisplayName
                AccountObjectId      = $identity.AccountObjectId
                Department           = $identity.Department
                JobTitle             = $identity.JobTitle
                IsAccountEnabled     = $identity.IsAccountEnabled
                AssignedEntraRoles   = $rolesStr
                EntraGroupMembership = $groupsStr
                RiskLevel            = $identity.RiskLevel
                BlastRadius          = $identity.BlastRadius
                IdentityEnvironment  = $identity.IdentityEnvironment
                ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        Export-Results -Data $rows -FileName "6_DefenderXDR_Identity_Role_Query" -Format $ExportFormat
    }
    catch {
        Write-Warn "Defender XDR Advanced Hunting section failed. Error: $_"
    }

    return $rows
}

function Export-ServicePrincipalSecurityPermissions {
    Write-Header "7/7 Service Principals & App Registrations - Security Permissions"

    $rows = @()

    $sensitiveApiPermissions = @(
        "RoleManagement.Read.All",
        "RoleManagement.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read.All",
        "Group.Read.All",
        "Application.Read.All",
        "Application.ReadWrite.All",
        "AppRoleAssignment.Read.All",
        "PrivilegedAccess.Read.AzureADGroup",
        "PrivilegedAccess.ReadWrite.AzureADGroup",
        "AdvancedHunting.Read.All",
        "SecurityEvents.Read.All",
        "SecurityEvents.ReadWrite.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "IdentityRiskyUser.Read.All",
        "IdentityRiskEvent.Read.All",
        "Exchange.ManageAsApp"
    )

    try {
        $allSPs = Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId,ServicePrincipalType,AppRoles" -ErrorAction Stop
        Write-OK "Found $(@($allSPs).Count) service principal(s)."

        foreach ($role in (Get-MgDirectoryRole -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -in $TargetRoleNames })) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue

            foreach ($m in $members) {
                $odataType = ($m.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", "")

                if ($odataType -eq "servicePrincipal") {
                    $sp = $allSPs | Where-Object { $_.Id -eq $m.Id } | Select-Object -First 1

                    if ($sp) {
                        $rows += [PSCustomObject]@{
                            SPDisplayName    = $sp.DisplayName
                            AppId            = $sp.AppId
                            SPType           = $sp.ServicePrincipalType
                            PermissionSource = "Entra Role"
                            Permission       = $role.DisplayName
                            PermissionScope  = "Entra ID"
                            IsRunningApp     = if ($sp.AppId -eq $script:AppClientId) { "YES - THIS IS THE APP RUNNING THE SCRIPT" } else { "" }
                            ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
            }
        }

        $graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property "Id,AppRoles" -ErrorAction SilentlyContinue
        $exoSP   = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'" -Property "Id,AppRoles" -ErrorAction SilentlyContinue
        $mtpSP   = Get-MgServicePrincipal -Filter "appId eq '8ee8fdad-f234-4243-8f3b-15c294843740'" -Property "Id,AppRoles" -ErrorAction SilentlyContinue

        $roleLookup = @{}

        foreach ($resourceSp in @($graphSP, $exoSP, $mtpSP)) {
            if ($resourceSp) {
                foreach ($r in $resourceSp.AppRoles) {
                    $roleLookup[$r.Id.ToString()] = $r.Value
                }
            }
        }

        foreach ($sp in $allSPs) {
            try {
                $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue

                foreach ($a in $assignments) {
                    $permName = $null

                    if ($roleLookup.ContainsKey($a.AppRoleId.ToString())) {
                        $permName = $roleLookup[$a.AppRoleId.ToString()]
                    }

                    if ($permName -and $permName -in $sensitiveApiPermissions) {
                        $rows += [PSCustomObject]@{
                            SPDisplayName    = $sp.DisplayName
                            AppId            = $sp.AppId
                            SPType           = $sp.ServicePrincipalType
                            PermissionSource = "API Permission (Application)"
                            Permission       = $permName
                            PermissionScope  = "Microsoft Graph / Exchange Online / MTP"
                            IsRunningApp     = if ($sp.AppId -eq $script:AppClientId) { "YES - THIS IS THE APP RUNNING THE SCRIPT" } else { "" }
                            ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
            }
            catch {
                # Continue scanning other service principals.
            }
        }

        if (-not ($rows | Where-Object { $_.IsRunningApp -eq "YES - THIS IS THE APP RUNNING THE SCRIPT" })) {
            Write-Warn "Running App Registration ($script:AppClientId) was not flagged in the service principal output."
        }

        Export-Results -Data $rows -FileName "7_ServicePrincipal_SecurityPermissions" -Format $ExportFormat
    }
    catch {
        Write-Error "Section 7 failed: $_"
    }

    return $rows
}

# =============================================================================
# Main export function
# =============================================================================

function Invoke-RoleAssignmentExport {
    Write-Header "Microsoft Security Stack - Role Assignments Export"

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-OK "Output folder created: $OutputPath"
    }

    Initialize-RequiredModules
    Initialize-AuthenticationInputs
    Connect-AllRequiredServices

    $entraRows   = Export-EntraDirectoryRoles
    $pimRows     = Export-PimEligibleRoles
    $sentinelRows = Export-SentinelWorkspaceRbac
    $mdcResult   = Export-DefenderForCloudRbac
    $purviewRows = Export-PurviewRoleGroups
    $xdrRows     = Export-DefenderXdrIdentityRoleQuery
    $spRows      = Export-ServicePrincipalSecurityPermissions

    Write-Header "Export Complete"

    $files = Get-ChildItem -Path $OutputPath -File -ErrorAction SilentlyContinue

    $manifest = [PSCustomObject]@{
        ExportTimestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        TenantId                = $script:TenantId
        AppClientId             = $script:AppClientId
        Organization            = $script:Organization
        CertificateThumbprint   = $script:AuthCertificate.Thumbprint
        AuthenticationModel     = "Single app registration + certificate-based app-only authentication"
        PromptModel             = if ($NonInteractiveStrict) { "Fully non-interactive; fail if required values are missing" } else { "Prompt only for missing initial auth values, then continue without browser sign-in" }
        TargetRoleNames         = ($TargetRoleNames -join "; ")
        SentinelWorkspaceCount  = $SentinelWorkspaces.Count
        IncludedPIM             = $IncludePIM.IsPresent
        ScannedDefenderForCloud = $ScanDefenderForCloud.IsPresent
        IncludedPurview         = $IncludePurview.IsPresent
        IncludedXDRRBAC         = $IncludeXDRRBAC.IsPresent
        EntraRoleRows           = @($entraRows).Count
        PimRoleRows             = @($pimRows).Count
        SentinelRows            = @($sentinelRows).Count
        DefenderForCloudScanRows = @($mdcResult.ScanRows).Count
        DefenderForCloudRbacRows = @($mdcResult.RbacRows).Count
        PurviewRows             = @($purviewRows).Count
        DefenderXdrRows         = @($xdrRows).Count
        ServicePrincipalRows    = @($spRows).Count
        FilesGenerated          = @($files).Count
    }

    $manifest | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputPath "00_ExportManifest.json") -Encoding UTF8
    Write-OK "Manifest written -> 00_ExportManifest.json"

    Write-Host ""
    Write-Host "Files written to: $OutputPath" -ForegroundColor Cyan

    foreach ($f in $files) {
        Write-Host "  $($f.Name) ($([math]::Round($f.Length / 1KB, 1)) KB)" -ForegroundColor White
    }

    try {
        if ($IncludePurview) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {}

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}

    try {
        if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {}

    Write-OK "All sessions disconnected."
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}

# =============================================================================
# Script controller
# =============================================================================

try {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $script:RunInstructions = Get-MenuRunInstructions -ScriptName ".\Get-RoleAssignments-Guided.ps1"

    if ($ShowRunInstructions -or $ShowRunInstructionsOnly) {
        Show-HowToRunLayer -Instructions $script:RunInstructions | Out-Null
    }

    if ($ExportRunInstructions) {
        $runInstructionPath = Join-Path $OutputPath "00_RunInstructions.json"
        $script:RunInstructions | ConvertTo-Json -Depth 12 | Out-File $runInstructionPath -Encoding UTF8
        Write-OK "Run instructions exported -> $runInstructionPath"
    }

    if ($ShowRunInstructionsOnly) {
        return
    }

    if ($RunExportNow -or $NonInteractiveStrict) {
        Invoke-RoleAssignmentExport
        return
    }

    # Default behavior: guided start menu unless direct execution is requested.
    while ($true) {
        $menuResult = Start-GuidedStartMenu -Instructions $script:RunInstructions -OutputPath $OutputPath

        switch ($menuResult) {
            "RunExport" {
                Invoke-RoleAssignmentExport

                Write-Host ""
                Write-Host "Export completed." -ForegroundColor Green
                Write-Host ""
                Write-Host "Next action:" -ForegroundColor Yellow
                Write-Host "  R. Return to start menu"
                Write-Host "  E. End"
                Write-Host ""

                while ($true) {
                    $postExportChoice = (Read-Host "Select R or E").Trim().ToUpperInvariant()

                    switch ($postExportChoice) {
                        "R" { break }
                        "E" { return }
                        default { Write-Warn "Invalid selection. Enter R or E." }
                    }

                    if ($postExportChoice -eq "R") {
                        break
                    }
                }
            }

            "End" {
                Write-Host ""
                Write-Host "No export was run. Exiting." -ForegroundColor Yellow
                return
            }

            default {
                Write-Host ""
                Write-Host "No export was run. Exiting." -ForegroundColor Yellow
                return
            }
        }
    }
}
catch {
    Write-Host ""
    Write-Host "Script stopped because of an error:" -ForegroundColor Red
    Write-Host $_ -ForegroundColor Red
    exit 1
}
