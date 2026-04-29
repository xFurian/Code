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
#Requires -Version 5.1
# =============================================================================
# Get-RoleAssignments.ps1  v3.0
# Exports role assignments from: Entra ID, PIM, Sentinel, Defender for Cloud,
#   Purview, Defender XDR, and Service Principals
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Array of Sentinel workspace definitions.")]
    [hashtable[]]$SentinelWorkspaces = @(),

    [Parameter(HelpMessage = "Output folder path.")]
    [string]$OutputPath = ".\RoleAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(HelpMessage = "Export format: CSV, JSON, or Both.")]
    [ValidateSet("CSV","JSON","Both")]
    [string]$ExportFormat = "Both",

    [Parameter(HelpMessage = "Include PIM eligible role assignments.")]
    [switch]$IncludePIM,

    [Parameter(HelpMessage = "Scan all accessible subscriptions for Defender for Cloud RBAC.")]
    [switch]$ScanDefenderForCloud,

    [Parameter(HelpMessage = "Export Purview compliance role groups and members.")]
    [switch]$IncludePurview,

    [Parameter(HelpMessage = "Certificate thumbprint for app-only Purview connection.")]
    [string]$PurviewCertThumbprint,

    [Parameter(HelpMessage = "Tenant primary domain for Purview app-only auth.")]
    [string]$PurviewOrganization,

    [Parameter(HelpMessage = "Export full XDR RBAC via Advanced Hunting.")]
    [switch]$IncludeXDRRBAC,

    [Parameter(HelpMessage = "App Registration Client ID.")]
    [string]$AppClientId,

    [Parameter(HelpMessage = "App Registration Client Secret VALUE.")]
    [string]$AppClientSecret,

    [Parameter(HelpMessage = "Tenant ID for the App Registration.")]
    [string]$AppTenantId,

    [Parameter(HelpMessage = "Tenant ID used for Graph and Az connections.")]
    [string]$TenantId = ""
)

# =============================================================================
# Helpers
# =============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 65) -ForegroundColor Cyan
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

function Export-Results {
    param([object[]]$Data, [string]$FileName, [string]$Format)
    $DataArray = @($Data)
    if ($DataArray.Count -eq 0) { Write-Warn "No data to export for: $FileName"; return }
    if ($Format -in @("CSV","Both")) {
        $DataArray | Export-Csv -Path "$OutputPath\$FileName.csv" -NoTypeInformation -Encoding UTF8
        Write-OK "Exported $($DataArray.Count) rows -> $FileName.csv"
    }
    if ($Format -in @("JSON","Both")) {
        $DataArray | ConvertTo-Json -Depth 10 | Out-File "$OutputPath\$FileName.json" -Encoding UTF8
        Write-OK "Exported $($DataArray.Count) rows -> $FileName.json"
    }
}

function Invoke-MgWithRetry {
    param([scriptblock]$Command, [int]$MaxRetries = 5)
    for ($i = 0; $i -lt $MaxRetries; $i++) {
        try { return (& $Command) }
        catch {
            if ($_.ToString() -match "429|throttl") {
                $wait = [math]::Pow(2, $i)
                Write-Warn "Graph throttled -- waiting ${wait}s (attempt $($i+1)/$MaxRetries)"
                Start-Sleep -Seconds $wait
            }
            else { throw }
        }
    }
}

function Build-AccessPath {
    param(
        [string]$RoleName,
        [string]$AssignmentType,
        [string]$GroupName = "",
        [string]$Scope = ""
    )
    switch ($AssignmentType) {
        "Direct"                   { return "Direct Entra role assignment: $RoleName" }
        "Group"                    { return "Member of group '$GroupName' which holds Entra role: $RoleName" }
        "PIM-Eligible"             { return "PIM-Eligible for Entra role: $RoleName" }
        "PIM-Active"               { return "PIM-Active (currently activated) for Entra role: $RoleName" }
        "PIM-Eligible (via Group)" { return "PIM-Eligible via group '$GroupName' which holds Entra role: $RoleName" }
        "PIM-Active (via Group)"   { return "PIM-Active via group '$GroupName' which holds Entra role: $RoleName" }
        "Azure RBAC"               { return "Azure RBAC role '$RoleName' at scope: $Scope" }
        "API Permission"           { return "Application API permission: $RoleName (Microsoft Graph / MTP)" }
        default                    { return "${AssignmentType}: $RoleName" }
    }
}

function Get-PimGroupAllMembers {
    param([string]$GroupId, [string]$GroupDisplayName)
    $results = @()

    try {
        $uri      = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$GroupId'"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        $schedules = @($response.value)
        while ($response.'@odata.nextLink') {
            $response  = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -ErrorAction SilentlyContinue
            $schedules += $response.value
        }
        foreach ($s in $schedules) {
            if ($s.accessId -and $s.accessId -ne "member") { continue }
            $u = Invoke-MgWithRetry {
                Get-MgUser -UserId $s.principalId `
                    -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" `
                    -ErrorAction SilentlyContinue
            }
            if ($u) {
                $results += [PSCustomObject]@{
                    MemberDisplayName = $u.DisplayName
                    MemberUPN         = $u.UserPrincipalName
                    MemberMail        = $u.Mail
                    AccountEnabled    = $u.AccountEnabled
                    Department        = $u.Department
                    JobTitle          = $u.JobTitle
                    PimMemberType     = "PIM-Eligible"
                    ScheduleExpiry    = $s.scheduleInfo.expiration.endDateTime
                    ExpiryType        = $s.scheduleInfo.expiration.type
                }
            }
            else { Write-Warn "    PrincipalId $($s.principalId) is not a user -- skipping" }
        }
        Write-OK "    PIM eligible members '$GroupDisplayName': $($results.Count)"
    }
    catch {
        Write-Warn "    Could not query eligibilitySchedules for '$GroupDisplayName': $_"
    }

    try {
        $uri2      = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$GroupId'"
        $response2 = Invoke-MgGraphRequest -Method GET -Uri $uri2 -ErrorAction SilentlyContinue
        $instances = @($response2.value)
        while ($response2.'@odata.nextLink') {
            $response2  = Invoke-MgGraphRequest -Method GET -Uri $response2.'@odata.nextLink' -ErrorAction SilentlyContinue
            $instances += $response2.value
        }
        $activeCount = 0
        foreach ($inst in $instances) {
            if ($inst.accessId -and $inst.accessId -ne "member") { continue }
            $u = Invoke-MgWithRetry {
                Get-MgUser -UserId $inst.principalId `
                    -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" `
                    -ErrorAction SilentlyContinue
            }
            if ($u) {
                $alreadyIn = $results | Where-Object { $_.MemberUPN -eq $u.UserPrincipalName }
                if (-not $alreadyIn) {
                    $results += [PSCustomObject]@{
                        MemberDisplayName = $u.DisplayName
                        MemberUPN         = $u.UserPrincipalName
                        MemberMail        = $u.Mail
                        AccountEnabled    = $u.AccountEnabled
                        Department        = $u.Department
                        JobTitle          = $u.JobTitle
                        PimMemberType     = "PIM-Active"
                        ScheduleExpiry    = $inst.endDateTime
                        ExpiryType        = $inst.assignmentType
                    }
                    $activeCount++
                }
            }
        }
        Write-OK "    PIM active members '$GroupDisplayName': $activeCount (new unique)"
    }
    catch {
        Write-Warn "    Could not query assignmentScheduleInstances for '$GroupDisplayName': $_"
    }

    return $results
}

# =============================================================================
# WinForms Credential Popup
# =============================================================================

function Show-CredentialDialog {
    param(
        [string]$InitialClientId = "",
        [string]$InitialTenantId = ""
    )

    $winFormsAvailable = $false
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $winFormsAvailable = $true
    }
    catch { Write-Warn "WinForms unavailable -- falling back to Read-Host." }

    if (-not $winFormsAvailable) {
        $cid = if ($InitialClientId) { $InitialClientId } else { Read-Host "  Enter App Registration Client ID" }
        $sec = Read-Host "  Enter Client Secret VALUE (not the Secret ID)" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        $secretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $tid = if ($InitialTenantId) { $InitialTenantId } else { Read-Host "  Enter Tenant ID" }
        return [PSCustomObject]@{ ClientId=$cid; ClientSecret=$secretPlain; TenantId=$tid; Cancelled=$false }
    }

    $form                 = New-Object System.Windows.Forms.Form
    $form.Text            = "Get-RoleAssignments v3.0 -- App Registration Credentials"
    $form.Size            = New-Object System.Drawing.Size(540,340)
    $form.StartPosition   = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.TopMost         = $true
    $form.BackColor       = [System.Drawing.Color]::FromArgb(30,30,30)
    $form.ForeColor       = [System.Drawing.Color]::White
    $form.Font            = New-Object System.Drawing.Font("Segoe UI",9)

    function New-Label($Text,$X,$Y,$W=480,$H=18){
        $l = New-Object System.Windows.Forms.Label
        $l.Text=$Text; $l.Location=New-Object System.Drawing.Point($X,$Y)
        $l.Size=New-Object System.Drawing.Size($W,$H)
        $l.ForeColor=[System.Drawing.Color]::FromArgb(180,180,180)
        return $l
    }

    function New-TextBox($Default,$X,$Y,$W=480,$Password=$false){
        $t = New-Object System.Windows.Forms.TextBox
        $t.Text=$Default
        $t.Location=New-Object System.Drawing.Point($X,$Y)
        $t.Size=New-Object System.Drawing.Size($W,24)
        $t.BackColor=[System.Drawing.Color]::FromArgb(50,50,50)
        $t.ForeColor=[System.Drawing.Color]::White
        $t.BorderStyle="FixedSingle"
        $t.Font=New-Object System.Drawing.Font("Consolas",9)
        if($Password){ $t.PasswordChar='*' }
        return $t
    }

    $lbl1      = New-Label "App Registration Client ID (GUID)" 24 18
    $txtClient = New-TextBox $InitialClientId 24 40

    $lbl2      = New-Label "Client Secret VALUE  (input is masked  --  NOT the Secret ID GUID)" 24 80
    $txtSecret = New-TextBox "" 24 102 480 $true

    $lbl2b = New-Object System.Windows.Forms.Label
    $lbl2b.Text = "The Secret ID is a GUID. The Secret VALUE is a random string shown once at creation."
    $lbl2b.Location = New-Object System.Drawing.Point(24,130)
    $lbl2b.Size = New-Object System.Drawing.Size(480,18)
    $lbl2b.ForeColor = [System.Drawing.Color]::FromArgb(200,100,100)
    $lbl2b.Font = New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Italic)

    $chkShow = New-Object System.Windows.Forms.CheckBox
    $chkShow.Text="Show secret"
    $chkShow.Location=New-Object System.Drawing.Point(24,152)
    $chkShow.Size=New-Object System.Drawing.Size(120,20)
    $chkShow.ForeColor=[System.Drawing.Color]::FromArgb(140,180,255)
    $chkShow.Add_CheckedChanged({
        $txtSecret.PasswordChar = if($chkShow.Checked){ [char]0 } else { '*' }
    })

    $lbl3      = New-Label "Tenant ID  (GUID  or  contoso.onmicrosoft.com)" 24 182
    $txtTenant = New-TextBox $InitialTenantId 24 204

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text="Connect"
    $btnOK.Location=New-Object System.Drawing.Point(328,260)
    $btnOK.Size=New-Object System.Drawing.Size(84,28)
    $btnOK.BackColor=[System.Drawing.Color]::FromArgb(0,120,212)
    $btnOK.ForeColor=[System.Drawing.Color]::White
    $btnOK.FlatStyle="Flat"
    $btnOK.DialogResult=[System.Windows.Forms.DialogResult]::OK
    $btnOK.Add_Click({
        $missing=@()
        if([string]::IsNullOrWhiteSpace($txtClient.Text)){ $missing+="Client ID" }
        if([string]::IsNullOrWhiteSpace($txtSecret.Text)){ $missing+="Client Secret" }
        if([string]::IsNullOrWhiteSpace($txtTenant.Text)){ $missing+="Tenant ID" }
        if($missing.Count -gt 0){
            [System.Windows.Forms.MessageBox]::Show(
                "Required fields missing:`n`n  - $($missing -join "`n  - ")",
                "Validation",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            $form.DialogResult=[System.Windows.Forms.DialogResult]::None
        }
    })

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text="Cancel"
    $btnCancel.Location=New-Object System.Drawing.Point(424,260)
    $btnCancel.Size=New-Object System.Drawing.Size(84,28)
    $btnCancel.BackColor=[System.Drawing.Color]::FromArgb(60,60,60)
    $btnCancel.ForeColor=[System.Drawing.Color]::White
    $btnCancel.FlatStyle="Flat"
    $btnCancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel

    $form.AcceptButton=$btnOK
    $form.CancelButton=$btnCancel
    $form.Controls.AddRange(@(
        $lbl1,$txtClient,
        $lbl2,$txtSecret,$lbl2b,$chkShow,
        $lbl3,$txtTenant,
        $btnOK,$btnCancel
    ))

    $result=$form.ShowDialog()
    $form.Dispose()

    if($result -ne [System.Windows.Forms.DialogResult]::OK){
        return [PSCustomObject]@{ ClientId=""; ClientSecret=""; TenantId=""; Cancelled=$true }
    }
    return [PSCustomObject]@{
        ClientId     = $txtClient.Text.Trim()
        ClientSecret = $txtSecret.Text
        TenantId     = $txtTenant.Text.Trim()
        Cancelled    = $false
    }
}

# =============================================================================
# Module Setup
# =============================================================================

Write-Header "Microsoft Security Stack - Role Assignments Export v3.0"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-OK "Output folder: $OutputPath"
}

$requiredModules = @(
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.Governance",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Applications"
)
if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) { $requiredModules += "Az.Accounts","Az.Resources" }
if ($ScanDefenderForCloud) { $requiredModules += "Az.Security" }
if ($IncludePurview)       { $requiredModules += "ExchangeOnlineManagement" }
$requiredModules = $requiredModules | Sort-Object -Unique

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Step "Installing: $mod"
        try { Install-Module $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop; Write-OK "Installed: $mod" }
        catch { Write-Error "Failed to install $mod"; exit 1 }
    }
    if (-not (Get-Module -Name $mod)) {
        try { Import-Module $mod -Force -ErrorAction Stop; Write-OK "Imported: $mod" }
        catch { Write-Error "Failed to import $mod : $_"; exit 1 }
    }
    else { Write-OK "Already loaded: $mod" }
}

# =============================================================================
# AUTH — Microsoft Graph
# =============================================================================

Write-Header "Auth  Microsoft Graph"
Write-Step "Connecting to Microsoft Graph..."

try {
    $mgCtx = Get-MgContext

    if (-not $mgCtx) {
        $needsDialog = (
            [string]::IsNullOrWhiteSpace($AppClientId) -or
            [string]::IsNullOrWhiteSpace($AppClientSecret) -or
            ([string]::IsNullOrWhiteSpace($AppTenantId) -and [string]::IsNullOrWhiteSpace($TenantId))
        )

        if ($needsDialog) {
            Write-Step "Credentials missing -- showing credential dialog..."
            $preId     = if (-not [string]::IsNullOrWhiteSpace($AppClientId))  { $AppClientId }  else { "" }
            $preTenant = if (-not [string]::IsNullOrWhiteSpace($AppTenantId))  { $AppTenantId }
                         elseif (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId }
                         else { "" }

            $creds = Show-CredentialDialog -InitialClientId $preId -InitialTenantId $preTenant

            if ($creds.Cancelled) { Write-Error "Credential dialog cancelled."; exit 1 }

            if (-not [string]::IsNullOrWhiteSpace($creds.ClientId))     { $AppClientId     = $creds.ClientId }
            if (-not [string]::IsNullOrWhiteSpace($creds.ClientSecret))  { $AppClientSecret = $creds.ClientSecret }
            if (-not [string]::IsNullOrWhiteSpace($creds.TenantId))      { $AppTenantId     = $creds.TenantId }
        }

        $resolvedTenant = if (-not [string]::IsNullOrWhiteSpace($AppTenantId))  { $AppTenantId }
                          elseif (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId }
                          else { $null }

        if ([string]::IsNullOrWhiteSpace($resolvedTenant)) { Write-Error "TenantId could not be resolved."; exit 1 }

        $tokenBody = @{
            grant_type    = "client_credentials"
            client_id     = $AppClientId
            client_secret = $AppClientSecret
            scope         = "https://graph.microsoft.com/.default"
        }

        Write-Step "Requesting access token..."
        $tokenResponse = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$resolvedTenant/oauth2/v2.0/token" `
            -Body $tokenBody -ErrorAction Stop

        Connect-MgGraph `
            -AccessToken ($tokenResponse.access_token | ConvertTo-SecureString -AsPlainText -Force) `
            -NoWelcome -ErrorAction Stop

        $mgCtx = Get-MgContext
        Write-OK "Connected to Microsoft Graph (App: $AppClientId)"
    }
    else { Write-OK "Reusing existing Graph session (App: $($mgCtx.ClientId))" }

    $TenantId = $mgCtx.TenantId
    Write-OK "Resolved TenantId: $TenantId"
}
catch { Write-Error "Graph connection failed: $_"; exit 1 }

# =============================================================================
# AUTH — Azure (Sections 3, 4, 7b)
# =============================================================================

if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
    Write-Step "Connecting to Azure (SP auth)..."
    try {
        $azCtx = Get-AzContext -ErrorAction SilentlyContinue
        if ($azCtx) { Disconnect-AzAccount -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
        $azSec  = ConvertTo-SecureString -String $AppClientSecret -AsPlainText -Force
        $azCred = New-Object System.Management.Automation.PSCredential($AppClientId,$azSec)
        Connect-AzAccount -TenantId $TenantId -ServicePrincipal -Credential $azCred -ErrorAction Stop | Out-Null
        Write-OK "Connected to Azure (App: $AppClientId)"
    }
    catch { Write-Error "Az connection failed: $_"; exit 1 }
}
# =============================================================================
# SECTION 1: Entra ID -- ALL role assignments
# =============================================================================

Write-Header "1/7  Entra ID - All Role Assignments (unifiedRoleAssignment)"

$targetEntraRoles = @(
    "Global Administrator",
    "Security Administrator",
    "Security Operator",
    "Security Reader",
    "Global Reader",
    "Compliance Administrator",
    "Compliance Data Administrator",
    "Information Protection Administrator",
    "Helpdesk Administrator",
    "Intune Administrator",
    "Attack Simulation Administrator",
    "Cloud App Security Administrator",
    "Cloud Device Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "Microsoft Sentinel Contributor",
    "Microsoft Sentinel Reader",
    "Microsoft Sentinel Responder"
)

$entraRoleAssignments = @()

Write-Step "Building role definition lookup..."
$allRoleDefinitions = @{}
try {
    $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
    foreach ($rd in $roleDefs) { $allRoleDefinitions[$rd.Id] = $rd }
    Write-OK "Loaded $($allRoleDefinitions.Count) role definition(s)"
}
catch { Write-Warn "Could not load role definitions: $_" }

try {
    Write-Step "Querying Get-MgRoleManagementDirectoryRoleAssignment -All..."
    $allAssignments = Invoke-MgWithRetry {
        Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty "principal" -ErrorAction Stop
    }
    Write-OK "Total raw assignments: $($allAssignments.Count)"

    $filteredAssignments = $allAssignments | Where-Object {
        $rd = $allRoleDefinitions[$_.RoleDefinitionId]
        $rd -and ($rd.DisplayName -in $targetEntraRoles)
    }
    Write-OK "Assignments after role filter: $($filteredAssignments.Count)"

    foreach ($assignment in $filteredAssignments) {
        $rd          = $allRoleDefinitions[$assignment.RoleDefinitionId]
        $roleName    = if ($rd) { $rd.DisplayName } else { $assignment.RoleDefinitionId }
        $roleDesc    = if ($rd) { $rd.Description } else { "" }
        $principalId = $assignment.PrincipalId
        $principal   = $assignment.Principal
        $odataType   = ""

        if ($principal -and $principal.AdditionalProperties) {
            $odataType = ($principal.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.","")
        }

        if ([string]::IsNullOrWhiteSpace($odataType)) {
            $tryUser = Invoke-MgWithRetry { Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue }
            if ($tryUser) { $odataType = "user" }
            else {
                $tryGroup = Invoke-MgWithRetry { Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue }
                if ($tryGroup) { $odataType = "group" } else { $odataType = "servicePrincipal" }
            }
        }

        try {
            switch ($odataType) {

                "user" {
                    $u = Invoke-MgWithRetry {
                        Get-MgUser -UserId $principalId `
                            -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,Department,JobTitle" `
                            -ErrorAction SilentlyContinue
                    }
                    $entraRoleAssignments += [PSCustomObject]@{
                        RoleName          = $roleName
                        RoleId            = $assignment.RoleDefinitionId
                        RoleDescription   = $roleDesc
                        MemberType        = "User"
                        MemberDisplayName = $u.DisplayName
                        MemberUPN         = $u.UserPrincipalName
                        MemberMail        = $u.Mail
                        MemberDepartment  = $u.Department
                        MemberJobTitle    = $u.JobTitle
                        AccountEnabled    = $u.AccountEnabled
                        UserType          = $u.UserType
                        MemberId          = $principalId
                        AssignmentType    = "Active"
                        AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "Direct"
                        ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

                "group" {
                    $g = Invoke-MgWithRetry {
                        Get-MgGroup -GroupId $principalId -Property "DisplayName,Mail,GroupTypes" -ErrorAction SilentlyContinue
                    }
                    $groupName = $g.DisplayName

                    $entraRoleAssignments += [PSCustomObject]@{
                        RoleName          = $roleName
                        RoleId            = $assignment.RoleDefinitionId
                        RoleDescription   = $roleDesc
                        MemberType        = "Group"
                        MemberDisplayName = $groupName
                        MemberUPN         = $g.Mail
                        MemberMail        = $g.Mail
                        MemberDepartment  = ""
                        MemberJobTitle    = ""
                        AccountEnabled    = $true
                        UserType          = "Group"
                        MemberId          = $principalId
                        AssignmentType    = "Active"
                        AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "Direct"
                        ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }

                    $directMembers = Invoke-MgWithRetry {
                        Get-MgGroupMember -GroupId $principalId -All -ErrorAction SilentlyContinue
                    }
                    foreach ($dm in $directMembers) {
                        $dmType = $dm.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.",""
                        if ($dmType -eq "user") {
                            $du = Invoke-MgWithRetry {
                                Get-MgUser -UserId $dm.Id `
                                    -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" `
                                    -ErrorAction SilentlyContinue
                            }
                            $entraRoleAssignments += [PSCustomObject]@{
                                RoleName          = $roleName
                                RoleId            = $assignment.RoleDefinitionId
                                RoleDescription   = $roleDesc
                                MemberType        = "User (via Group: $groupName)"
                                MemberDisplayName = $du.DisplayName
                                MemberUPN         = $du.UserPrincipalName
                                MemberMail        = $du.Mail
                                MemberDepartment  = $du.Department
                                MemberJobTitle    = $du.JobTitle
                                AccountEnabled    = $du.AccountEnabled
                                UserType          = "User"
                                MemberId          = $dm.Id
                                AssignmentType    = "Active"
                                AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "Group" -GroupName $groupName
                                ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            }
                        }
                    }

                    Write-Step "  PIM-for-Groups check: $groupName"
                    $pimMembers = Get-PimGroupAllMembers -GroupId $principalId -GroupDisplayName $groupName
                    foreach ($pgm in $pimMembers) {
                        $assignType = if ($pgm.PimMemberType -eq "PIM-Active") { "PIM-Active (via Group)" } else { "PIM-Eligible (via Group)" }
                        $entraRoleAssignments += [PSCustomObject]@{
                            RoleName          = $roleName
                            RoleId            = $assignment.RoleDefinitionId
                            RoleDescription   = $roleDesc
                            MemberType        = "$($pgm.PimMemberType) via Group: $groupName"
                            MemberDisplayName = $pgm.MemberDisplayName
                            MemberUPN         = $pgm.MemberUPN
                            MemberMail        = $pgm.MemberMail
                            MemberDepartment  = $pgm.Department
                            MemberJobTitle    = $pgm.JobTitle
                            AccountEnabled    = $pgm.AccountEnabled
                            UserType          = "User"
                            MemberId          = ""
                            AssignmentType    = $assignType
                            AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType $assignType -GroupName $groupName
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }

                "servicePrincipal" {
                    $spName = if ($principal.AdditionalProperties["displayName"]) { $principal.AdditionalProperties["displayName"] } else { $principalId }
                    $entraRoleAssignments += [PSCustomObject]@{
                        RoleName          = $roleName
                        RoleId            = $assignment.RoleDefinitionId
                        RoleDescription   = $roleDesc
                        MemberType        = "ServicePrincipal"
                        MemberDisplayName = $spName
                        MemberUPN         = ""
                        MemberMail        = ""
                        MemberDepartment  = ""
                        MemberJobTitle    = ""
                        AccountEnabled    = $true
                        UserType          = "ServicePrincipal"
                        MemberId          = $principalId
                        AssignmentType    = "Active"
                        AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "Direct"
                        ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

                default { Write-Warn "Unknown principal type '$odataType' for $principalId" }
            }
        }
        catch { Write-Warn "Could not resolve principal $principalId : $_" }
    }

    Export-Results -Data $entraRoleAssignments -FileName "1_Entra_Security_Roles" -Format $ExportFormat
}
catch { Write-Error "Failed to retrieve Entra ID role assignments: $_" }

# =============================================================================
# SECTION 2: PIM Eligible Assignments
# =============================================================================

if ($IncludePIM) {
    Write-Header "2/7  Entra ID - PIM Eligible Role Assignments"
    $pimAssignments = @()

    try {
        $eligibleAssignments = Invoke-MgWithRetry {
            Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
        }
        Write-OK "Total PIM eligible: $($eligibleAssignments.Count). Filtering..."

        foreach ($assignment in $eligibleAssignments) {
            $principalId = $assignment.PrincipalId
            $roleDefId   = $assignment.RoleDefinitionId
            $roleDef     = $allRoleDefinitions[$roleDefId]
            if (-not $roleDef -or $roleDef.DisplayName -notin $targetEntraRoles) { continue }
            $roleName = $roleDef.DisplayName

            $memberDisplayName = $principalId
            $memberUPN = ""; $memberMail = ""; $memberDept = ""; $memberType = "Unknown"

            $user = Invoke-MgWithRetry {
                Get-MgUser -UserId $principalId -Property "DisplayName,UserPrincipalName,Mail,Department" -ErrorAction SilentlyContinue
            }

            if ($user) {
                $memberDisplayName = $user.DisplayName; $memberUPN = $user.UserPrincipalName
                $memberMail = $user.Mail; $memberDept = $user.Department; $memberType = "User"

                $pimAssignments += [PSCustomObject]@{
                    RoleName          = $roleName; RoleId = $roleDefId
                    MemberType        = $memberType; MemberDisplayName = $memberDisplayName
                    MemberUPN         = $memberUPN; MemberMail = $memberMail; MemberDepartment = $memberDept
                    AssignmentType    = "PIM-Eligible"
                    AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "PIM-Eligible"
                    ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                    ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                    ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                    MembershipType    = $assignment.MemberType; Status = $assignment.Status
                    ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
            }
            else {
                $group = Invoke-MgWithRetry {
                    Get-MgGroup -GroupId $principalId -Property "DisplayName,Mail" -ErrorAction SilentlyContinue
                }

                if ($group) {
                    Write-Step "  PIM group: $($group.DisplayName)"
                    $directCount = 0
                    try {
                        $groupMembers = Invoke-MgWithRetry { Get-MgGroupMember -GroupId $principalId -All -ErrorAction SilentlyContinue }
                        foreach ($gm in $groupMembers) {
                            $odataType = $gm.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.",""
                            if ($odataType -eq "user") {
                                $u = Invoke-MgWithRetry {
                                    Get-MgUser -UserId $gm.Id -Property "DisplayName,UserPrincipalName,Mail,Department" -ErrorAction SilentlyContinue
                                }
                                $pimAssignments += [PSCustomObject]@{
                                    RoleName          = $roleName; RoleId = $roleDefId
                                    MemberType        = "User (via Group: $($group.DisplayName))"
                                    MemberDisplayName = $u.DisplayName; MemberUPN = $u.UserPrincipalName
                                    MemberMail        = $u.Mail; MemberDepartment = $u.Department
                                    AssignmentType    = "PIM-Eligible"
                                    AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "PIM-Eligible (via Group)" -GroupName $group.DisplayName
                                    ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                                    ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                                    ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                                    MembershipType    = $assignment.MemberType; Status = $assignment.Status
                                    ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                }
                                $directCount++
                            }
                        }
                        Write-OK "  Direct members '$($group.DisplayName)': $directCount"
                    }
                    catch { Write-Warn "  Could not expand '$($group.DisplayName)': $_" }

                    $pimGroupMembers = Get-PimGroupAllMembers -GroupId $principalId -GroupDisplayName $group.DisplayName
                    foreach ($pgm in $pimGroupMembers) {
                        $assignType = if ($pgm.PimMemberType -eq "PIM-Active") { "PIM-Active (via Group)" } else { "PIM-Eligible (via Group)" }
                        $pimAssignments += [PSCustomObject]@{
                            RoleName          = $roleName; RoleId = $roleDefId
                            MemberType        = $pgm.PimMemberType; MemberDisplayName = $pgm.MemberDisplayName
                            MemberUPN         = $pgm.MemberUPN; MemberMail = $pgm.MemberMail; MemberDepartment = $pgm.Department
                            AssignmentType    = $assignType
                            AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType $assignType -GroupName $group.DisplayName
                            ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                            ScheduleExpiry    = $pgm.ScheduleExpiry; ExpiryType = $pgm.ExpiryType
                            MembershipType    = $assignment.MemberType; Status = $assignment.Status
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    if ($directCount -eq 0 -and $pimGroupMembers.Count -eq 0) {
                        $pimAssignments += [PSCustomObject]@{
                            RoleName          = $roleName; RoleId = $roleDefId
                            MemberType        = "Group (no resolvable members)"; MemberDisplayName = $group.DisplayName
                            MemberUPN         = $group.Mail; MemberMail = $group.Mail; MemberDepartment = ""
                            AssignmentType    = "PIM-Eligible"
                            AccessPath        = "PIM-Eligible group '$($group.DisplayName)' holds '$roleName' -- no resolvable members"
                            ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                            ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                            ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                            MembershipType    = $assignment.MemberType; Status = $assignment.Status
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                    continue
                }
                else {
                    $sp = Invoke-MgWithRetry { Get-MgServicePrincipal -ServicePrincipalId $principalId -Property "DisplayName" -ErrorAction SilentlyContinue }
                    if ($sp) { $memberDisplayName = $sp.DisplayName; $memberType = "ServicePrincipal" }
                }

                $pimAssignments += [PSCustomObject]@{
                    RoleName          = $roleName; RoleId = $roleDefId
                    MemberType        = $memberType; MemberDisplayName = $memberDisplayName
                    MemberUPN         = $memberUPN; MemberMail = $memberMail; MemberDepartment = $memberDept
                    AssignmentType    = "PIM-Eligible"
                    AccessPath        = Build-AccessPath -RoleName $roleName -AssignmentType "PIM-Eligible"
                    ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                    ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                    ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                    MembershipType    = $assignment.MemberType; Status = $assignment.Status
                    ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
            }
        }

        Export-Results -Data $pimAssignments -FileName "2_EntraID_PIM_EligibleRoles" -Format $ExportFormat
    }
    catch { Write-Warn "PIM retrieval failed: $_" }
}
else { Write-Warn "PIM skipped. Use -IncludePIM to include." }
# =============================================================================
# SECTION 3: Microsoft Sentinel - Workspace RBAC
# =============================================================================

Write-Header "3/7  Microsoft Sentinel - Workspace RBAC"

if ($SentinelWorkspaces.Count -gt 0) {
    $sentinelRoleNames = @(
        "Microsoft Sentinel Contributor","Microsoft Sentinel Reader",
        "Microsoft Sentinel Responder","Microsoft Sentinel Automation Contributor",
        "Log Analytics Contributor","Log Analytics Reader"
    )
    $allSentinelRoles = @()
    $wsIndex = 0

    foreach ($ws in $SentinelWorkspaces) {
        $wsIndex++
        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) {
            Write-Warn "Workspace $wsIndex skipped -- missing required keys"; continue
        }
        $wsSubId = $ws.SubscriptionId; $wsRG = $ws.ResourceGroup; $wsId = $ws.WorkspaceId

        Write-Step "Workspace $wsIndex/$($SentinelWorkspaces.Count): $wsId"
        try {
            Set-AzContext -SubscriptionId $wsSubId -Tenant $TenantId -ErrorAction Stop | Out-Null

            $rgScope = "/subscriptions/$wsSubId/resourceGroups/$wsRG"
            $rgRoles = @(Get-AzRoleAssignment -Scope $rgScope -ErrorAction Stop |
                Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames } |
                ForEach-Object {[PSCustomObject]@{
                    WorkspaceId=$wsId; ResourceGroup=$wsRG; SubscriptionId=$wsSubId
                    RoleName=$_.RoleDefinitionName; PrincipalName=$_.DisplayName
                    PrincipalType=$_.ObjectType; SignInName=$_.SignInName; Scope=$_.Scope
                    ScopeLevel="ResourceGroup"
                    AccessPath=Build-AccessPath -RoleName $_.RoleDefinitionName -AssignmentType "Azure RBAC" -Scope $_.Scope
                    ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }})

            $wsResourceId = "/subscriptions/$wsSubId/resourceGroups/$wsRG/providers/Microsoft.OperationalInsights/workspaces/$wsId"
            $wsResourceRoles = @(Get-AzRoleAssignment -Scope $wsResourceId -ErrorAction SilentlyContinue |
                Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames -and $_.Scope -eq $wsResourceId } |
                ForEach-Object {[PSCustomObject]@{
                    WorkspaceId=$wsId; ResourceGroup=$wsRG; SubscriptionId=$wsSubId
                    RoleName=$_.RoleDefinitionName; PrincipalName=$_.DisplayName
                    PrincipalType=$_.ObjectType; SignInName=$_.SignInName; Scope=$_.Scope
                    ScopeLevel="WorkspaceResource"
                    AccessPath=Build-AccessPath -RoleName $_.RoleDefinitionName -AssignmentType "Azure RBAC" -Scope $_.Scope
                    ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }})

            $combined = $rgRoles + $wsResourceRoles
            Write-OK "Found $($combined.Count) assignment(s) for $wsId (RG: $($rgRoles.Count) | Resource: $($wsResourceRoles.Count))"
            $allSentinelRoles += $combined
        }
        catch { Write-Warn "Failed for $wsId : $_" }
    }

    Export-Results -Data $allSentinelRoles -FileName "3_Sentinel_Workspace_Roles" -Format $ExportFormat

    $sentinelSummary = $allSentinelRoles | Group-Object WorkspaceId | ForEach-Object {
        [PSCustomObject]@{
            WorkspaceId=$_.Name; ResourceGroup=$_.Group[0].ResourceGroup
            SubscriptionId=$_.Group[0].SubscriptionId; TotalRoles=$_.Count
            RoleBreakdown=($_.Group | Group-Object RoleName | ForEach-Object {"$($_.Name): $($_.Count)"}) -join " | "
        }
    }
    Export-Results -Data $sentinelSummary -FileName "3_Sentinel_Workspace_Summary" -Format $ExportFormat
    Write-OK "Total Sentinel assignments: $($allSentinelRoles.Count)"

    $sentinelPermissionActions = @(
        "Microsoft.SecurityInsights/*/read","Microsoft.SecurityInsights/*",
        "Microsoft.SecurityInsights/incidents/*","Microsoft.SecurityInsights/automationRules/*",
        "Microsoft.OperationalInsights/workspaces/*/read","Microsoft.OperationalInsights/workspaces/query/read",
        "Microsoft.OperationalInsights/workspaces/query/*/read","Microsoft.OperationalInsights/workspaces/savedSearches/*",
        "Microsoft.Insights/workbooks/*"
    )
    $customPermissionRows = @()

    foreach ($ws in $SentinelWorkspaces) {
        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) { continue }
        $wsSubId=$ws.SubscriptionId; $wsRG=$ws.ResourceGroup; $wsId=$ws.WorkspaceId
        try {
            Set-AzContext -SubscriptionId $wsSubId -Tenant $TenantId -ErrorAction Stop | Out-Null
            $rgScope="/subscriptions/$wsSubId/resourceGroups/$wsRG"
            $allAssignmentsAtScope = Get-AzRoleAssignment -Scope $rgScope -ErrorAction Stop

            foreach ($ra in $allAssignmentsAtScope) {
                if ($ra.RoleDefinitionName -in $sentinelRoleNames) { continue }
                try {
                    $roleDef = Get-AzRoleDefinition -Id $ra.RoleDefinitionId -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    if (-not $roleDef) { continue }
                    $allActions = @()
                    foreach ($perm in $roleDef.Permissions) {
                        if ($perm.Actions)     { $allActions += @($perm.Actions) }
                        if ($perm.DataActions) { $allActions += @($perm.DataActions) }
                    }
                    $matchedPermissions = @()
                    foreach ($targetAction in $sentinelPermissionActions) {
                        $pattern = "^" + [regex]::Escape($targetAction).Replace("\*",".*") + "$"
                        foreach ($action in $allActions) {
                            if ($action -match $pattern -and $matchedPermissions -notcontains $targetAction) { $matchedPermissions += $targetAction }
                        }
                        foreach ($action in $allActions) {
                            $ap = "^" + [regex]::Escape($action).Replace("\*",".*") + "$"
                            if ($targetAction -match $ap -and $matchedPermissions -notcontains $targetAction) { $matchedPermissions += $targetAction }
                        }
                    }
                    if ($matchedPermissions.Count -gt 0) {
                        $customPermissionRows += [PSCustomObject]@{
                            WorkspaceId=$wsId; ResourceGroup=$wsRG; SubscriptionId=$wsSubId
                            RoleName=$ra.RoleDefinitionName; RoleType=$roleDef.RoleType
                            PrincipalName=$ra.DisplayName; PrincipalType=$ra.ObjectType
                            SignInName=$ra.SignInName; Scope=$ra.Scope
                            MatchedPermissions=($matchedPermissions -join "; "); MatchedCount=$matchedPermissions.Count
                            AccessPath=Build-AccessPath -RoleName $ra.RoleDefinitionName -AssignmentType "Azure RBAC" -Scope $ra.Scope
                            ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
                catch { Write-Warn "  Could not inspect '$($ra.RoleDefinitionName)': $_" }
            }
        }
        catch { Write-Warn "  3b failed for $wsId : $_" }
    }
    Write-OK "3b - Found $($customPermissionRows.Count) role(s) with Sentinel permissions"
    Export-Results -Data $customPermissionRows -FileName "3b_Sentinel_CustomPermission_Assignments" -Format $ExportFormat
}
else { Write-Warn "Sentinel skipped. Use -SentinelWorkspaces to provide workspace definitions." }

# =============================================================================
# SECTION 4: Defender for Cloud - Subscription RBAC
# =============================================================================

Write-Header "4/7  Defender for Cloud - Subscription RBAC"

if ($ScanDefenderForCloud) {
    try {
        $mdcTargetRoles = @("Owner","Contributor","Security Admin","Security Reader")
        Write-Step "Enumerating subscriptions..."
        $allSubscriptions = Get-AzSubscription -ErrorAction Stop
        Write-OK "Found $($allSubscriptions.Count) subscription(s)"

        $mdcSubScan=@(); $mdcRbacRows=@()

        foreach ($sub in $allSubscriptions) {
            Write-Step "  [$($sub.Name)] ($($sub.Id))"
            try {
                Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null
                $pricingTiers = Get-AzSecurityPricing -ErrorAction SilentlyContinue
                $enabledPlans = @($pricingTiers | Where-Object { $_.PricingTier -eq "Standard" } | Select-Object -ExpandProperty Name)
                $isMDCEnabled = ($enabledPlans.Count -gt 0)

                $mdcSubScan += [PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; TenantId=$sub.TenantId
                    MDCEnabled=$isMDCEnabled; EnabledPlanCount=$enabledPlans.Count
                    EnabledPlans=($enabledPlans -join "; "); ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }

                if ($isMDCEnabled) {
                    Write-OK "  MDC ENABLED: $($sub.Name)"
                    $subScope="/subscriptions/$($sub.Id)"
                    $allRbac=Get-AzRoleAssignment -Scope $subScope -ErrorAction SilentlyContinue
                    $matched=0
                    foreach ($ra in $allRbac) {
                        if ($ra.RoleDefinitionName -notin $mdcTargetRoles) { continue }
                        $scopeLevel = switch -Wildcard ($ra.Scope) {
                            "/subscriptions/*/resourceGroups/*/providers/*" {"Resource"}
                            "/subscriptions/*/resourceGroups/*"             {"ResourceGroup"}
                            "/subscriptions/*"                              {"Subscription"}
                            "/providers/Microsoft.Management/*"             {"ManagementGroup"}
                            default                                         {"Other"}
                        }
                        $mdcRbacRows += [PSCustomObject]@{
                            SubscriptionId=$sub.Id; SubscriptionName=$sub.Name
                            MDCEnabledPlans=($enabledPlans -join "; "); RoleName=$ra.RoleDefinitionName
                            PrincipalName=$ra.DisplayName; PrincipalType=$ra.ObjectType
                            PrincipalId=$ra.ObjectId; SignInName=$ra.SignInName
                            Scope=$ra.Scope; ScopeLevel=$scopeLevel; CanDelegate=$ra.CanDelegate
                            AccessPath=Build-AccessPath -RoleName $ra.RoleDefinitionName -AssignmentType "Azure RBAC" -Scope $ra.Scope
                            ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                        $matched++
                    }
                    Write-OK "  Exported $matched role assignment(s)"
                }
                else { Write-Warn "  MDC not enabled: $($sub.Name)" }
            }
            catch { Write-Warn "  Could not process [$($sub.Name)]: $_" }
        }

        Export-Results -Data $mdcSubScan  -FileName "4_MDC_Subscription_Scan"  -Format $ExportFormat
        Export-Results -Data $mdcRbacRows -FileName "4_MDC_RBAC_Assignments"   -Format $ExportFormat
        Write-OK "MDC enabled on $(($mdcSubScan | Where-Object MDCEnabled -eq $true).Count) of $($allSubscriptions.Count) subscription(s)"
        Write-OK "Total MDC RBAC rows: $($mdcRbacRows.Count)"
    }
    catch { Write-Error "Defender for Cloud scan failed: $_" }
}
else { Write-Warn "Defender for Cloud skipped. Use -ScanDefenderForCloud to enable." }

# =============================================================================
# SECTION 5: Microsoft Purview - Compliance Role Groups
# =============================================================================

Write-Header "5/7  Microsoft Purview - Compliance Role Groups"

if ($IncludePurview) {
    if ([string]::IsNullOrWhiteSpace($PurviewCertThumbprint) -or [string]::IsNullOrWhiteSpace($PurviewOrganization)) {
        Write-Warn "Purview skipped -- provide -PurviewCertThumbprint and -PurviewOrganization."
    }
    else {
        Write-Step "Connecting to Purview (app-only, certificate)..."
        try {
            Connect-IPPSSession -AppId $AppClientId -CertificateThumbprint $PurviewCertThumbprint -Organization $PurviewOrganization -ErrorAction Stop
            Write-OK "Connected to Purview"

            $allRoleGroups = Get-RoleGroup -ErrorAction Stop
            Write-OK "Found $($allRoleGroups.Count) compliance role group(s)"
            $purviewMembers = @()

            foreach ($rg in $allRoleGroups) {
                Write-Step "  Processing: $($rg.Name)"
                try {
                    $members = Get-RoleGroupMember -Identity $rg.Name -ErrorAction SilentlyContinue
                    $roleList = ""
                    try {
                        $roleList = ($rg.Roles | ForEach-Object {
                            if ($_ -is [string]) { ($_ -split "/")[-1] }
                            elseif ($_.Name)     { $_.Name }
                            else                 { ($_.ToString() -split "/")[-1] }
                        }) -join "; "
                    }
                    catch { $roleList = ($rg.Roles -join "; ") }

                    if (-not $members -or @($members).Count -eq 0) {
                        $purviewMembers += [PSCustomObject]@{
                            RoleGroupName=$rg.Name; RoleGroupDescription=$rg.Description
                            RoleGroupType=$rg.RoleGroupType; AssignedRoles=$roleList
                            MemberDisplayName="(No members)"; MemberUPN=""; MemberMail=""
                            MemberType=""; AccountEnabled=""; Department=""; JobTitle=""
                            AccessPath="Purview role group '$($rg.Name)' has no members"
                            ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                    else {
                        foreach ($m in $members) {
                            $recipientType = $m.RecipientTypeDetails
                            $isGroup = $recipientType -match "Group|MailUniversalDistributionGroup|MailNonUniversalGroup|MailUniversalSecurityGroup|GroupMailbox"

                            if ($isGroup) {
                                $mgGroup = $null
                                try {
                                    if (-not [string]::IsNullOrWhiteSpace($m.ExternalDirectoryObjectId)) {
                                        $mgGroup = Invoke-MgWithRetry { Get-MgGroup -GroupId $m.ExternalDirectoryObjectId -ErrorAction SilentlyContinue }
                                    }
                                    if (-not $mgGroup -and -not [string]::IsNullOrWhiteSpace($m.PrimarySmtpAddress)) {
                                        $mgGroup = Invoke-MgWithRetry { Get-MgGroup -Filter "mail eq '$($m.PrimarySmtpAddress)'" -ErrorAction SilentlyContinue } | Select-Object -First 1
                                    }
                                    if (-not $mgGroup) {
                                        $mgGroup = Invoke-MgWithRetry { Get-MgGroup -Filter "displayName eq '$($m.DisplayName)'" -ErrorAction SilentlyContinue } | Select-Object -First 1
                                    }
                                }
                                catch { $mgGroup = $null }

                                if ($mgGroup) {
                                    $groupUsers = Invoke-MgWithRetry { Get-MgGroupMember -GroupId $mgGroup.Id -All -ErrorAction SilentlyContinue }
                                    $expanded = 0
                                    foreach ($gu in $groupUsers) {
                                        $odataType = $gu.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.",""
                                        if ($odataType -eq "user") {
                                            $u = Invoke-MgWithRetry {
                                                Get-MgUser -UserId $gu.Id -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" -ErrorAction SilentlyContinue
                                            }
                                            $purviewMembers += [PSCustomObject]@{
                                                RoleGroupName=$rg.Name; RoleGroupDescription=$rg.Description
                                                RoleGroupType=$rg.RoleGroupType; AssignedRoles=$roleList
                                                MemberDisplayName=$u.DisplayName; MemberUPN=$u.UserPrincipalName
                                                MemberMail=$u.Mail; MemberType="User (via Group: $($m.DisplayName))"
                                                AccountEnabled=$u.AccountEnabled; Department=$u.Department; JobTitle=$u.JobTitle
                                                AccessPath="Purview role group '$($rg.Name)' -> group '$($m.DisplayName)' -> user '$($u.UserPrincipalName)'"
                                                ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                            }
                                            $expanded++
                                        }
                                    }
                                    Write-OK "    Expanded '$($m.DisplayName)': $expanded user(s)"
                                }
                                else {
                                    $purviewMembers += [PSCustomObject]@{
                                        RoleGroupName=$rg.Name; RoleGroupDescription=$rg.Description
                                        RoleGroupType=$rg.RoleGroupType; AssignedRoles=$roleList
                                        MemberDisplayName=$m.DisplayName
                                        MemberUPN=if($m.PrimarySmtpAddress){$m.PrimarySmtpAddress}else{$m.Name}
                                        MemberMail=$m.PrimarySmtpAddress; MemberType="$recipientType (Group - could not expand)"
                                        AccountEnabled=""; Department=""; JobTitle=""
                                        AccessPath="Purview role group '$($rg.Name)' -> group '$($m.DisplayName)' (Graph resolution failed)"
                                        ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                    }
                                }
                            }
                            else {
                                $upn = if($m.WindowsLiveId){$m.WindowsLiveId} elseif($m.PrimarySmtpAddress){$m.PrimarySmtpAddress} else{$m.Name}
                                $purviewMembers += [PSCustomObject]@{
                                    RoleGroupName=$rg.Name; RoleGroupDescription=$rg.Description
                                    RoleGroupType=$rg.RoleGroupType; AssignedRoles=$roleList
                                    MemberDisplayName=$m.DisplayName; MemberUPN=$upn
                                    MemberMail=$m.PrimarySmtpAddress; MemberType=$recipientType
                                    AccountEnabled=""; Department=""; JobTitle=""
                                    AccessPath="Direct member of Purview role group '$($rg.Name)'"
                                    ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                }
                            }
                        }
                    }
                }
                catch { Write-Warn "  Could not get members for '$($rg.Name)': $_" }
            }

            Export-Results -Data $purviewMembers -FileName "5_Purview_RoleGroups" -Format $ExportFormat
            Write-OK "Total Purview entries: $($purviewMembers.Count)"
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-OK "Purview session disconnected"
        }
        catch {
            Write-Error "Purview failed: $_"
            Write-Warn "Required: Exchange.ManageAsApp + Admin Consent, App SP assigned Compliance Administrator in Purview portal"
        }
    }
}
else { Write-Warn "Purview skipped. Use -IncludePurview -PurviewCertThumbprint <thumb> -PurviewOrganization <domain>" }

# =============================================================================
# SECTION 6: Microsoft Defender XDR - Complete RBAC
# =============================================================================

if ($IncludeXDRRBAC) {
    Write-Header "6/7  Defender XDR - Complete RBAC Export"

    $mdeRoles=@(); $mdeRoleAssignments=@(); $mdeIdentityAudit=@()
    $Script:secToken=$null

    if ([string]::IsNullOrWhiteSpace($AppClientId) -or [string]::IsNullOrWhiteSpace($AppClientSecret)) {
        Write-Warn "No App Registration params -- Section 6 skipped."
    }
    else {
        $resolvedTenant = if(-not [string]::IsNullOrWhiteSpace($AppTenantId)){$AppTenantId}else{(Get-MgContext).TenantId}

        function Get-MdeToken {
            param([string]$Scope)
            try {
                $r = Invoke-RestMethod -Method POST `
                    -Uri "https://login.microsoftonline.com/$resolvedTenant/oauth2/v2.0/token" `
                    -Body @{grant_type="client_credentials";client_id=$AppClientId;client_secret=$AppClientSecret;scope=$Scope} `
                    -ErrorAction Stop
                return $r.access_token
            }
            catch { Write-Warn "Token failed for '$Scope': $_"; return $null }
        }

        Write-Step "Acquiring XDR Security token..."
        $Script:secToken = Get-MdeToken -Scope "https://api.security.microsoft.com/.default"
        if ($Script:secToken) { Write-OK "XDR Security token acquired" }
        else { Write-Warn "XDR Security token failed -- Advanced Hunting skipped." }
    }

    $entraKnownUPNs = @()
    if ($entraRoleAssignments.Count -gt 0) {
        $entraKnownUPNs = $entraRoleAssignments |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.MemberUPN) } |
            Select-Object -ExpandProperty MemberUPN -Unique
    }

    if ($Script:secToken) {
        $kqlRoleList = ($targetEntraRoles | ForEach-Object { "`"$_`"" }) -join ","

        $kqlQuery = @"
let XdrRoles = dynamic([$kqlRoleList]);
IdentityInfo
| where Timestamp > ago(1d)
| where isnotempty(AssignedRoles)
| mv-expand AssignedRole = AssignedRoles
| where AssignedRole in (XdrRoles)
| summarize arg_max(Timestamp, *) by AccountObjectId
| project AccountUpn, AccountDisplayName, AccountObjectId, Department, JobTitle,
          IsAccountEnabled, AssignedRoles, GroupMembership, RiskLevel, BlastRadius, IdentityEnvironment
| order by AccountDisplayName asc
"@

        $body = @{ Query = $kqlQuery } | ConvertTo-Json
        $hdrs = @{ Authorization="Bearer $($Script:secToken)"; "Content-Type"="application/json" }

        Write-Step "Submitting Advanced Hunting query..."
        try {
            $ahResult = Invoke-RestMethod -Method POST `
                -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
                -Headers $hdrs -Body $body -ErrorAction Stop

            if ($ahResult -and $ahResult.Results -and $ahResult.Results.Count -gt 0) {
                Write-OK "Advanced Hunting returned $($ahResult.Results.Count) record(s)"

                foreach ($identity in $ahResult.Results) {
                    $rolesStr    = if($identity.AssignedRoles)   {($identity.AssignedRoles   | ForEach-Object {$_}) -join "; "} else {""}
                    $groupsStr   = if($identity.GroupMembership) {($identity.GroupMembership | ForEach-Object {$_}) -join "; "} else {""}
                    $isBlindSpot = ($identity.AccountUpn -notin $entraKnownUPNs) -and (-not [string]::IsNullOrWhiteSpace($identity.AccountUpn))
                    $identityType = if(-not [string]::IsNullOrWhiteSpace($identity.AccountUpn)){"User"}
                                    elseif($identity.IdentityEnvironment -eq "Cloud" -and [string]::IsNullOrWhiteSpace($identity.Department)){"App"}
                                    else{"ServicePrincipal"}

                    $mdeIdentityAudit += [PSCustomObject]@{
                        IdentityType=$identityType; AccountUPN=$identity.AccountUpn
                        DisplayName=$identity.AccountDisplayName; AccountObjectId=$identity.AccountObjectId
                        Department=$identity.Department; JobTitle=$identity.JobTitle
                        IsAccountEnabled=$identity.IsAccountEnabled
                        AssignedEntraRoles=$rolesStr; EntraGroupMembership=$groupsStr
                        RiskLevel=$identity.RiskLevel; BlastRadius=$identity.BlastRadius
                        IdentityEnvironment=$identity.IdentityEnvironment
                        AccessPath="Defender XDR IdentityInfo: Entra roles=[$rolesStr] | Groups=[$groupsStr]"
                        InSection1Export=if($isBlindSpot){"NO - NOT IN ENTRA ROLE EXPORT"}else{"Yes"}
                        BlindSpotFlag=if($isBlindSpot){"REVIEW REQUIRED"}else{""}
                        ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

                $blindSpotCount=($mdeIdentityAudit | Where-Object {$_.BlindSpotFlag -eq "REVIEW REQUIRED"}).Count
                Write-OK "6b - $($mdeIdentityAudit.Count) identities, $blindSpotCount blind spot(s)"
                if ($blindSpotCount -gt 0) { Write-Warn "ACTION: $blindSpotCount identities not in Section 1 -- filter BlindSpotFlag=REVIEW REQUIRED" }
                else { Write-OK "No blind spots detected." }
            }
            else { Write-Warn "No results. Verify Defender for Identity or Entra ID connector is active." }
        }
        catch { Write-Warn "Advanced Hunting failed: $_" }
    }

    Export-Results -Data $mdeIdentityAudit -FileName "6b_MDE_RBAC" -Format $ExportFormat

    Write-Host ""
    Write-Host "  XDR RBAC Summary" -ForegroundColor Cyan
    Write-Host "  6b MDE Identity Audit : $($mdeIdentityAudit.Count) identities" -ForegroundColor White
    if ($mdeRoles.Count -eq 0 -and $mdeRoleAssignments.Count -eq 0) {
        Write-Warn "  6a returned 0 custom roles -- expected for Unified RBAC tenants (post Feb 2025)."
    }
}
else { Write-Warn "XDR RBAC skipped. Use -IncludeXDRRBAC to enable." }
# =============================================================================
# SECTION 7: Service Principals & App Registrations -- Security Permissions
# =============================================================================

Write-Header "7/7  Service Principals & App Registrations -- Security Permissions"

$spResults = @()

$sensitiveApiPermissions = @(
    "RoleManagement.Read.All","RoleManagement.ReadWrite.All",
    "Directory.Read.All","Directory.ReadWrite.All",
    "User.Read.All","Group.Read.All",
    "Application.Read.All","Application.ReadWrite.All",
    "PrivilegedAccess.Read.AzureADGroup","PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
    "AdvancedHunting.Read.All",
    "SecurityEvents.Read.All","SecurityEvents.ReadWrite.All",
    "Policy.Read.All","AuditLog.Read.All",
    "IdentityRiskyUser.Read.All","IdentityRiskEvent.Read.All"
)

try {
    Write-Step "Fetching all Service Principals..."
    $allSPs = Invoke-MgWithRetry {
        Get-MgServicePrincipal -All `
            -Property "Id,DisplayName,AppId,ServicePrincipalType,AppRoles,OAuth2PermissionScopes" `
            -ErrorAction Stop
    }
    Write-OK "Found $($allSPs.Count) service principal(s)"

    # 7a -- Entra Role Assignments for SPs
    Write-Step "7a - Entra role assignments for Service Principals..."
    $spRoleAssignments = Invoke-MgWithRetry {
        Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty "principal" -ErrorAction SilentlyContinue
    }
    foreach ($ra in $spRoleAssignments) {
        $principal=$ra.Principal; $odataType=""
        if ($principal -and $principal.AdditionalProperties) {
            $odataType=($principal.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.","")
        }
        if ($odataType -ne "servicePrincipal") { continue }
        $rd=$allRoleDefinitions[$ra.RoleDefinitionId]
        if (-not $rd -or $rd.DisplayName -notin $targetEntraRoles) { continue }
        $sp=$allSPs | Where-Object {$_.Id -eq $ra.PrincipalId}
        $isRunningApp=($sp -and $sp.AppId -eq $AppClientId)
        $spResults += [PSCustomObject]@{
            SPDisplayName=if($sp){$sp.DisplayName}else{$ra.PrincipalId}
            AppId=if($sp){$sp.AppId}else{""}
            SPType=if($sp){$sp.ServicePrincipalType}else{"ServicePrincipal"}
            PermissionSource="Entra Role"; Permission=$rd.DisplayName; PermissionScope="Entra ID"
            AccessPath=Build-AccessPath -RoleName $rd.DisplayName -AssignmentType "Direct"
            IsRunningApp=if($isRunningApp){"YES - THIS IS THE APP RUNNING THE SCRIPT"}else{""}
            ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
    Write-OK "7a complete"

    # 7b -- Azure RBAC for SPs
    if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
        Write-Step "7b - Azure RBAC assignments for Service Principals..."
        $securityAzureRoles=@("Owner","Contributor","Security Admin","Security Reader",
            "Microsoft Sentinel Contributor","Microsoft Sentinel Reader",
            "Microsoft Sentinel Responder","Log Analytics Contributor")
        try {
            $allAzSubs=Get-AzSubscription -TenantId $TenantId -ErrorAction SilentlyContinue
            foreach ($sub in $allAzSubs) {
                Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction SilentlyContinue | Out-Null
                $assignments=Get-AzRoleAssignment -ErrorAction SilentlyContinue |
                    Where-Object {$_.ObjectType -eq "ServicePrincipal" -and $_.RoleDefinitionName -in $securityAzureRoles}
                foreach ($ra in $assignments) {
                    $sp=$allSPs | Where-Object {$_.Id -eq $ra.ObjectId}
                    $isRunningApp=($sp -and $sp.AppId -eq $AppClientId)
                    $spResults += [PSCustomObject]@{
                        SPDisplayName=$ra.DisplayName
                        AppId=if($sp){$sp.AppId}else{""}
                        SPType="ServicePrincipal"; PermissionSource="Azure RBAC"
                        Permission=$ra.RoleDefinitionName; PermissionScope=$ra.Scope
                        AccessPath=Build-AccessPath -RoleName $ra.RoleDefinitionName -AssignmentType "Azure RBAC" -Scope $ra.Scope
                        IsRunningApp=if($isRunningApp){"YES - THIS IS THE APP RUNNING THE SCRIPT"}else{""}
                        ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }
            }
            Write-OK "7b complete"
        }
        catch { Write-Warn "7b failed: $_" }
    }
    else { Write-Warn "7b skipped (no -SentinelWorkspaces or -ScanDefenderForCloud)" }

    # 7c -- API Permissions
    Write-Step "7c - API permissions for Service Principals..."

    $graphSP = Invoke-MgWithRetry {
        Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction SilentlyContinue
    }
    $graphRoleLookup=@{}
    if ($graphSP) { foreach ($r in $graphSP.AppRoles) { $graphRoleLookup[$r.Id.ToString()]=$r.Value } }

    $mtpSP = Invoke-MgWithRetry {
        Get-MgServicePrincipal -Filter "appId eq '8ee8fdad-f234-4243-8f3b-15c294843740'" -ErrorAction SilentlyContinue
    }
    $mtpRoleLookup=@{}
    if ($mtpSP) { foreach ($r in $mtpSP.AppRoles) { $mtpRoleLookup[$r.Id.ToString()]=$r.Value } }

    foreach ($sp in $allSPs) {
        try {
            $assignments = Invoke-MgWithRetry {
                Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
            }
            foreach ($a in $assignments) {
                $permName=""
                if ($graphRoleLookup.ContainsKey($a.AppRoleId.ToString())) { $permName=$graphRoleLookup[$a.AppRoleId.ToString()] }
                elseif ($mtpRoleLookup.ContainsKey($a.AppRoleId.ToString())) { $permName=$mtpRoleLookup[$a.AppRoleId.ToString()] }
                if ($permName -and $permName -in $sensitiveApiPermissions) {
                    $isRunningApp=($sp.AppId -eq $AppClientId)
                    $spResults += [PSCustomObject]@{
                        SPDisplayName=$sp.DisplayName; AppId=$sp.AppId; SPType=$sp.ServicePrincipalType
                        PermissionSource="API Permission (Application)"; Permission=$permName
                        PermissionScope="Microsoft Graph / MTP"
                        AccessPath=Build-AccessPath -RoleName $permName -AssignmentType "API Permission"
                        IsRunningApp=if($isRunningApp){"YES - THIS IS THE APP RUNNING THE SCRIPT"}else{""}
                        ExportedAt=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }
            }
        }
        catch {}
    }
    Write-OK "7c complete"

    $runningAppFound=@($spResults | Where-Object {$_.IsRunningApp -eq "YES - THIS IS THE APP RUNNING THE SCRIPT"})
    if ($runningAppFound.Count -eq 0) { Write-Warn "Running App ($AppClientId) not found in any security scan." }
    else { Write-OK "Running App ($AppClientId) flagged with IsRunningApp = YES" }

    Export-Results -Data $spResults -FileName "7_ServicePrincipal_SecurityPermissions" -Format $ExportFormat

    Write-Host ""
    Write-Host "  Section 7 Summary" -ForegroundColor Cyan
    Write-Host "  Total SP entries : $($spResults.Count)" -ForegroundColor White
    Write-Host "  Unique SPs       : $((@($spResults | Select-Object -ExpandProperty AppId -Unique)).Count)" -ForegroundColor White
    Write-Host "  Running app      : $(if($runningAppFound.Count -gt 0){'Yes'}else{'No'})" -ForegroundColor White
}
catch { Write-Error "Section 7 failed: $_" }

# =============================================================================
# Final Summary + Manifest
# =============================================================================

Write-Header "Export Complete"

$files = Get-ChildItem -Path $OutputPath -File
Write-Host ""
Write-Host "  Files written to: $OutputPath" -ForegroundColor Cyan
foreach ($f in $files) {
    Write-Host "    $($f.Name)  ($([math]::Round($f.Length/1KB,1)) KB)" -ForegroundColor White
}

$knownBlindSpots = @(
    [PSCustomObject]@{
        Area="Defender XDR Unified RBAC custom roles"
        Reason="Custom roles in the Defender portal are not surfaced via Entra role assignments. Requires GET /beta/security/roleAssignments."
        Mitigation="Review custom roles in the Defender XDR portal manually."
    },
    [PSCustomObject]@{
        Area="IdentityInfo MDI sensor coverage gaps"
        Reason="IdentityInfo only reflects identities seen by Defender for Identity sensors."
        Mitigation="Entra-authoritative data (Section 1) is the reliable source. Use Section 6 as corroboration only."
    },
    [PSCustomObject]@{
        Area="Sentinel Unified RBAC (post-Feb 2026)"
        Reason="Sentinel permissions can be managed in the Defender portal. Azure RBAC alone may not reflect the full picture."
        Mitigation="Combine Section 3 with a manual review of Defender XDR Unified RBAC role assignments."
    },
    [PSCustomObject]@{
        Area="PIM activation history"
        Reason="Script captures current state only, not historical activation events."
        Mitigation="Use Entra audit logs (auditLogs/directoryAudits) for activation history."
    },
    [PSCustomObject]@{
        Area="Guest and B2B identities"
        Reason="May hold role assignments but not surface cleanly in IdentityInfo."
        Mitigation="Section 1 covers B2B users via Get-MgRoleManagementDirectoryRoleAssignment."
    },
    [PSCustomObject]@{
        Area="Subscriptions without Azure RBAC for the App Registration SP"
        Reason="Sections 3 and 4 require Reader or Security Reader at subscription or MG scope."
        Mitigation="Assign the App SP to a Management Group with Reader + Security Reader."
    },
    [PSCustomObject]@{
        Area="Future RBAC model changes"
        Reason="Script reflects the permission model at time of execution."
        Mitigation="Rerun on a defined cadence. Consider Entra Access Reviews for continuous coverage."
    }
)

$manifest = [PSCustomObject]@{
    ExportTimestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion           = "v3.0"
    TenantId                = (Get-MgContext).TenantId
    ExportedBy              = (Get-MgContext).Account
    SentinelWorkspaceCount  = $SentinelWorkspaces.Count
    IncludedPIM             = $IncludePIM.IsPresent
    ScannedDefenderForCloud = $ScanDefenderForCloud.IsPresent
    IncludedPurview         = $IncludePurview.IsPresent
    IncludedXDRRBAC         = $IncludeXDRRBAC.IsPresent
    EntraRoleCount          = $entraRoleAssignments.Count
    PIMAssignmentCount      = if ($IncludePIM) { $pimAssignments.Count } else { "skipped" }
    MDERBACCount            = if ($IncludeXDRRBAC) { $mdeIdentityAudit.Count } else { "skipped" }
    SPPermissionCount       = $spResults.Count
    FilesGenerated          = $files.Count
    KnownBlindSpots         = $knownBlindSpots
}

$manifest | ConvertTo-Json -Depth 10 | Out-File "$OutputPath\00_ExportManifest.json" -Encoding UTF8
Write-OK "Manifest written -> 00_ExportManifest.json"

Disconnect-MgGraph | Out-Null
Write-OK "Graph session disconnected"

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
