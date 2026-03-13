# Get-RoleAssignments.ps1  v1.9
# Exports role assignments from: Entra ID, PIM, Sentinel, Defender for Cloud, Purview, Defender XDR
#
# Section 6 requires an App Registration with Admin Consent for:
#   WindowsDefenderATP (Application)          : Machine.Read.All, SecurityConfiguration.Read.All,
#                                               AdvancedQuery.Read.All
#   Microsoft Threat Protection (Application) : AdvancedHunting.Read.All
#
# Author : Nitin

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

    [Parameter(HelpMessage = "Include PIM eligible role assignments (requires Entra P2).")]
    [switch]$IncludePIM,

    [Parameter(HelpMessage = "Scan all accessible subscriptions for Defender for Cloud RBAC.")]
    [switch]$ScanDefenderForCloud,

    [Parameter(HelpMessage = "Export Purview compliance role groups and members.")]
    [switch]$IncludePurview,

    [Parameter(HelpMessage = "Admin UPN for Purview connection (required with -IncludePurview).")]
    [string]$PurviewAdminUPN,

    [Parameter(HelpMessage = "Export full XDR RBAC: MDE roles, device groups, access matrix, Entra cross-reference, Advanced Hunting identity audit.")]
    [switch]$IncludeXDRRBAC,

    [Parameter(HelpMessage = "App Registration Client ID (required for Section 6).")]
    [string]$AppClientId,

    [Parameter(HelpMessage = "App Registration Client Secret (required for Section 6).")]
    [string]$AppClientSecret,

    [Parameter(HelpMessage = "Tenant ID for the App Registration. Defaults to current Graph tenant.")]
    [string]$AppTenantId,

    [Parameter(HelpMessage = "Tenant ID used for Graph and Az account connections.")]
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
    if (-not $Data -or $Data.Count -eq 0) { Write-Warn "No data to export for: $FileName"; return }
    if ($Format -in @("CSV", "Both")) {
        $Data | Export-Csv -Path "$OutputPath\$FileName.csv" -NoTypeInformation -Encoding UTF8
        Write-OK "Exported $($Data.Count) rows -> $FileName.csv"
    }
    if ($Format -in @("JSON", "Both")) {
        $Data | ConvertTo-Json -Depth 6 | Out-File "$OutputPath\$FileName.json" -Encoding UTF8
        Write-OK "Exported $($Data.Count) rows -> $FileName.json"
    }
}

# =============================================================================
# Setup
# =============================================================================

Write-Header "Microsoft Security Stack - Role Assignments Export v2.0"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-OK "Output folder created: $OutputPath"
}

$requiredModules = @(
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups"
)
if ($IncludePIM)           { $requiredModules += "Microsoft.Graph.Identity.Governance" }
if ($SubscriptionId)       { $requiredModules += "Az.Accounts", "Az.Resources" }
if ($ScanDefenderForCloud) { $requiredModules += "Az.Accounts", "Az.Resources", "Az.Security" }
if ($IncludePurview)       { $requiredModules += "ExchangeOnlineManagement" }

$requiredModules = $requiredModules | Sort-Object -Unique

Write-Step "Checking and loading required modules..."

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Step "  Installing missing module: $mod"
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-OK "Installed: $mod"
        }
        catch {
            Write-Error "Failed to install $mod. Run manually: Install-Module $mod -Scope CurrentUser"
            exit 1
        }
    }
    if (-not (Get-Module -Name $mod)) {
        try {
            Import-Module -Name $mod -Force -ErrorAction Stop
            Write-OK "Imported: $mod"
        }
        catch {
            Write-Error "Failed to import $mod : $_"
            exit 1
        }
    }
    else {
        Write-OK "Already loaded: $mod"
    }
}

# =============================================================================
# SECTION 1: Entra ID Directory Roles
# =============================================================================

Write-Header "1/6  Entra ID - Directory Role Assignments"
Write-Step "Connecting to Microsoft Graph..."

try {
    $mgCtx = Get-MgContext

    if (-not $mgCtx) {
        $connectParams = @{
            Scopes                  = "RoleManagement.Read.All","Directory.Read.All","User.Read.All","Group.Read.All"
            UseDeviceAuthentication = $true
            NoWelcome               = $true
            ErrorAction             = "Stop"
        }
        if ($TenantId) { $connectParams["TenantId"] = $TenantId }
        Connect-MgGraph @connectParams
        $mgCtx = Get-MgContext
        Write-OK "Connected to Microsoft Graph (device auth)"
    }
    else {
        Write-OK "Reusing existing Graph session ($($mgCtx.Account))"
    }

    # Always resolve TenantId from live session - overrides any hardcoded default
    $TenantId = $mgCtx.TenantId
    Write-OK "Resolved TenantId from Graph session: $TenantId"
}
catch {
    Write-Error "Graph connection failed: $_"
    exit 1
}

# =============================================================================
# Az Account Connection (Sections 3 + 4)
# =============================================================================

if ($SentinelWorkspaces.Count -gt 0 -or $ScanDefenderForCloud) {
    Write-Step "Connecting to Azure (required for Sentinel / Defender for Cloud)..."
    try {
        # Validate existing session with a lightweight test call
        $azCtx      = Get-AzContext
        $tokenValid = $false

        if ($azCtx -and $azCtx.Tenant.Id -eq $TenantId) {
            try {
                Get-AzSubscription -TenantId $TenantId -ErrorAction Stop | Out-Null
                $tokenValid = $true
                Write-OK "Existing Az session token validated ($($azCtx.Account.Id))"
            }
            catch {
                Write-Warn "Existing Az session token is stale -- reconnecting..."
            }
        }

        if (-not $tokenValid) {
            if ($azCtx) { Disconnect-AzAccount -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
            Connect-AzAccount -TenantId $TenantId -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            Write-OK "Connected to Azure: $((Get-AzContext).Account.Id)"
        }
    }
    catch {
        Write-Error "Az connection failed: $_"
        exit 1
    }
}

Write-Step "Fetching active directory role assignments..."

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
    "Intune Administrator"
)

$entraRoleAssignments = @()

try {
    $activeRoles = Get-MgDirectoryRole -All -ErrorAction Stop
    $activeRoles = $activeRoles | Where-Object { $_.DisplayName -in $targetEntraRoles }
    Write-OK "Scoping to $($activeRoles.Count) target role(s): $($targetEntraRoles -join ', ')"

    foreach ($role in $activeRoles) {
        Write-Step "  Processing role: $($role.DisplayName)"

        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue

        foreach ($member in $members) {

            $odataKey   = "@odata.type"
            $odataValue = $member.AdditionalProperties[$odataKey]
            $memberType = ($odataValue -replace "#microsoft.graph.", "")

            try {
                switch ($memberType) {

                    "user" {
                        $u = Get-MgUser -UserId $member.Id `
                                -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,Department,JobTitle" `
                                -ErrorAction SilentlyContinue

                        $entraRoleAssignments += [PSCustomObject]@{
                            RoleName          = $role.DisplayName
                            RoleId            = $role.Id
                            RoleDescription   = $role.Description
                            MemberType        = "User"
                            MemberDisplayName = $u.DisplayName
                            MemberUPN         = $u.UserPrincipalName
                            MemberMail        = $u.Mail
                            MemberDepartment  = $u.Department
                            MemberJobTitle    = $u.JobTitle
                            AccountEnabled    = $u.AccountEnabled
                            UserType          = $u.UserType
                            MemberId          = $member.Id
                            AssignmentType    = "Active"
                            MDEAccessLevel    = switch ($role.DisplayName) {
                                "Global Administrator"    { "Full MDE Access" }
                                "Security Administrator"  { "Full MDE Read/Write" }
                                "Security Operator"       { "MDE Response Actions" }
                                "Security Reader"         { "MDE Read Only" }
                                "Global Reader"           { "MDE Read Only" }
                                "Helpdesk Administrator"  { "MDE Device Management" }
                                "Intune Administrator"    { "MDE Device Management" }
                                default                   { "-" }
                            }
                            PurviewAccessLevel = switch ($role.DisplayName) {
                                "Global Administrator"                { "Full Purview Access" }
                                "Compliance Administrator"            { "Full Compliance Center" }
                                "Compliance Data Administrator"       { "Read/Write Compliance Data" }
                                "Security Administrator"              { "Read Purview Alerts" }
                                "Security Reader"                     { "Read Only" }
                                "Global Reader"                       { "Read Only" }
                                "Information Protection Administrator" { "Sensitivity Labels & DLP" }
                                default                               { "-" }
                            }
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    "group" {
                        $g = Get-MgGroup -GroupId $member.Id `
                                -Property "DisplayName,Mail,GroupTypes" `
                                -ErrorAction SilentlyContinue

                        $entraRoleAssignments += [PSCustomObject]@{
                            RoleName          = $role.DisplayName
                            RoleId            = $role.Id
                            RoleDescription   = $role.Description
                            MemberType        = "Group"
                            MemberDisplayName = $g.DisplayName
                            MemberUPN         = $g.Mail
                            MemberMail        = $g.Mail
                            MemberDepartment  = ""
                            MemberJobTitle    = ""
                            AccountEnabled    = $true
                            UserType          = "Group"
                            MemberId          = $member.Id
                            AssignmentType    = "Active"
                            MDEAccessLevel    = switch ($role.DisplayName) {
                                "Global Administrator"    { "Full MDE Access" }
                                "Security Administrator"  { "Full MDE Read/Write" }
                                "Security Operator"       { "MDE Response Actions" }
                                "Security Reader"         { "MDE Read Only" }
                                "Global Reader"           { "MDE Read Only" }
                                "Helpdesk Administrator"  { "MDE Device Management" }
                                "Intune Administrator"    { "MDE Device Management" }
                                default                   { "-" }
                            }
                            PurviewAccessLevel = switch ($role.DisplayName) {
                                "Global Administrator"                { "Full Purview Access" }
                                "Compliance Administrator"            { "Full Compliance Center" }
                                "Compliance Data Administrator"       { "Read/Write Compliance Data" }
                                "Security Administrator"              { "Read Purview Alerts" }
                                "Security Reader"                     { "Read Only" }
                                "Global Reader"                       { "Read Only" }
                                "Information Protection Administrator" { "Sensitivity Labels & DLP" }
                                default                               { "-" }
                            }
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    "servicePrincipal" {
                        $spName = $member.AdditionalProperties["displayName"]

                        $entraRoleAssignments += [PSCustomObject]@{
                            RoleName          = $role.DisplayName
                            RoleId            = $role.Id
                            RoleDescription   = $role.Description
                            MemberType        = "ServicePrincipal"
                            MemberDisplayName = $spName
                            MemberUPN         = ""
                            MemberMail        = ""
                            MemberDepartment  = ""
                            MemberJobTitle    = ""
                            AccountEnabled    = $true
                            UserType          = "ServicePrincipal"
                            MemberId          = $member.Id
                            AssignmentType    = "Active"
                            MDEAccessLevel    = switch ($role.DisplayName) {
                                "Global Administrator"    { "Full MDE Access" }
                                "Security Administrator"  { "Full MDE Read/Write" }
                                "Security Operator"       { "MDE Response Actions" }
                                "Security Reader"         { "MDE Read Only" }
                                "Global Reader"           { "MDE Read Only" }
                                "Helpdesk Administrator"  { "MDE Device Management" }
                                "Intune Administrator"    { "MDE Device Management" }
                                default                   { "-" }
                            }
                            PurviewAccessLevel = switch ($role.DisplayName) {
                                "Global Administrator"                { "Full Purview Access" }
                                "Compliance Administrator"            { "Full Compliance Center" }
                                "Compliance Data Administrator"       { "Read/Write Compliance Data" }
                                "Security Administrator"              { "Read Purview Alerts" }
                                "Security Reader"                     { "Read Only" }
                                "Global Reader"                       { "Read Only" }
                                "Information Protection Administrator" { "Sensitivity Labels & DLP" }
                                default                               { "-" }
                            }
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    default {
                        Write-Warn "Unknown member type '$memberType' for member $($member.Id)"
                    }
                }
            }
            catch {
                Write-Warn "Could not resolve member $($member.Id): $_"
            }
        }
    }

    Export-Results -Data $entraRoleAssignments -FileName "1_Entra_Security_Roles" -Format $ExportFormat
}
catch {
    Write-Error "Failed to retrieve Entra ID roles: $_"
}

# =============================================================================
# SECTION 2: PIM Eligible Assignments
# =============================================================================

if ($IncludePIM) {
    Write-Header "2/6  Entra ID - PIM Eligible Role Assignments"
    Write-Step "Fetching PIM eligible role assignments..."

    $pimAssignments = @()

    try {
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
        Write-OK "Total PIM eligible assignments found: $($eligibleAssignments.Count). Filtering to target roles only..."

        foreach ($assignment in $eligibleAssignments) {
            $principalId = $assignment.PrincipalId
            $roleDefId   = $assignment.RoleDefinitionId

            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition `
                           -UnifiedRoleDefinitionId $roleDefId `
                           -ErrorAction SilentlyContinue

            if ($roleDef.DisplayName -notin $targetEntraRoles) { continue }

            # Resolve principal: try User first, then Group, then ServicePrincipal
            $memberDisplayName = $principalId
            $memberUPN         = ""
            $memberMail        = ""
            $memberDepartment  = ""
            $memberType        = "Unknown"

            $user = Get-MgUser -UserId $principalId `
                        -Property "DisplayName,UserPrincipalName,Mail,Department" `
                        -ErrorAction SilentlyContinue

            if ($user) {
                $memberDisplayName = $user.DisplayName
                $memberUPN         = $user.UserPrincipalName
                $memberMail        = $user.Mail
                $memberDepartment  = $user.Department
                $memberType        = "User"
            }
            else {
                $group = Get-MgGroup -GroupId $principalId `
                             -Property "DisplayName,Mail" `
                             -ErrorAction SilentlyContinue

                if ($group) {
                    $memberDisplayName = $group.DisplayName
                    $memberMail        = $group.Mail
                    $memberType        = "Group"
                }
                else {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $principalId `
                              -Property "DisplayName" `
                              -ErrorAction SilentlyContinue

                    if ($sp) {
                        $memberDisplayName = $sp.DisplayName
                        $memberType        = "ServicePrincipal"
                    }
                }
            }

            $pimAssignments += [PSCustomObject]@{
                RoleName          = $roleDef.DisplayName
                RoleId            = $roleDefId
                MemberType        = $memberType
                MemberDisplayName = $memberDisplayName
                MemberUPN         = $memberUPN
                MemberMail        = $memberMail
                MemberDepartment  = $memberDepartment
                AssignmentType    = "PIM-Eligible"
                ScheduleStartDate = $assignment.ScheduleInfo.StartDateTime
                ScheduleExpiry    = $assignment.ScheduleInfo.Expiration.EndDateTime
                ExpiryType        = $assignment.ScheduleInfo.Expiration.Type
                MembershipType    = $assignment.MemberType
                Status            = $assignment.Status
                ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        Export-Results -Data $pimAssignments -FileName "2_EntraID_PIM_EligibleRoles" -Format $ExportFormat
    }
    catch {
        Write-Warn "PIM data retrieval failed (requires Entra P2 + Identity Governance module): $_"
    }
}
else {
    Write-Warn "PIM eligible assignments skipped. Use -IncludePIM to include them."
}

# =============================================================================
# SECTION 3: Microsoft Sentinel - Workspace RBAC
# =============================================================================

Write-Header "3/6  Microsoft Sentinel - Workspace RBAC"
Write-Step "Processing Sentinel workspace RBAC..."

if ($SentinelWorkspaces.Count -gt 0) {
    Write-Step "Processing $($SentinelWorkspaces.Count) Sentinel workspace(s)..."

    $sentinelRoleNames = @(
        "Microsoft Sentinel Contributor",
        "Microsoft Sentinel Reader",
        "Microsoft Sentinel Responder",
        "Microsoft Sentinel Automation Contributor",
        "Log Analytics Contributor",
        "Log Analytics Reader"
    )

    $allSentinelRoles = @()
    $wsIndex = 0

    foreach ($ws in $SentinelWorkspaces) {
        $wsIndex++

        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) {
            Write-Warn "Workspace $wsIndex skipped -- missing one or more required keys (WorkspaceId, ResourceGroup, SubscriptionId)"
            continue
        }

        $wsSubId = $ws.SubscriptionId
        $wsRG    = $ws.ResourceGroup
        $wsId    = $ws.WorkspaceId

        Write-Step "  Workspace $wsIndex/$($SentinelWorkspaces.Count): $wsId (RG: $wsRG, Sub: $wsSubId)"

        try {
            Set-AzContext -SubscriptionId $wsSubId -Tenant $TenantId -ErrorAction Stop | Out-Null

            $sentinelScope = "/subscriptions/$wsSubId/resourceGroups/$wsRG"

            $wsRoles = Get-AzRoleAssignment -Scope $sentinelScope -ErrorAction Stop |
                Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames } |
                ForEach-Object {
                    [PSCustomObject]@{
                        WorkspaceId    = $wsId
                        ResourceGroup  = $wsRG
                        SubscriptionId = $wsSubId
                        RoleName       = $_.RoleDefinitionName
                        PrincipalName  = $_.DisplayName
                        PrincipalType  = $_.ObjectType
                        SignInName     = $_.SignInName
                        Scope          = $_.Scope
                        ExportedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

            $count = if ($wsRoles) { @($wsRoles).Count } else { 0 }
            Write-OK "  Found $count role assignment(s) for workspace $wsId"
            $allSentinelRoles += $wsRoles
        }
        catch {
            Write-Warn "  Failed to retrieve roles for workspace $wsId : $_"
        }
    }

    Export-Results -Data $allSentinelRoles -FileName "3_Sentinel_Workspace_Roles" -Format $ExportFormat

    $sentinelSummary = $allSentinelRoles |
        Group-Object WorkspaceId |
        ForEach-Object {
            [PSCustomObject]@{
                WorkspaceId    = $_.Name
                ResourceGroup  = $_.Group[0].ResourceGroup
                SubscriptionId = $_.Group[0].SubscriptionId
                TotalRoles     = $_.Count
                RoleBreakdown  = ($_.Group | Group-Object RoleName |
                    ForEach-Object { "$($_.Name): $($_.Count)" }) -join " | "
            }
        }

    Export-Results -Data $sentinelSummary -FileName "3_Sentinel_Workspace_Summary" -Format $ExportFormat
    Write-OK "Total Sentinel role assignments across all workspaces: $($allSentinelRoles.Count)"

    # 3b - Custom roles with Sentinel-relevant permissions
    Write-Step "3b - Scanning for custom/built-in roles with Sentinel-relevant permissions..."

    $sentinelPermissionActions = @(
        "Microsoft.SecurityInsights/*/read",
        "Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action",
        "Microsoft.SecurityInsights/threatIntelligence/indicators/query/action",
        "Microsoft.SecurityInsights/threatIntelligence/queryIndicators/action",
        "Microsoft.OperationalInsights/workspaces/analytics/query/action",
        "Microsoft.OperationalInsights/workspaces/*/read",
        "Microsoft.OperationalInsights/workspaces/LinkedServices/read",
        "Microsoft.OperationalInsights/workspaces/savedSearches/read",
        "Microsoft.OperationsManagement/solutions/read",
        "Microsoft.OperationalInsights/workspaces/query/read",
        "Microsoft.OperationalInsights/workspaces/query/*/read",
        "Microsoft.OperationalInsights/querypacks/*/read",
        "Microsoft.OperationalInsights/workspaces/dataSources/read",
        "Microsoft.Insights/workbooks/read",
        "Microsoft.Insights/myworkbooks/read",
        "Microsoft.Authorization/*/read",
        "Microsoft.Insights/alertRules/*",
        "Microsoft.Resources/deployments/*",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Resources/templateSpecs/*/read",
        "Microsoft.Support/*",
        "Microsoft.SecurityInsights/automationRules/*",
        "Microsoft.SecurityInsights/cases/*",
        "Microsoft.SecurityInsights/incidents/*",
        "Microsoft.SecurityInsights/entities/runPlaybook/action",
        "Microsoft.SecurityInsights/threatIntelligence/indicators/appendTags/action",
        "Microsoft.SecurityInsights/threatIntelligence/bulkTag/action",
        "Microsoft.SecurityInsights/threatIntelligence/indicators/replaceTags/action",
        "Microsoft.SecurityInsights/businessApplicationAgents/systems/undoAction/action",
        "Microsoft.SecurityInsights/*",
        "Microsoft.OperationalInsights/workspaces/savedSearches/*",
        "Microsoft.Insights/workbooks/*"
    )

    $customPermissionRows = @()

    foreach ($ws in $SentinelWorkspaces) {

        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) { continue }

        $wsSubId = $ws.SubscriptionId
        $wsRG    = $ws.ResourceGroup
        $wsId    = $ws.WorkspaceId

        Write-Step "  3b scanning workspace: $wsId"

        try {
            Set-AzContext -SubscriptionId $wsSubId -Tenant $TenantId -ErrorAction Stop | Out-Null

            $sentinelScope         = "/subscriptions/$wsSubId/resourceGroups/$wsRG"
            $allAssignmentsAtScope = Get-AzRoleAssignment -Scope $sentinelScope -ErrorAction Stop

            foreach ($ra in $allAssignmentsAtScope) {

                if ($ra.RoleDefinitionName -in $sentinelRoleNames) { continue }

                try {
                    $roleDef = Get-AzRoleDefinition -Id $ra.RoleDefinitionId `
                                   -WarningAction SilentlyContinue `
                                   -ErrorAction SilentlyContinue
                    if (-not $roleDef) { continue }

                    $allActions = @()
                    foreach ($perm in $roleDef.Permissions) {
                        if ($perm.Actions)     { $allActions += @($perm.Actions) }
                        if ($perm.DataActions) { $allActions += @($perm.DataActions) }
                    }

                    $matchedPermissions = @()
                    foreach ($targetAction in $sentinelPermissionActions) {
                        $pattern = "^" + [regex]::Escape($targetAction).Replace("\*", ".*") + "$"
                        foreach ($action in $allActions) {
                            if ($action -match $pattern -and $matchedPermissions -notcontains $targetAction) {
                                $matchedPermissions += $targetAction
                            }
                        }
                        foreach ($action in $allActions) {
                            $actionPattern = "^" + [regex]::Escape($action).Replace("\*", ".*") + "$"
                            if ($targetAction -match $actionPattern -and $matchedPermissions -notcontains $targetAction) {
                                $matchedPermissions += $targetAction
                            }
                        }
                    }

                    if ($matchedPermissions.Count -gt 0) {
                        $customPermissionRows += [PSCustomObject]@{
                            WorkspaceId        = $wsId
                            ResourceGroup      = $wsRG
                            SubscriptionId     = $wsSubId
                            RoleName           = $ra.RoleDefinitionName
                            RoleType           = $roleDef.RoleType
                            PrincipalName      = $ra.DisplayName
                            PrincipalType      = $ra.ObjectType
                            SignInName         = $ra.SignInName
                            Scope              = $ra.Scope
                            MatchedPermissions = ($matchedPermissions -join "; ")
                            MatchedCount       = $matchedPermissions.Count
                            ExportedAt         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
                catch {
                    Write-Warn "    Could not inspect role definition for '$($ra.RoleDefinitionName)': $_"
                }
            }
        }
        catch {
            Write-Warn "  3b scan failed for workspace $wsId : $_"
        }
    }

    Write-OK "3b - Found $($customPermissionRows.Count) role assignment(s) with matching Sentinel permissions"
    Export-Results -Data $customPermissionRows -FileName "3b_Sentinel_CustomPermission_Assignments" -Format $ExportFormat
}
else {
    Write-Warn "Sentinel workspace roles skipped. Use -SentinelWorkspaces to provide workspace definitions."
    Write-Warn "  Example: -SentinelWorkspaces @(@{ WorkspaceId='ws-id'; ResourceGroup='rg-name'; SubscriptionId='sub-id' })"
}

# =============================================================================
# SECTION 4: Defender for Cloud - Subscription RBAC
# =============================================================================

Write-Header "4/6  Defender for Cloud - Subscription RBAC"

if ($ScanDefenderForCloud) {

    Write-Step "Connecting to Azure..."

    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            Write-OK "Connected to Azure"
        }
        else {
            Write-OK "Reusing existing Azure session: $($azContext.Account)"
        }

        $mdcTargetRoles = @("Owner", "Contributor", "Security Admin")

        Write-Step "Enumerating all accessible subscriptions..."
        $allSubscriptions = Get-AzSubscription -ErrorAction Stop
        Write-OK "Found $($allSubscriptions.Count) subscription(s) in tenant"

        $mdcSubScan  = @()
        $mdcRbacRows = @()

        foreach ($sub in $allSubscriptions) {
            Write-Step "  Checking [$($sub.Name)] ($($sub.Id))..."

            try {
                Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null

                $pricingTiers = Get-AzSecurityPricing -ErrorAction SilentlyContinue
                $enabledPlans = $pricingTiers |
                                    Where-Object { $_.PricingTier -eq "Standard" } |
                                    Select-Object -ExpandProperty Name
                $isMDCEnabled = ($null -ne $enabledPlans -and $enabledPlans.Count -gt 0)

                $mdcSubScan += [PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    TenantId         = $sub.TenantId
                    MDCEnabled       = $isMDCEnabled
                    EnabledPlanCount = if ($isMDCEnabled) { $enabledPlans.Count } else { 0 }
                    EnabledPlans     = if ($isMDCEnabled) { ($enabledPlans -join "; ") } else { "" }
                    ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }

                if ($isMDCEnabled) {
                    Write-OK "  MDC ENABLED: $($sub.Name) | Plans: $($enabledPlans -join ', ')"

                    $subScope = "/subscriptions/$($sub.Id)"
                    $allRbac  = Get-AzRoleAssignment -Scope $subScope -ErrorAction SilentlyContinue

                    $matched = 0
                    foreach ($ra in $allRbac) {
                        if ($ra.RoleDefinitionName -in $mdcTargetRoles) {

                            $scopeLevel = switch -Wildcard ($ra.Scope) {
                                "/subscriptions/*/resourceGroups/*/providers/*" { "Resource" }
                                "/subscriptions/*/resourceGroups/*"             { "ResourceGroup" }
                                "/subscriptions/*"                              { "Subscription" }
                                "/providers/Microsoft.Management/*"             { "ManagementGroup" }
                                default                                         { "Other" }
                            }

                            $mdcRbacRows += [PSCustomObject]@{
                                SubscriptionId   = $sub.Id
                                SubscriptionName = $sub.Name
                                MDCEnabledPlans  = ($enabledPlans -join "; ")
                                RoleName         = $ra.RoleDefinitionName
                                PrincipalName    = $ra.DisplayName
                                PrincipalType    = $ra.ObjectType
                                PrincipalId      = $ra.ObjectId
                                SignInName       = $ra.SignInName
                                Scope            = $ra.Scope
                                ScopeLevel       = $scopeLevel
                                CanDelegate      = $ra.CanDelegate
                                ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            }
                            $matched++
                        }
                    }
                    Write-OK "  Exported $matched targeted role assignment(s) for $($sub.Name)"
                }
                else {
                    Write-Warn "  MDC not enabled: $($sub.Name)"
                }
            }
            catch {
                Write-Warn "  Could not process subscription [$($sub.Name)]: $_"
            }
        }

        Export-Results -Data $mdcSubScan  -FileName "4_MDC_Subscription_Scan" -Format $ExportFormat
        Export-Results -Data $mdcRbacRows -FileName "4_MDC_RBAC_Assignments"  -Format $ExportFormat

        $mdcCount = ($mdcSubScan | Where-Object MDCEnabled -eq $true).Count
        Write-OK "MDC enabled on $mdcCount of $($allSubscriptions.Count) subscription(s)"
        Write-OK "Total targeted RBAC rows exported: $($mdcRbacRows.Count)"
    }
    catch {
        Write-Error "Defender for Cloud scan failed: $_"
    }
}
else {
    Write-Warn "Defender for Cloud scan skipped. Use -ScanDefenderForCloud to enable."
}

# =============================================================================
# SECTION 5: Microsoft Purview - Compliance Role Groups
# =============================================================================

Write-Header "5/6  Microsoft Purview - Compliance Role Groups"

if ($IncludePurview) {

    if (-not $PurviewAdminUPN) {
        Write-Warn "Purview scan skipped -- provide -PurviewAdminUPN 'admin@yourtenant.com'"
    }
    else {
        Write-Step "Connecting to Purview / Security and Compliance Center..."

        try {
            Connect-IPPSSession -UserPrincipalName $PurviewAdminUPN -ErrorAction Stop
            Write-OK "Connected to Purview / Security and Compliance Center"

            Write-Step "Fetching all compliance role groups..."
            $allRoleGroups = Get-RoleGroup -ErrorAction Stop
            Write-OK "Found $($allRoleGroups.Count) compliance role group(s)"

            $purviewMembers = @()

            foreach ($rg in $allRoleGroups) {
                Write-Step "  Processing: $($rg.Name)"

                try {
                    $members = Get-RoleGroupMember -Identity $rg.Name -ErrorAction SilentlyContinue

                    # $rg.Roles returns Exchange objects whose ToString() resolves to a DN path -- extract .Name explicitly
                    $roleList = ""
                    try {
                        $roleList = ($rg.Roles | ForEach-Object {
                            if ($_ -is [string]) { ($_ -split "/")[-1] }
                            elseif ($_.Name)     { $_.Name }
                            else                 { ($_.ToString() -split "/")[-1] }
                        }) -join "; "
                    }
                    catch { $roleList = ($rg.Roles -join "; ") }

                    if (-not $members -or $members.Count -eq 0) {
                        $purviewMembers += [PSCustomObject]@{
                            RoleGroupName        = $rg.Name
                            RoleGroupDescription = $rg.Description
                            RoleGroupType        = $rg.RoleGroupType
                            AssignedRoles        = $roleList
                            MemberDisplayName    = "(No members)"
                            MemberUPN            = ""
                            MemberType           = ""
                            ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                    else {
                        foreach ($m in $members) {
                            $purviewMembers += [PSCustomObject]@{
                                RoleGroupName        = $rg.Name
                                RoleGroupDescription = $rg.Description
                                RoleGroupType        = $rg.RoleGroupType
                                AssignedRoles        = $roleList
                                MemberDisplayName    = $m.DisplayName
                                MemberUPN            = if (-not [string]::IsNullOrWhiteSpace($m.WindowsLiveId)) { $m.WindowsLiveId } elseif (-not [string]::IsNullOrWhiteSpace($m.PrimarySmtpAddress)) { $m.PrimarySmtpAddress } else { $m.Name }
                                MemberType           = $m.RecipientTypeDetails
                                ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            }
                        }
                    }
                }
                catch {
                    Write-Warn "  Could not get members for '$($rg.Name)': $_"
                }
            }

            Export-Results -Data $purviewMembers -FileName "5_Purview_RoleGroups" -Format $ExportFormat
            Write-OK "Total Purview role group member entries: $($purviewMembers.Count)"

            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-OK "Purview session disconnected"
        }
        catch {
            Write-Error "Purview connection or data retrieval failed: $_"
            Write-Warn "Required Purview roles: Compliance Management or View-Only Recipients"
        }
    }
}
else {
    Write-Warn "Purview export skipped. Use -IncludePurview -PurviewAdminUPN 'admin@tenant.com' to enable."
}


# =============================================================================
# SECTION 6: Microsoft Defender XDR - Complete RBAC
# =============================================================================

if ($IncludeXDRRBAC) {

    Write-Header "6/6  Defender XDR - Complete RBAC Export"

    function Resolve-GroupMembersForMDE {
        param([string]$GroupId, [string]$GroupName)
        $resolved = @()
        try {
            $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $odataType = $m.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", ""
                if ($odataType -eq "user") {
                    $u = Get-MgUser -UserId $m.Id `
                            -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" `
                            -ErrorAction SilentlyContinue
                    $resolved += [PSCustomObject]@{
                        MemberDisplayName = $u.DisplayName
                        MemberUPN         = $u.UserPrincipalName
                        MemberMail        = $u.Mail
                        MemberType        = "User (via Group)"
                        GroupName         = $GroupName
                        GroupId           = $GroupId
                        AccountEnabled    = $u.AccountEnabled
                        Department        = $u.Department
                        JobTitle          = $u.JobTitle
                        MemberId          = $m.Id
                    }
                }
            }
        }
        catch {
            Write-Warn "  Could not resolve members for group $GroupName : $_"
        }
        return $resolved
    }

    # Two tokens required:
    #   wdatpToken : api.securitycenter.microsoft.com  (sections 6a-6d)
    #   secToken   : api.security.microsoft.com        (section 6d Advanced Hunting)
    $Script:wdatpToken = $null
    $Script:secToken   = $null

    if ([string]::IsNullOrWhiteSpace($AppClientId) -or [string]::IsNullOrWhiteSpace($AppClientSecret)) {
        Write-Warn "  No App Registration params supplied (-AppClientId / -AppClientSecret). Section 6 will be skipped."
    }
    else {
        $resolvedTenant = if (-not [string]::IsNullOrWhiteSpace($AppTenantId)) { $AppTenantId } else { (Get-MgContext).TenantId }
        Write-Step "  App Registration Tenant : $resolvedTenant"
        Write-Step "  App Registration Client : $AppClientId"

        function Get-MdeToken {
            param([string]$Scope)
            try {
                $r = Invoke-RestMethod -Method POST `
                    -Uri  "https://login.microsoftonline.com/$resolvedTenant/oauth2/v2.0/token" `
                    -Body @{ grant_type = "client_credentials"; client_id = $AppClientId; client_secret = $AppClientSecret; scope = $Scope } `
                    -ErrorAction Stop
                return $r.access_token
            }
            catch {
                Write-Warn "    Token request failed for scope '$Scope': $_"
                return $null
            }
        }

        Write-Step "  Acquiring WDATP token  (api.securitycenter.microsoft.com)..."
        $Script:wdatpToken = Get-MdeToken -Scope "https://api.securitycenter.microsoft.com/.default"
        if ($Script:wdatpToken) { Write-OK "  WDATP token acquired" } else { Write-Warn "  WDATP token failed -- sections 6a/6b/6c/6d will be skipped." }

        Write-Step "  Acquiring XDR Security token (api.security.microsoft.com)..."
        $Script:secToken = Get-MdeToken -Scope "https://api.security.microsoft.com/.default"
        if ($Script:secToken) { Write-OK "  XDR Security token acquired" } else { Write-Warn "  XDR Security token failed -- section 6d Advanced Hunting will be skipped." }
    }

    function Invoke-MdeApi {
        param([string]$Uri, [string]$Token)
        if (-not $Token) { Write-Warn "  No token available for: $Uri"; return @() }
        $hdrs = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
        $all  = @()
        $next = $Uri
        do {
            try {
                $r    = Invoke-RestMethod -Method GET -Uri $next -Headers $hdrs -ErrorAction Stop
                $vals = if ($r.value) { $r.value } elseif ($r.Results) { $r.Results } else { @() }
                $all += $vals
                $next = $r.'@odata.nextLink'
            }
            catch {
                $msg = $_.ToString()
                if ($msg -like "*404*") {
                    # 404 on /api/roles is expected for Unified RBAC tenants -- not a real failure
                } else {
                    Write-Warn "    MDE API call failed ($next): $_"
                }
                break
            }
        } while ($next)
        return $all
    }

    # -------------------------------------------------------------------------
    # [COMMENTED OUT] MDE UnifiedRoles -- legacy MDE custom roles (pre-Feb 2025 tenants only)
    # Uncomment if your tenant has legacy MDE RBAC enabled
    # -------------------------------------------------------------------------
    <#
    Write-Step "MDE UnifiedRoles: Fetching custom roles (Settings > Endpoints > Roles)..."
    $mdeRolesRaw = Invoke-MdeApi -Uri "https://api.security.microsoft.com/api/roles" -Token $Script:wdatpToken
    if ($mdeRolesRaw.Count -gt 0) {
        $mdeUnifiedRoles = $mdeRolesRaw | ForEach-Object {
            [PSCustomObject]@{
                RoleId          = $_.id
                RoleDisplayName = $_.name
                RoleDescription = $_.description
                IsEnabled       = $_.enabled
                Permissions     = ($_.permissions -join "; ")
                AssignedGroups  = ($_.roleGroups | ForEach-Object { $_.name }) -join "; "
                ExportedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }
        Export-Results -Data $mdeUnifiedRoles -FileName "6_MDE_UnifiedRoles" -Format $ExportFormat
        Write-OK "  UnifiedRoles - Found $($mdeUnifiedRoles.Count) role(s)"
    }
    #>
    $mdeRolesRaw = @()


    # -------------------------------------------------------------------------
    # 6b - MDE_RBAC / 6c - Identity Audit via Advanced Hunting (KQL)
    # Queries IdentityInfo for identities with Entra roles or group memberships.
    # Cross-references Section 1 to flag blind spots.
    # -------------------------------------------------------------------------
    Write-Step "6b/6c - MDE RBAC & Identity Audit via Advanced Hunting (KQL)..."

    $mdeIdentityAudit = @()

    $entraKnownUPNs_6d = @()
    if ($entraRoleAssignments.Count -gt 0) {
        $entraKnownUPNs_6d = $entraRoleAssignments |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.MemberUPN) } |
            Select-Object -ExpandProperty MemberUPN -Unique
    }

    try {
        if (-not $Script:secToken) {
            Write-Warn "  6d - Skipped: no XDR Security token."
            Write-Warn "  Ensure AdvancedHunting.Read.All (Application) is granted on Microsoft Threat Protection."
        }
        else {
            $kqlQuery = @'
IdentityInfo
| where isnotempty(AssignedRoles) or isnotempty(GroupMembership)
| summarize arg_max(Timestamp, *) by AccountObjectId
| project AccountUpn, AccountDisplayName, AccountObjectId, Department, JobTitle,
          IsAccountEnabled, AssignedRoles, GroupMembership, RiskLevel, BlastRadius, IdentityEnvironment
| order by AccountDisplayName asc
'@

            $body = @{ Query = $kqlQuery } | ConvertTo-Json
            $hdrs = @{ Authorization = "Bearer $($Script:secToken)"; "Content-Type" = "application/json" }

            Write-Step "  Submitting Advanced Hunting query to IdentityInfo table..."
            $ahResult = $null
            try {
                $ahResult = Invoke-RestMethod -Method POST `
                    -Uri     "https://api.security.microsoft.com/api/advancedhunting/run" `
                    -Headers $hdrs -Body $body -ErrorAction Stop
            }
            catch {
                Write-Warn "  6d - Advanced Hunting query failed: $_"
                Write-Warn "  Verify AdvancedHunting.Read.All is granted and admin consent applied."
            }

            if ($ahResult -and $ahResult.Results -and $ahResult.Results.Count -gt 0) {
                Write-OK "  6d - Advanced Hunting returned $($ahResult.Results.Count) identity record(s)"

                foreach ($identity in $ahResult.Results) {

                    $rolesStr    = if ($identity.AssignedRoles)   { ($identity.AssignedRoles   | ForEach-Object { $_ }) -join "; " } else { "" }
                    $groupsStr   = if ($identity.GroupMembership) { ($identity.GroupMembership | ForEach-Object { $_ }) -join "; " } else { "" }
                    $isBlindSpot = ($identity.AccountUpn -notin $entraKnownUPNs_6d) -and (-not [string]::IsNullOrWhiteSpace($identity.AccountUpn))

                    # Users have a UPN; apps/service principals do not
                    $identityType = if (-not [string]::IsNullOrWhiteSpace($identity.AccountUpn)) { "User" }
                                    elseif ($identity.IdentityEnvironment -eq "Cloud" -and [string]::IsNullOrWhiteSpace($identity.Department)) { "App" }
                                    else { "ServicePrincipal" }

                    $mdeIdentityAudit += [PSCustomObject]@{
                        IdentityType         = $identityType
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
                        InSection1Export     = if ($isBlindSpot) { "NO - NOT IN ENTRA ROLE EXPORT" } else { "Yes" }
                        BlindSpotFlag        = if ($isBlindSpot) { "REVIEW REQUIRED" } else { "" }
                        ExportedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                }

                $blindSpotCount = ($mdeIdentityAudit | Where-Object { $_.BlindSpotFlag -eq "REVIEW REQUIRED" }).Count
                Write-OK "  6b - Identity audit complete: $($mdeIdentityAudit.Count) identities, $blindSpotCount blind spot(s)"

                $blindSpots = ($mdeIdentityAudit | Where-Object { $_.BlindSpotFlag -eq "REVIEW REQUIRED" }).Count
                if ($blindSpots -gt 0) {
                    Write-Warn "  ACTION REQUIRED: $blindSpots identities not in Section 1 -- filter BlindSpotFlag=REVIEW REQUIRED in 6b_MDE_RBAC."
                }
                else {
                    Write-OK "  No blind spots detected -- all identities with roles/groups are covered in Section 1."
                }
            }
            else {
                Write-Warn "  6d - No results from Advanced Hunting. Verify Defender for Identity or Entra ID connector is active."
            }
        }
    }
    catch {
        Write-Warn "  6d - Advanced Hunting section failed: $_"
    }

    Export-Results -Data $mdeIdentityAudit -FileName "6b_MDE_RBAC" -Format $ExportFormat

    Write-Host ""
    Write-Host "  XDR Complete RBAC Export Summary" -ForegroundColor Cyan
    Write-Host "  --------------------------------" -ForegroundColor Cyan
    Write-Host "  6b  MDE RBAC : $($mdeIdentityAudit.Count) identities (filter BlindSpotFlag=REVIEW REQUIRED for gaps)" -ForegroundColor White
    Write-Host ""

    if ($mdeRoles.Count -eq 0 -and $mdeRoleAssignments.Count -eq 0) {
        Write-Warn "  Sections 6a/6b returned 0 roles -- expected for XDR Unified RBAC tenants (post Feb 2025)."
        Write-Warn "  MDE access is controlled via Entra ID roles (see 6c) and group memberships (see 6d)."
    }
}
else {
    Write-Warn "XDR RBAC export skipped. Use -IncludeXDRRBAC to enable."
    Write-Warn "Without MDE custom RBAC, access is controlled by Entra ID roles (see 1_EntraID_Roles)."
}

# =============================================================================
# Final Summary
# =============================================================================

Write-Header "Export Complete"

$files = Get-ChildItem -Path $OutputPath -File
Write-Host ""
Write-Host "  Files written to: $OutputPath" -ForegroundColor Cyan
Write-Host ""
foreach ($f in $files) {
    Write-Host "    $($f.Name)  ($([math]::Round($f.Length / 1KB, 1)) KB)" -ForegroundColor White
}
Write-Host ""

$manifest = [PSCustomObject]@{
    ExportTimestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    TenantId                = (Get-MgContext).TenantId
    ExportedBy              = (Get-MgContext).Account
    SentinelWorkspaceCount  = $SentinelWorkspaces.Count
    IncludedPIM             = $IncludePIM.IsPresent
    ScannedDefenderForCloud = $ScanDefenderForCloud.IsPresent
    IncludedPurview         = $IncludePurview.IsPresent
    IncludedXDRRBAC         = $IncludeXDRRBAC.IsPresent
    EntraRoleCount          = $entraRoleAssignments.Count
    MDERBACCount            = if ($IncludeXDRRBAC) { $mdeIdentityAudit.Count }   else { "skipped" }
    FilesGenerated          = $files.Count
}

$manifest | ConvertTo-Json | Out-File "$OutputPath\00_ExportManifest.json" -Encoding UTF8
Write-OK "Manifest written -> 00_ExportManifest.json"

Disconnect-MgGraph | Out-Null
Write-OK "Graph session disconnected"

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
