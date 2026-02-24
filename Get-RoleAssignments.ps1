# =============================================================================
# Get-RoleAssignments.ps1
# Downloads current role assignments from:
#   - Microsoft Entra ID (Azure AD)         - Directory Roles
#   - Microsoft Entra ID (PIM)              - Eligible Role Assignments
#   - Microsoft Defender XDR               - Security and Admin Roles
#   - Microsoft Sentinel                   - Workspace RBAC Roles
#   - Microsoft Defender for Cloud         - Owner, Contributor, Security Admin
#                                            across ALL MDC-enabled subscriptions
#   - Microsoft Purview                    - Compliance Role Groups and Members
#
# Prerequisites:
#   Install-Module Microsoft.Graph          -Scope CurrentUser
#   Install-Module Az                       -Scope CurrentUser
#   Install-Module Az.Security              -Scope CurrentUser   (for MDC scan)
#   Install-Module ExchangeOnlineManagement -Scope CurrentUser   (for Purview)
#
# Author : Nitin
# Version: 1.2
# =============================================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    # --- Multi-workspace Sentinel support ---
    # Pass one or more workspace definitions as a hashtable array. Each entry must
    # contain three keys: WorkspaceId, ResourceGroup, SubscriptionId
    #
    # Single workspace:
    #   -SentinelWorkspaces @(
    #       @{ WorkspaceId = "ws-id-1"; ResourceGroup = "rg-sentinel"; SubscriptionId = "sub-id-1" }
    #   )
    #
    # Multiple workspaces:
    #   -SentinelWorkspaces @(
    #       @{ WorkspaceId = "ws-id-1"; ResourceGroup = "rg-sentinel-prod"; SubscriptionId = "sub-id-1" },
    #       @{ WorkspaceId = "ws-id-2"; ResourceGroup = "rg-sentinel-dev";  SubscriptionId = "sub-id-2" },
    #       @{ WorkspaceId = "ws-id-3"; ResourceGroup = "rg-sentinel-corp"; SubscriptionId = "sub-id-3" }
    #   )
    [Parameter(HelpMessage = "Array of Sentinel workspace definitions: @{ WorkspaceId=''; ResourceGroup=''; SubscriptionId='' }")]
    [hashtable[]]$SentinelWorkspaces = @(),

    [Parameter(HelpMessage = "Output folder path. Defaults to timestamped folder in current directory.")]
    [string]$OutputPath = ".\RoleAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(HelpMessage = "Export format: CSV, JSON, or Both.")]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",

    [Parameter(HelpMessage = "Include PIM eligible role assignments (requires Entra P2).")]
    [switch]$IncludePIM,

    [Parameter(HelpMessage = "Scan ALL accessible subscriptions for MDC and export targeted RBAC.")]
    [switch]$ScanDefenderForCloud,

    [Parameter(HelpMessage = "Export Microsoft Purview compliance role groups and their members.")]
    [switch]$IncludePurview,

    [Parameter(HelpMessage = "Admin UPN used to connect to Purview (required when -IncludePurview is set).")]
    [string]$PurviewAdminUPN
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
    param(
        [object[]]$Data,
        [string]$FileName,
        [string]$Format
    )
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Warn "No data to export for: $FileName"
        return
    }
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
# Setup - Output folder and module loading
# =============================================================================

Write-Header "Microsoft Security Stack - Role Assignments Export v1.2"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-OK "Output folder created: $OutputPath"
}

# Build required module list based on switches
$requiredModules = @(
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups"
)
if ($IncludePIM)           { $requiredModules += "Microsoft.Graph.Identity.Governance" }
if ($SubscriptionId)       { $requiredModules += "Az.Accounts", "Az.Resources" }
if ($ScanDefenderForCloud) { $requiredModules += "Az.Accounts", "Az.Resources", "Az.Security" }
if ($IncludePurview)       { $requiredModules += "ExchangeOnlineManagement" }

# Deduplicate
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
    Connect-MgGraph -Scopes "RoleManagement.Read.All",
                             "Directory.Read.All",
                             "User.Read.All",
                             "Group.Read.All" -ErrorAction Stop
    Write-OK "Connected to Microsoft Graph"
}
catch {
    Write-Error "Graph connection failed: $_"
    exit 1
}

Write-Step "Fetching active directory role assignments..."

$entraRoleAssignments = @()

try {
    $activeRoles = Get-MgDirectoryRole -All -ErrorAction Stop

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
                            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }

                    "servicePrincipal" {
                        $spNameKey = "displayName"
                        $spName    = $member.AdditionalProperties[$spNameKey]

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

    Export-Results -Data $entraRoleAssignments -FileName "1_EntraID_Roles" -Format $ExportFormat
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

        foreach ($assignment in $eligibleAssignments) {
            $principalId = $assignment.PrincipalId
            $roleDefId   = $assignment.RoleDefinitionId

            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition `
                           -UnifiedRoleDefinitionId $roleDefId `
                           -ErrorAction SilentlyContinue

            $user = Get-MgUser -UserId $principalId `
                        -Property "DisplayName,UserPrincipalName,Mail,Department" `
                        -ErrorAction SilentlyContinue

            $pimAssignments += [PSCustomObject]@{
                RoleName          = $roleDef.DisplayName
                RoleId            = $roleDefId
                MemberDisplayName = if ($user) { $user.DisplayName } else { $principalId }
                MemberUPN         = $user.UserPrincipalName
                MemberMail        = $user.Mail
                MemberDepartment  = $user.Department
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
# SECTION 3: Defender XDR and Sentinel Roles
# =============================================================================

Write-Header "3/6  Microsoft Defender XDR - Security and Admin Roles"
Write-Step "Filtering Defender-relevant roles from Entra ID data..."

$defenderRoleNames = @(
    "Security Administrator",
    "Security Reader",
    "Security Operator",
    "Global Administrator",
    "Compliance Administrator",
    "Compliance Data Administrator",
    "Cloud App Security Administrator",
    "Attack Simulation Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "Privileged Role Administrator",
    "Global Reader"
)

if ($entraRoleAssignments.Count -gt 0) {
    $defenderRoles = $entraRoleAssignments |
        Where-Object { $_.RoleName -in $defenderRoleNames } |
        Select-Object RoleName, MemberType, MemberDisplayName, MemberUPN,
                      MemberDepartment, AccountEnabled, AssignmentType, ExportedAt

    Export-Results -Data $defenderRoles -FileName "3_DefenderXDR_Roles" -Format $ExportFormat
}
else {
    Write-Warn "Skipped Defender role filter - Entra ID data not available."
}

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

        # Validate all three required keys are present and non-empty
        if (-not $ws.WorkspaceId -or -not $ws.ResourceGroup -or -not $ws.SubscriptionId) {
            Write-Warn "Workspace $wsIndex skipped -- missing one or more required keys (WorkspaceId, ResourceGroup, SubscriptionId)"
            continue
        }

        $wsSubId = $ws.SubscriptionId
        $wsRG    = $ws.ResourceGroup
        $wsId    = $ws.WorkspaceId

        Write-Step "  Workspace $wsIndex/$($SentinelWorkspaces.Count): $wsId (RG: $wsRG, Sub: $wsSubId)"

        try {
            # Switch to the correct subscription for this workspace
            Set-AzContext -SubscriptionId $wsSubId -ErrorAction Stop | Out-Null

            $sentinelScope = "/subscriptions/$wsSubId/resourceGroups/$wsRG"

            $wsRoles = Get-AzRoleAssignment -Scope $sentinelScope -ErrorAction Stop |
                Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames } |
                ForEach-Object {
                    [PSCustomObject]@{
                        WorkspaceId      = $wsId
                        ResourceGroup    = $wsRG
                        SubscriptionId   = $wsSubId
                        RoleName         = $_.RoleDefinitionName
                        PrincipalName    = $_.DisplayName
                        PrincipalType    = $_.ObjectType
                        SignInName       = $_.SignInName
                        Scope            = $_.Scope
                        ExportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
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

    # Single combined export across all workspaces
    Export-Results -Data $allSentinelRoles -FileName "4_Sentinel_Workspace_Roles" -Format $ExportFormat

    # Also export a per-workspace summary
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

    Export-Results -Data $sentinelSummary -FileName "4_Sentinel_Workspace_Summary" -Format $ExportFormat
    Write-OK "Total Sentinel role assignments across all workspaces: $($allSentinelRoles.Count)"
}
else {
    Write-Warn "Sentinel workspace roles skipped. Use -SentinelWorkspaces to provide workspace definitions."
    Write-Warn "  Example: -SentinelWorkspaces @(@{ WorkspaceId='ws-id'; ResourceGroup='rg-name'; SubscriptionId='sub-id' })"
}

# =============================================================================
# SECTION 4: Defender for Cloud - All Subscriptions RBAC Scan
# =============================================================================

Write-Header "4/6  Defender for Cloud - Subscription RBAC Scan"

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

        # Roles to capture for MDC-enabled subscriptions
        $mdcTargetRoles = @("Owner", "Contributor", "Security Admin")

        Write-Step "Enumerating all accessible subscriptions..."
        $allSubscriptions = Get-AzSubscription -ErrorAction Stop
        Write-OK "Found $($allSubscriptions.Count) subscription(s) in tenant"

        $mdcSubScan   = @()   # One row per subscription scanned
        $mdcRbacRows  = @()   # RBAC assignments from MDC-enabled subscriptions

        foreach ($sub in $allSubscriptions) {
            Write-Step "  Checking [$($sub.Name)] ($($sub.Id))..."

            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

                # Get Defender for Cloud pricing tiers - Standard = MDC plan enabled
                $pricingTiers   = Get-AzSecurityPricing -ErrorAction SilentlyContinue
                $enabledPlans   = $pricingTiers |
                                    Where-Object { $_.PricingTier -eq "Standard" } |
                                    Select-Object -ExpandProperty Name
                $isMDCEnabled   = ($null -ne $enabledPlans -and $enabledPlans.Count -gt 0)

                # Record the subscription scan result
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

                    # Pull RBAC assignments for this subscription
                    $subScope  = "/subscriptions/$($sub.Id)"
                    $allRbac   = Get-AzRoleAssignment -Scope $subScope -ErrorAction SilentlyContinue

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

        # Export subscription scan summary
        Export-Results -Data $mdcSubScan  -FileName "5_MDC_Subscription_Scan" -Format $ExportFormat

        # Export RBAC rows from MDC-enabled subscriptions
        Export-Results -Data $mdcRbacRows -FileName "5_MDC_RBAC_Assignments"  -Format $ExportFormat

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
        Write-Step "  (Uses ExchangeOnlineManagement module via Connect-IPPSSession)"

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

                    # Flatten the Roles collection to a readable string
                    $roleList = ""
                    try {
                        $roleList = ($rg.Roles | ForEach-Object {
                            if ($_ -is [string]) { $_ } else { $_.Name }
                        }) -join "; "
                    }
                    catch { $roleList = $rg.Roles -join "; " }

                    if (-not $members -or $members.Count -eq 0) {
                        # Record empty role groups -- useful for clean-up review
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
                                MemberUPN            = $m.WindowsLiveId
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

            # Full member export
            Export-Results -Data $purviewMembers -FileName "6_Purview_RoleGroups" -Format $ExportFormat

            # Summary - role group name, member count, assigned roles
            $purviewSummary = $purviewMembers |
                Group-Object RoleGroupName |
                ForEach-Object {
                    $realMembers = $_.Group | Where-Object { $_.MemberUPN -ne "" }
                    [PSCustomObject]@{
                        RoleGroupName   = $_.Name
                        MemberCount     = $realMembers.Count
                        AssignedRoles   = $_.Group[0].AssignedRoles
                        Description     = $_.Group[0].RoleGroupDescription
                    }
                } |
                Sort-Object MemberCount -Descending

            Export-Results -Data $purviewSummary -FileName "6_Purview_RoleGroups_Summary" -Format $ExportFormat

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
# Summary
# =============================================================================

Write-Header "6/6  Export Complete"

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
    EntraRoleCount          = $entraRoleAssignments.Count
    FilesGenerated          = $files.Count
}

$manifest | ConvertTo-Json | Out-File "$OutputPath\00_ExportManifest.json" -Encoding UTF8
Write-OK "Manifest written -> 00_ExportManifest.json"

Disconnect-MgGraph | Out-Null
Write-OK "Graph session disconnected"

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
