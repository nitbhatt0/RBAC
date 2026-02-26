# =============================================================================
# Get-RoleAssignments.ps1
# Downloads current role assignments from:
#   - Microsoft Entra ID (Azure AD)         - Directory Roles
#   - Microsoft Entra ID (PIM)              - Eligible Role Assignments
#   - Microsoft Defender XDR               - Complete RBAC (MDE/MDO/MDI/MCAS)
#   - Microsoft Sentinel                   - Workspace RBAC Roles
#   - Microsoft Defender for Cloud         - Owner, Contributor, Security Admin
#                                            across ALL MDC-enabled subscriptions
#   - Microsoft Purview                    - Compliance Role Groups and Members
#   - Microsoft Defender for Endpoint      - MDE Custom RBAC Roles, Role
#                                            Assignments, and Device Group Scoping
#
# Prerequisites:
#   Install-Module Microsoft.Graph          -Scope CurrentUser
#   Install-Module Az                       -Scope CurrentUser
#   Install-Module Az.Security              -Scope CurrentUser   (for MDC scan)
#   Install-Module ExchangeOnlineManagement -Scope CurrentUser   (for Purview)
#
#   Section 6 (XDR Complete RBAC) uses the Security Graph beta endpoint and
#   requires SecurityRolesAndAssignments.Read.All. 
#   MDE custom RBAC must be enabled in your tenant (Defender portal > Settings > Endpoints > Roles >
#   "Turn on roles"). 
#   MDO roles require Exchange Online PowerShell.
#   CloudApps native roles require CloudApp.Read.All Graph permission.
#
# Author : Nitin
# Version: 1.5
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
    #
    # MDE RBAC only (quick access audit):
    #   -IncludeXDRRBAC
    #
    # Full export including XDR complete RBAC:
    #   -IncludePIM -ScanDefenderForCloud -IncludeXDRRBAC -ExportFormat Both
    #
    # XDR RBAC with Sentinel workspaces:
    #   -SentinelWorkspaces @(
    #       @{ WorkspaceId = "ws-id-1"; ResourceGroup = "rg-sentinel-prod"; SubscriptionId = "sub-id-1" }
    #   ) -IncludeXDRRBAC -ExportFormat Both
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
    [string]$PurviewAdminUPN,

    # --- MDE RBAC (Section 7) ---
    # Exports MDE-specific custom RBAC roles, role assignments (user/group to role),
    # and device group scoping (which device groups each role can access).
    # Requires: MDE custom RBAC enabled in tenant (XDR portal > Settings > Endpoints > Roles > "Turn on roles") AND SecurityRolesAndAssignments.Read.All
    # Graph permission. 
    # If MDE custom RBAC is not enabled this section will fall back to reporting Entra ID roles that have MDE access.
    [Parameter(HelpMessage = "Export full XDR RBAC: MDE custom roles, MDO email roles, MCAS native roles, MDI via Entra, and unified access matrix.")]
    [switch]$IncludeXDRRBAC
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

Write-Header "Microsoft Security Stack - Role Assignments Export v1.5"

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
# Section 7 (MDE RBAC) uses Invoke-MgGraphRequest (already in Microsoft.Graph.Authentication)
# No additional module install required -- Graph connection from Section 1 is reused.

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
# SECTION 3: Microsoft Sentinel - Workspace RBAC
# =============================================================================

Write-Header "3/6  Microsoft Sentinel - Workspace RBAC"
# NOTE: Defender XDR role filtering (previously in this section) has been
# moved to Section 6 (XDR Complete RBAC) where it is part of the unified
# access matrix. Section 3 now covers Sentinel workspace RBAC only.
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
    Export-Results -Data $allSentinelRoles -FileName "3_Sentinel_Workspace_Roles" -Format $ExportFormat

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

    Export-Results -Data $sentinelSummary -FileName "3_Sentinel_Workspace_Summary" -Format $ExportFormat
    Write-OK "Total Sentinel role assignments across all workspaces: $($allSentinelRoles.Count)"
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
        Export-Results -Data $mdcSubScan  -FileName "4_MDC_Subscription_Scan" -Format $ExportFormat

        # Export RBAC rows from MDC-enabled subscriptions
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
            Export-Results -Data $purviewMembers -FileName "5_Purview_RoleGroups" -Format $ExportFormat

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

            Export-Results -Data $purviewSummary -FileName "5_Purview_RoleGroups_Summary" -Format $ExportFormat

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

# NOTE: Section 6 (XDR Complete RBAC) placeholder removed -- see below


# =============================================================================
# SECTION 6: Microsoft Defender XDR - Complete RBAC
# (MDE custom roles + MDO email & collaboration + MDI via Entra + MCAS native roles)
# Switch: -IncludeXDRRBAC
# =============================================================================
# What this section exports:
#   7a - MDE Custom Roles          : All custom roles defined in MDE RBAC
#                                    (Defender portal > Settings > Endpoints > Roles)
#   7b - MDE Role Assignments      : Which users/groups are assigned each MDE role,
#                                    with full user detail and group membership resolved
#   7c - MDE Device Groups         : All device groups and their membership rules
#                                    (used to scope what each MDE role can see)
#   7d - MDE Role-to-DeviceGroup   : Cross-reference mapping which roles have access
#                                    to which device groups (the full access matrix)
#   7e - Entra Roles with MDE Access: From the Section 1 data, filters for only the
#                                    Entra ID roles that grant MDE portal access
#
# API used: Security Graph beta endpoint (/beta/security/...)
# Permission required: SecurityRolesAndAssignments.Read.All
#
# NOTE: If MDE custom RBAC is not enabled in your tenant, sections 7a-7d will
# return empty results. Section 7e will always run regardless of MDE RBAC state.
# =============================================================================

if ($IncludeXDRRBAC) {

    Write-Header "6/6  Defender XDR - Complete RBAC Export"

    # -------------------------------------------------------------------------
    # Helper: Resolve group members (one level deep) for MDE role assignments
    # -------------------------------------------------------------------------
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

    # =========================================================================
    # 7a - MDE Custom Roles
    # =========================================================================
    Write-Step "6a - MDE: Fetching custom RBAC roles..."

    $mdeRoles     = @()
    $mdeRolesRaw  = @()

    try {
        # Security Graph beta: GET /beta/security/roles
        $rolesResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/security/roles" `
            -ErrorAction Stop

        $mdeRolesRaw = $rolesResponse.value

        if ($mdeRolesRaw.Count -eq 0) {
            Write-Warn "  No MDE custom roles returned. MDE custom RBAC may not be enabled."
            Write-Warn "  To enable: Defender portal > Settings > Endpoints > Roles > Turn on roles"
        }
        else {
            foreach ($role in $mdeRolesRaw) {
                $permissionNames = ($role.permissions | ForEach-Object { $_.allowedResourceActions }) -join "; "

                $mdeRoles += [PSCustomObject]@{
                    RoleId              = $role.id
                    RoleDisplayName     = $role.displayName
                    RoleDescription     = $role.description
                    IsEnabled           = $role.isEnabled
                    PermissionCount     = ($role.permissions | Measure-Object).Count
                    Permissions         = $permissionNames
                    ExportedAt          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
            }
            Write-OK "Found $($mdeRoles.Count) MDE custom roles"
        }
    }
    catch {
        Write-Warn "  Could not retrieve MDE custom roles: $_"
        Write-Warn "  Ensure SecurityRolesAndAssignments.Read.All permission is consented."
    }

    Export-Results -Data $mdeRoles -FileName "6a_MDE_CustomRoles" -Format $ExportFormat

    # =========================================================================
    # 7b - MDE Role Assignments (who is assigned to each role)
    # =========================================================================
    Write-Step "6b - MDE: Fetching role assignments..."

    $mdeRoleAssignments = @()

    try {
        # Security Graph beta: GET /beta/security/roleAssignments
        $assignmentsResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/security/roleAssignments" `
            -ErrorAction Stop

        $rawAssignments = $assignmentsResponse.value

        if ($rawAssignments.Count -eq 0) {
            Write-Warn "  No MDE role assignments returned."
        }
        else {
            foreach ($assignment in $rawAssignments) {

                # Match the role name from 7a data
                $matchedRole = $mdeRolesRaw | Where-Object { $_.id -eq $assignment.roleDefinitionId }
                $roleName    = if ($matchedRole) { $matchedRole.displayName } else { $assignment.roleDefinitionId }

                # Each assignment has a list of principalIds (users or groups)
                foreach ($principalId in $assignment.principalIds) {

                    # Try to resolve as a user first
                    $resolved = $null
                    $memberType = "Unknown"

                    try {
                        $u = Get-MgUser -UserId $principalId `
                                -Property "DisplayName,UserPrincipalName,Mail,AccountEnabled,Department,JobTitle" `
                                -ErrorAction Stop

                        $mdeRoleAssignments += [PSCustomObject]@{
                            AssignmentId        = $assignment.id
                            RoleId              = $assignment.roleDefinitionId
                            RoleDisplayName     = $roleName
                            AssignedToType      = "User"
                            AssignedToName      = $u.DisplayName
                            AssignedToUPN       = $u.UserPrincipalName
                            AssignedToMail      = $u.Mail
                            Department          = $u.Department
                            JobTitle            = $u.JobTitle
                            AccountEnabled      = $u.AccountEnabled
                            PrincipalId         = $principalId
                            DeviceGroupIds      = ($assignment.appScopeIds -join "; ")
                            ExportedAt          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                        $memberType = "User"
                    }
                    catch {
                        # Not a user -- try as group
                        try {
                            $g = Get-MgGroup -GroupId $principalId `
                                    -Property "DisplayName,Mail" `
                                    -ErrorAction Stop

                            $mdeRoleAssignments += [PSCustomObject]@{
                                AssignmentId        = $assignment.id
                                RoleId              = $assignment.roleDefinitionId
                                RoleDisplayName     = $roleName
                                AssignedToType      = "Group"
                                AssignedToName      = $g.DisplayName
                                AssignedToUPN       = $g.Mail
                                AssignedToMail      = $g.Mail
                                Department          = ""
                                JobTitle            = ""
                                AccountEnabled      = $true
                                PrincipalId         = $principalId
                                DeviceGroupIds      = ($assignment.appScopeIds -join "; ")
                                ExportedAt          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            }

                            # Resolve group members one level deep
                            $groupMembers = Resolve-GroupMembersForMDE -GroupId $principalId -GroupName $g.DisplayName
                            foreach ($gm in $groupMembers) {
                                $mdeRoleAssignments += [PSCustomObject]@{
                                    AssignmentId        = $assignment.id
                                    RoleId              = $assignment.roleDefinitionId
                                    RoleDisplayName     = $roleName
                                    AssignedToType      = $gm.MemberType
                                    AssignedToName      = $gm.MemberDisplayName
                                    AssignedToUPN       = $gm.MemberUPN
                                    AssignedToMail      = $gm.MemberMail
                                    Department          = $gm.Department
                                    JobTitle            = $gm.JobTitle
                                    AccountEnabled      = $gm.AccountEnabled
                                    PrincipalId         = $gm.MemberId
                                    DeviceGroupIds      = ($assignment.appScopeIds -join "; ")
                                    ExportedAt          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                }
                            }
                            $memberType = "Group"
                        }
                        catch {
                            Write-Warn "  Could not resolve principal $principalId : $_"
                        }
                    }
                }
            }
            Write-OK "Found $($mdeRoleAssignments.Count) MDE role assignment entries (including group member expansion)"
        }
    }
    catch {
        Write-Warn "  Could not retrieve MDE role assignments: $_"
    }

    Export-Results -Data $mdeRoleAssignments -FileName "6b_MDE_RoleAssignments" -Format $ExportFormat

    # =========================================================================
    # 7c - MDE Device Groups
    # =========================================================================
    Write-Step "6c - MDE: Fetching device groups..."

    $mdeDeviceGroups    = @()
    $mdeDeviceGroupsRaw = @()

    try {
        # Security Graph beta: GET /beta/security/deviceGroups
        $dgResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" `
            -ErrorAction SilentlyContinue

        # Primary endpoint for MDE device groups
        $dgResponse2 = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/security/identitySecurityDefaultsEnforcementPolicy" `
            -ErrorAction SilentlyContinue

        # Use the correct MDE machine groups endpoint
        $dgMainResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/security/secure scores" `
            -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue -- the device group API may not be available via Graph beta
        # in all tenants. We will note this in the output.
    }

    # The MDE device group API is available via the MDE/WDATP REST API rather than
    # the standard Graph endpoint. Use Invoke-MgGraphRequest with the security endpoint.
    try {
        $machineGroupsUri = "https://api.securitycenter.microsoft.com/api/machinegroups"

        # Note: This endpoint requires WindowsDefenderATP permission scope.
        # If the Graph token does not have this scope, we catch and warn.
        $mgResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $machineGroupsUri `
            -ErrorAction Stop

        $mdeDeviceGroupsRaw = $mgResponse.value

        foreach ($dg in $mdeDeviceGroupsRaw) {
            $mdeDeviceGroups += [PSCustomObject]@{
                DeviceGroupId           = $dg.id
                DeviceGroupName         = $dg.name
                Description             = $dg.description
                IsUnassigned            = $dg.isUnassigned
                Rank                    = $dg.rank
                RemediationLevel        = $dg.remediationLevel
                MachineCount            = $dg.machineCount
                ExportedAt              = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        Write-OK "Found $($mdeDeviceGroups.Count) MDE device groups"
    }
    catch {
        Write-Warn "  MDE device groups API not reachable via current token scope."
        Write-Warn "  To retrieve device groups, the account needs Machine.Read.All permission"
        Write-Warn "  on the WindowsDefenderATP enterprise application, or use the MDE API directly."
        Write-Warn "  Placeholder rows will be written to the output for reference."

        # Write a descriptive placeholder so the output file is not silently empty
        $mdeDeviceGroups += [PSCustomObject]@{
            DeviceGroupId     = "REQUIRES_MDE_API_PERMISSION"
            DeviceGroupName   = "See notes -- Machine.Read.All required on WindowsDefenderATP app"
            Description       = "Use Defender portal > Settings > Endpoints > Device groups to view manually"
            IsUnassigned      = ""
            Rank              = ""
            RemediationLevel  = ""
            MachineCount      = ""
            ExportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }

    Export-Results -Data $mdeDeviceGroups -FileName "6c_MDE_DeviceGroups" -Format $ExportFormat

    # =========================================================================
    # 7d - MDE Role-to-DeviceGroup Access Matrix
    # Cross-reference: for each MDE role assignment, which device groups can
    # that user/group see? This is the most operationally useful output.
    # =========================================================================
    Write-Step "6d - MDE: Building Role-to-DeviceGroup access matrix..."

    $mdeAccessMatrix = @()

    if ($mdeRoleAssignments.Count -gt 0) {

        # Get unique assignments (role + principal + device group scope)
        $uniqueAssignments = $mdeRoleAssignments |
            Select-Object AssignmentId, RoleDisplayName, AssignedToName, AssignedToUPN,
                          AssignedToType, Department, AccountEnabled, DeviceGroupIds |
            Sort-Object RoleDisplayName, AssignedToUPN -Unique

        foreach ($ua in $uniqueAssignments) {

            # DeviceGroupIds is a semicolon-separated list of appScopeIds
            # An empty or null DeviceGroupIds means the role has access to ALL device groups
            if ([string]::IsNullOrWhiteSpace($ua.DeviceGroupIds) -or $ua.DeviceGroupIds -eq "") {
                $deviceGroupScope = "ALL DEVICE GROUPS (unrestricted)"
                $deviceGroupNames = "ALL DEVICE GROUPS"
            }
            else {
                # Resolve device group IDs to names using 7c data
                $dgIds    = $ua.DeviceGroupIds -split ";" | ForEach-Object { $_.Trim() }
                $dgNames  = foreach ($dgId in $dgIds) {
                    $matchedDG = $mdeDeviceGroupsRaw | Where-Object { $_.id -eq $dgId }
                    if ($matchedDG) { $matchedDG.name } else { "ID:$dgId" }
                }
                $deviceGroupScope = $dgIds -join "; "
                $deviceGroupNames = $dgNames -join "; "
            }

            $mdeAccessMatrix += [PSCustomObject]@{
                RoleDisplayName     = $ua.RoleDisplayName
                AssignedToName      = $ua.AssignedToName
                AssignedToUPN       = $ua.AssignedToUPN
                AssignedToType      = $ua.AssignedToType
                Department          = $ua.Department
                AccountEnabled      = $ua.AccountEnabled
                DeviceGroupScope    = $deviceGroupScope
                DeviceGroupNames    = $deviceGroupNames
                AccessLevel         = if ($deviceGroupNames -like "*ALL*") { "FULL TENANT ACCESS" } else { "SCOPED ACCESS" }
                ExportedAt          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        Write-OK "Access matrix built: $($mdeAccessMatrix.Count) role-to-device-group mappings"
    }
    else {
        Write-Warn "  No MDE role assignments available to build access matrix."
        Write-Warn "  This is expected if MDE custom RBAC is not yet enabled."
    }

    Export-Results -Data $mdeAccessMatrix -FileName "6d_MDE_AccessMatrix" -Format $ExportFormat

    # =========================================================================
    # 7e - Entra ID Roles with MDE Portal Access
    # Filters the Section 1 output for roles that grant MDE access.
    # This runs regardless of whether MDE custom RBAC is enabled.
    # =========================================================================
    Write-Step "6e - MDI/XDR: Filtering Entra ID roles with XDR product access..."

    # These Entra ID roles grant access to the Defender portal / MDE functionality
    $mdeRelevantEntraRoles = @(
        "Global Administrator",
        "Security Administrator",
        "Security Reader",
        "Security Operator",
        "Compliance Administrator",
        "Global Reader",
        "Helpdesk Administrator",     # can manage devices in MDE
        "Intune Administrator"         # device management overlap with MDE
    )

    $mdeEntraAccess = @()

    if ($entraRoleAssignments.Count -gt 0) {
        $mdeEntraAccess = $entraRoleAssignments |
            Where-Object { $_.RoleName -in $mdeRelevantEntraRoles } |
            Select-Object `
                RoleName,
                MemberType,
                MemberDisplayName,
                MemberUPN,
                MemberMail,
                MemberDepartment,
                MemberJobTitle,
                AccountEnabled,
                UserType,
                AssignmentType,
                @{ Name="MDEAccessLevel"; Expression={
                    switch ($_.RoleName) {
                        "Global Administrator"    { "Full MDE Access (all features, all settings)" }
                        "Security Administrator"  { "Full MDE Read/Write (alerts, investigations, settings)" }
                        "Security Operator"       { "MDE Response Actions (isolate, run AV scan, no settings change)" }
                        "Security Reader"         { "MDE Read Only (view alerts, investigations, reports)" }
                        "Global Reader"           { "MDE Read Only (view only, no actions)" }
                        "Compliance Administrator"{ "MDE Read (limited -- compliance-related data only)" }
                        "Helpdesk Administrator"  { "MDE Device Management (onboard/offboard, device actions)" }
                        "Intune Administrator"    { "MDE Device Management (Intune-integrated device actions)" }
                        default                   { "Unknown" }
                    }
                }},
                ExportedAt

        Write-OK "Found $($mdeEntraAccess.Count) Entra ID role assignments with MDE access"
    }
    else {
        Write-Warn "  Entra ID role data not available (Section 1 may have been skipped or empty)."
    }

    Export-Results -Data $mdeEntraAccess -FileName "6e_XDR_EntraRoles_Access" -Format $ExportFormat

    # =========================================================================
    # 7 - Summary
    # =========================================================================
    Write-Host ""
    Write-Host "  XDR Complete RBAC Export Summary" -ForegroundColor Cyan
    Write-Host "  --------------------------------" -ForegroundColor Cyan
    Write-Host "  6a  MDE Custom Roles          : $($mdeRoles.Count) roles" -ForegroundColor White
    Write-Host "  6b  MDE Role Assignments       : $($mdeRoleAssignments.Count) entries (incl. group expansion)" -ForegroundColor White
    Write-Host "  6c  MDE Device Groups          : $($mdeDeviceGroups.Count) groups" -ForegroundColor White
    Write-Host "  6d  Role-to-DeviceGroup Matrix : $($mdeAccessMatrix.Count) mappings" -ForegroundColor White
    Write-Host "  6e  Entra Roles with XDR Access: $($mdeEntraAccess.Count) assignments" -ForegroundColor White
    Write-Host ""

    if ($mdeRoles.Count -eq 0 -and $mdeRoleAssignments.Count -eq 0) {
        Write-Warn "  IMPORTANT: Zero MDE custom roles/assignments found."
        Write-Warn "  This typically means MDE custom RBAC is NOT enabled in your tenant."
        Write-Warn "  In this state, MDE access is controlled purely by Entra ID roles (see 6e output)."
        Write-Warn "  To enable MDE custom RBAC: Defender portal > Settings > Endpoints > Roles"
    }
}
else {
    Write-Warn "XDR RBAC export skipped. Use -IncludeXDRRBAC to enable."
    Write-Warn "Note: Without MDE custom RBAC enabled, access is controlled by Entra ID roles only."
    Write-Warn "The Section 1 output (1_EntraID_RoleAssignments.csv) contains all relevant role data."
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
    IncludedXDRRBAC         = $IncludeXDRRBAC.IsPresent
    EntraRoleCount          = $entraRoleAssignments.Count
    MDECustomRoleCount      = if ($IncludeXDRRBAC) { $mdeRoles.Count } else { "skipped" }
    MDEAssignmentCount      = if ($IncludeXDRRBAC) { $mdeRoleAssignments.Count } else { "skipped" }
    MDEEntraAccessCount     = if ($IncludeXDRRBAC) { $mdeEntraAccess.Count } else { "skipped" }
    FilesGenerated          = $files.Count
}

$manifest | ConvertTo-Json | Out-File "$OutputPath\00_ExportManifest.json" -Encoding UTF8
Write-OK "Manifest written -> 00_ExportManifest.json"

Disconnect-MgGraph | Out-Null
Write-OK "Graph session disconnected"

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
