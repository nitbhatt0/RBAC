# =============================================================================
# Get-RoleAssignments.ps1
# Downloads current role assignments from:
#   - Microsoft Entra ID (Azure AD) - Directory Roles
#   - Azure RBAC - Subscription/Resource Group level
#   - Microsoft Defender XDR - Security portal roles
#   - Microsoft Sentinel - Workspace roles
#
# =============================================================================
# PREREQUISITES - Run once before executing the script
# =============================================================================
#
# MODULES:
#   Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
#   Install-Module Microsoft.Graph.Users                        -Scope CurrentUser
#   Install-Module Microsoft.Graph.Groups                       -Scope CurrentUser
#   Install-Module Microsoft.Graph.Identity.Governance          -Scope CurrentUser
#   Install-Module Az.Accounts                                  -Scope CurrentUser
#   Install-Module Az.Resources                                 -Scope CurrentUser
#   Install-Module Az.Security                                  -Scope CurrentUser
#   Install-Module ExchangeOnlineManagement                     -Scope CurrentUser
#
# PERMISSIONS:
#   Entra ID Role  : Global Reader
#   Azure Role     : Reader (at Management Group or Subscription scope)--Your account needs across every subscription it will scan.
#   Purview Role   : View-Only Organization Management
# =============================================================================
# =============================================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Azure Subscription ID (for RBAC roles). Leave blank to skip.")]
    [string]$SubscriptionId,

    [Parameter(HelpMessage = "Log Analytics Workspace ID (for Sentinel roles). Leave blank to skip.")]
    [string]$SentinelWorkspaceId,

    [Parameter(HelpMessage = "Log Analytics Workspace Resource Group")]
    [string]$SentinelResourceGroup,

    [Parameter(HelpMessage = "Output folder path. Defaults to current directory.")]
    [string]$OutputPath = ".\RoleAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(HelpMessage = "Export as CSV, JSON, or Both")]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",

    [Parameter(HelpMessage = "Include PIM eligible assignments")]
    [switch]$IncludePIM
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
# Setup
# =============================================================================


if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-OK "Output folder created: $OutputPath"
}

$requiredModules = @(
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups"
)
if ($IncludePIM)     { $requiredModules += "Microsoft.Graph.Identity.Governance" }
if ($SubscriptionId) { $requiredModules += "Az.Accounts", "Az.Resources" }

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Warn "Module not found: $mod  -- run: Install-Module $mod"
    }
}

# =============================================================================
# SECTION 1: Entra ID Directory Roles
# =============================================================================

Write-Header "1/4  Entra ID - Directory Role Assignments"
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

            # Read odata.type safely into a plain variable first
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

Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All  | Export-Csv PIM_Eligible.csv
Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All   | Export-Csv PIM_Active.csv



# =============================================================================
# SECTION 2: PIM Eligible Assignments
# =============================================================================

if ($IncludePIM) {
    Write-Header "2/4  Entra ID - PIM Eligible Role Assignments"
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
        Write-Warn "PIM data retrieval failed (requires P2 licence + Identity Governance module): $_"
    }
}
else {
    Write-Warn "PIM eligible assignments skipped. Use -IncludePIM switch to include them."
}


# =============================================================================
# SECTION 3: Defender XDR and Sentinel Roles
# =============================================================================

Write-Header "3/3  Microsoft Defender XDR - Security and Admin Roles"
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

if ($SentinelWorkspaceId -and $SentinelResourceGroup -and $SubscriptionId) {
    Write-Step "Fetching Sentinel workspace RBAC roles..."

    $sentinelRoleNames = @(
        "Microsoft Sentinel Contributor",
        "Microsoft Sentinel Reader",
        "Microsoft Sentinel Responder",
        "Microsoft Sentinel Automation Contributor",
        "Log Analytics Contributor",
        "Log Analytics Reader"
    )

    try {
        $sentinelScope = "/subscriptions/$SubscriptionId/resourceGroups/$SentinelResourceGroup"

        $sentinelRoles = Get-AzRoleAssignment -Scope $sentinelScope -ErrorAction Stop |
            Where-Object { $_.RoleDefinitionName -in $sentinelRoleNames } |
            Select-Object @{N = "RoleName";      E = { $_.RoleDefinitionName }},
                          @{N = "PrincipalName"; E = { $_.DisplayName }},
                          @{N = "PrincipalType"; E = { $_.ObjectType }},
                          @{N = "SignInName";    E = { $_.SignInName }},
                          @{N = "Scope";         E = { $_.Scope }},
                          @{N = "ExportedAt";    E = { (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }}

        Export-Results -Data $sentinelRoles -FileName "4_Sentinel_Workspace_Roles" -Format $ExportFormat
    }
    catch {
        Write-Warn "Sentinel role retrieval failed: $_"
    }
}

# =============================================================================
# Summary
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
    ExportTimestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    TenantId        = (Get-MgContext).TenantId
    ExportedBy      = (Get-MgContext).Account
    SubscriptionId  = $SubscriptionId
    IncludedPIM     = $IncludePIM.IsPresent
    EntraRoleCount  = $entraRoleAssignments.Count
    FilesGenerated  = $files.Count
}

$manifest | ConvertTo-Json | Out-File "$OutputPath\00_ExportManifest.json" -Encoding UTF8
Write-OK "Manifest written -> 00_ExportManifest.json"

Disconnect-MgGraph | Out-Null
Write-OK "Graph session disconnected"

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
