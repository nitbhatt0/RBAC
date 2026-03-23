
================================================================================

# Get-RoleAssignments.ps1  v2.0
# Exports role assignments from: Entra ID, PIM, Sentinel, Defender for Cloud, Purview, Defender XDR
#
# Requirements: PowerShell 5.1+
#
# PowerShell modules (auto-installed if missing):
#   Always required:
#     Microsoft.Graph.Identity.DirectoryManagement
#     Microsoft.Graph.Users
#     Microsoft.Graph.Groups
#   -IncludePIM:
#     Microsoft.Graph.Identity.Governance   (+ Entra P2 license on tenant)
#   -SentinelWorkspaces / -ScanDefenderForCloud:
#     Az.Accounts, Az.Resources
#   -ScanDefenderForCloud:
#     Az.Security
#   -IncludePurview:
#     ExchangeOnlineManagement
#
# Graph API delegated scopes (interactive login, Sections 1-5):
#   RoleManagement.Read.All   - read directory role assignments
#   Directory.Read.All        - read role definitions
#   User.Read.All             - resolve user details
#   Group.Read.All            - resolve group details
#   Application.Read.All      - resolve service principals in PIM (Section 2)
#
# Purview account (-PurviewAdminUPN):
#   Requires: View-Only Organization Management or Compliance Management role in Purview
#
# Section 6 App Registration (grant Admin Consent for each):
#   WindowsDefenderATP (Application)          : Machine.Read.All
#                                               SecurityConfiguration.Read.All
#                                               AdvancedQuery.Read.All
#   Microsoft Threat Protection (Application) : AdvancedHunting.Read.All
#
# Usage examples:
#   # Sections 1-2 only (Entra + PIM):
#   .\Get-RoleAssignments.ps1 -IncludePIM
#
#   # Full run with all sections:
#   .\Get-RoleAssignments.ps1 -IncludePIM -ScanDefenderForCloud -IncludePurview `
#       -PurviewAdminUPN "admin@tenant.com" -IncludeXDRRBAC `
#       -AppClientId "xxx" -AppClientSecret "xxx" -TenantId "xxx" `
#       -SentinelWorkspaces @(@{ WorkspaceId="ws-id"; ResourceGroup="rg"; SubscriptionId="sub-id" })
#
# Author: Nitin
======================================


# RBAC
Scan and Export current RBAC assingment across Entra, MDC, XDR, Purview.

For Sentinel- you can add multiple workspaces. by using
 -SentinelWorkspaces @(
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";  SubscriptionId = "xxx" },
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";   SubscriptionId = "xxx" } 
)


For MDC, the Script will scan all subscriptions that have MDC enabled.
and then will scan/export only these assignments--Owner, Contributor
