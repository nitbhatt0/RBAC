
================================================================================

Section-wise permissions required (for the user running the script)

Section 1 — Entra ID Directory Roles (always runs)
Entra role → Global Reader or Security Reader
Graph scope → RoleManagement.Read.All
Graph scope → Directory.Read.All
Graph scope → User.Read.All
Graph scope → Group.Read.All
Enterprise app → Must be assigned to Microsoft Graph Command Line Tools (if tenant has Assignment Required enabled)

Section 2 — PIM Eligible Assignments (-IncludePIM)
Entra role → Global Reader or Security Reader
Graph scope → RoleManagement.Read.All
Graph scope → Directory.Read.All
Graph scope → User.Read.All
Graph scope → Group.Read.All
Graph scope → Application.Read.All (required for resolving Service Principal PIM assignments)
Tenant license → Entra ID P2 required on tenant

Section 3 — Sentinel Workspace RBAC (-SentinelWorkspaces)
Azure role → Reader on each Sentinel Resource Group
Azure role → Reader on Subscription (Section 3b custom role inspection)
Note → Reader at Resource Group scope does not cover subscription-level role definitions — both scopes are needed

Section 4 — Defender for Cloud (-ScanDefenderForCloud)
Azure role → Security Reader on each Subscription
Note → Security Reader includes Reader — one role covers both Get-AzSecurityPricing and Get-AzRoleAssignment

Section 5 — Microsoft Purview (-IncludePurview)
Purview role → View-Only Organization Management (on the -PurviewAdminUPN account)
Graph scope → Group.Read.All (already granted in Section 1 — reused for group expansion)
Graph scope → User.Read.All (already granted in Section 1 — reused for expanded member lookup)
Note → The -PurviewAdminUPN account needs the Purview role — can be a different account from the one running the script

Section 6 — Defender XDR / MDE RBAC (-IncludeXDRRBAC)
Auth method → App Registration only (-AppClientId, -AppClientSecret) — not the user account
App permission → WindowsDefenderATP : AdvancedQuery.Read.All (Application + Admin Consent)
App permission → WindowsDefenderATP : SecurityConfiguration.Read.All (Application + Admin Consent)
App permission → WindowsDefenderATP : Machine.Read.All (Application + Admin Consent)
App permission → Microsoft Threat Protection : AdvancedHunting.Read.All (Application + Admin Consent)
User role → None required — all calls use App Registration tokens

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
