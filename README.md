Permissions required (for the user running the script)

## Section 1 — Entra ID Directory Roles (always runs)

- **Entra role**
  - Global Reader or Security Reader

- **Application permissions**
  - RoleManagement.Read.All → Application
  - Directory.Read.All → Application
  - User.Read.All → Application
  - Group.Read.All → Application
  - Application.Read.All → Application


## Section 2 — PIM Eligible Assignments (-IncludePIM)

- **Entra role**
  - Global Reader or Security Reader

- **Graph scopes**
  - RoleManagement.Read.All
  - Directory.Read.All
  - User.Read.All
  - Group.Read.All
  - Application.Read.All  
    *(required for resolving Service Principal PIM assignments)*

- **Tenant license**
  - Entra ID P2 required on tenant


## Section 3 — Sentinel Workspace RBAC (-SentinelWorkspaces)

- **Azure roles**
  - Reader on each Sentinel Resource Group
  - Reader on Subscription *(Section 3b custom role inspection)*

> ⚠️ **Note:**  
> Reader at Resource Group scope does not cover subscription-level role definitions — both scopes are needed.


## Section 4 — Defender for Cloud (-ScanDefenderForCloud)

- **Azure role**
  - Security Reader on each Subscription

> ℹ️ **Note:**  
> Security Reader includes Reader — one role covers both:
> - Get-AzSecurityPricing  
> - Get-AzRoleAssignment  

## Section 5 — Microsoft Purview (-IncludePurview)

- **Purview role**
  - View-Only Organization Management *(on the `-PurviewAdminUPN` account)*

- **Graph scopes (reused from Section 1)**
  - Group.Read.All *(for group expansion)*
  - User.Read.All *(for expanded member lookup)*

> ⚠️ **Note:**  
> The `-PurviewAdminUPN` account needs the Purview role and can be a different account from the one running the script.


## Section 6 — Defender XDR / MDE RBAC (-IncludeXDRRBAC)

- **Authentication method**
  - App Registration only (`-AppClientId`, `-AppClientSecret`)
  - *(not the user account)*

- **App permissions (Application + Admin Consent required)**
  - WindowsDefenderATP → AdvancedQuery.Read.All
  - WindowsDefenderATP → SecurityConfiguration.Read.All
  - WindowsDefenderATP → Machine.Read.All
  - Microsoft Threat Protection → AdvancedHunting.Read.All

- **User role**
  - None required *(all calls use App Registration tokens)*

======================================


# RBAC
Scan and Export current RBAC assingment across Entra, MDC, XDR, Purview.

For Sentinel- you can add multiple workspaces. by using
 -SentinelWorkspaces @(
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";  SubscriptionId = "xxx" },
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";   SubscriptionId = "xxx" } 
)


For MDC, the Script will scan all subscriptions that have MDC enabled.
and then will scan/export only these assignments--Owner, Contributor, Security Admin
