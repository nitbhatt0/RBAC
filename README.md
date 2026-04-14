Permissions required (for the user running the script)

## Section 1 — Entra ID Directory Roles (always runs)

- **Application permissions**
  - RoleManagement.Read.All → Application
  - Directory.Read.All → Application
  - User.Read.All → Application
  - Group.Read.All → Application
  - Application.Read.All → Application
  - PrivilegedAccess.Read.AzureADGroup → Application (for PIM for Groups expansion on role-assigned groups)


## Section 2 — PIM Eligible Assignments (-IncludePIM)


- **Application permissions**
  - RoleManagement.Read.All → Application
  - Directory.Read.All → Application
  - User.Read.All → Application
  - Group.Read.All → Application
  - PrivilegedAccess.Read.AzureADGroup → Application
  - AdvancedHunting.Read.All → Application (Section 6b (XDR Advanced Hunting).
  - Application.Read.All  → Application
    *(required for resolving Service Principal PIM assignments)*

- **Tenant license**
  - Entra ID P2 required on tenant


## Section 3 — Sentinel Workspace RBAC (-SentinelWorkspaces)
- Assign 'Reader' or 'Security Reader' to the App Registration service principal on that subscription. (Same required for Section 4 as well)
- **Azure roles**
  - Reader on each Sentinel Resource Group
  - Reader on Subscription *(Section 3b custom role inspection)*

> **Note:**  
> Reader at Resource Group scope does not cover subscription-level role definitions — both scopes are needed.


## Section 4 — Defender for Cloud (-ScanDefenderForCloud)
- Assign 'Reader' or 'Security Reader' to the App Registration service principal on that subscription.
- **Azure role**
  - Security Reader on each Subscription

> ℹ️ **Note:**  
> Security Reader includes Reader — one role covers both:
> - Get-AzSecurityPricing  
> - Get-AzRoleAssignment  

## Section 5 — Microsoft Purview (-IncludePurview)

- **Purview role**
  - View-Only Organization Management *(on the `-PurviewAdminUPN` account)*

- **Application permissions (reused from Section 1)**
  - Group.Read.All *(for group expansion)* → Application
  - User.Read.All *(for expanded member lookup)* → Application

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
