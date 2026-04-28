=======================================================================
Entra ID Roles & XDR Portal Access — Script Coverage
=======================================================================

The script targets the following Entra ID built-in roles that grant
access to the Microsoft Defender XDR portal (security.microsoft.com),
including MDE, MDI, MDO, MDCA, and Advanced Hunting:

  - Global Administrator
  - Security Administrator
  - Security Operator
  - Security Reader
  - Global Reader
  - Compliance Administrator
  - Compliance Data Administrator
  - Information Protection Administrator
  - Helpdesk Administrator
  - Intune Administrator

These are captured in:
  - 1_Entra_Security_Roles.csv       (active assignments)
  - 2_EntraID_PIM_EligibleRoles.csv  (PIM eligible assignments)

-----------------------------------------------------------------------
Azure Subscription-Level Roles
-----------------------------------------------------------------------

The script additionally captures Azure RBAC roles relevant to
Sentinel and Defender for Cloud. These are resource-level permissions
and do not grant access to the XDR portal directly.

  Sentinel  -> Sentinel Contributor, Sentinel Reader,
               Sentinel Responder, Log Analytics Contributor
  MDC       -> Owner, Contributor, Security Admin

These are captured in:
  - 3_Sentinel_Workspace_Roles.csv
  - 4_MDC_RBAC_Assignments.csv

-----------------------------------------------------------------------
Known Gap — Unified RBAC Custom Roles
-----------------------------------------------------------------------

Custom roles created directly in the Defender portal
(Permissions & Roles > Microsoft Defender XDR) are NOT captured
by this script.

Reason: Microsoft does not currently expose a supported API endpoint
for querying Unified RBAC custom roles via application-only
authentication.

Recommendation: Export Unified RBAC custom roles manually from:
  Defender portal > System > Permissions > Roles > Export

Reference:
  https://techcommunity.microsoft.com/blog/microsoftsentinelblog/
  managing-microsoft-sentinel-and-microsoft-defender-xdr-permissions
  -in-microsoft-/4480583

=======================================================================
=======================================================================


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
