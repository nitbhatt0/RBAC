# RBAC
Scan and Export current RBAC assingment across Entra, MDC, XDR, Purview.

For Sentinel- you can add multiple workspaces. by using
 -SentinelWorkspaces @(
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";  SubscriptionId = "xxx" },
      @{ WorkspaceId = "xxx"; ResourceGroup = "xxx";   SubscriptionId = "xxx" } 
)


For MDC, the Script will scan all subscriptions that have MDC enabled.
and then will scan/export only these assignments--Owner, Contributor
