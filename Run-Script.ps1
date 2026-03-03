.\Get-RoleAssignments.ps1 `
 -SentinelWorkspaces @(
      @{ WorkspaceId = "x-4c78-8f56-5ab1942884c3"; ResourceGroup = "xx";  SubscriptionId = "xxxx" },
      @{ WorkspaceId = "x-4d26-b09f-b3e84a3cd865"; ResourceGroup = "x";   SubscriptionId = "xxxx" } 
) `
  -IncludePIM `
  -IncludeXDRRBAC `
  -ScanDefenderForCloud `
  -IncludePurview `
  -PurviewAdminUPN "xx" `
  -AppClientId     "bxx3" `
  -AppClientSecret "xx" `
  -AppTenantId     "xx" `
  -ExportFormat Both
