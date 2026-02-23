.\Get-RoleAssignments.ps1 `
 -SentinelWorkspaces @(
      @{ WorkspaceId = "b7aa54dd-970d-4c78-8f56-5ab1942884c3"; ResourceGroup = "nit-rg1";  SubscriptionId = "f07ec78d-739f-40a0-bcbc-d71385becc02" },
      @{ WorkspaceId = "e50e8f96-5857-4d26-b09f-b3e84a3cd865"; ResourceGroup = "nit-rg1";   SubscriptionId = "f07ec78d-739f-40a0-bcbc-d71385becc02" } 
) `
  -IncludePIM `
  -ScanDefenderForCloud `
  -IncludePurview `
  -PurviewAdminUPN "admin@MngEnvMCAP107482.onmicrosoft.com" `
  -ExportFormat Both