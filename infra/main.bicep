// Azure infrastructure for Jibril Correlation Agent
// Deploys: Cosmos DB (NoSQL, serverless, free tier) + Container Apps + managed identity RBAC

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Base name for resources')
param baseName string = 'jibril'

@description('Container image to deploy')
param containerImage string = 'ghcr.io/samueltauil/jibril-correlation-agent:latest'

@description('GitHub App ID for Copilot Extension')
@secure()
param githubAppId string = ''

@description('GitHub App private key (PEM)')
@secure()
param githubAppPrivateKey string = ''

@description('Webhook secret for Jibril event ingestion')
@secure()
param webhookSecret string = ''

@description('Repository for auto-alert issues (owner/repo)')
param alertRepo string = ''

@description('Container image to GitHub repo mappings (image1=owner/repo1,image2=owner/repo2)')
param repoMappings string = ''

// ─── Cosmos DB ───────────────────────────────────────────────────────────────

resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: '${baseName}-cosmos'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    enableFreeTier: true
    disableLocalAuth: true
    capacityMode: 'Serverless'
    locations: [
      {
        locationName: location
        failoverPriority: 0
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
  }
}

resource cosmosDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmosAccount
  name: baseName
  properties: {
    resource: {
      id: baseName
    }
  }
}

resource eventsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDatabase
  name: 'events'
  properties: {
    resource: {
      id: 'events'
      partitionKey: {
        paths: ['/eventType']
        kind: 'Hash'
      }
      defaultTtl: 86400
    }
  }
}

resource chainsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDatabase
  name: 'chains'
  properties: {
    resource: {
      id: 'chains'
      partitionKey: {
        paths: ['/scope']
        kind: 'Hash'
      }
      defaultTtl: -1
    }
  }
}

resource correlationContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDatabase
  name: 'correlation'
  properties: {
    resource: {
      id: 'correlation'
      partitionKey: {
        paths: ['/key']
        kind: 'Hash'
      }
      defaultTtl: 3600
    }
  }
}

// ─── Container Apps Environment ──────────────────────────────────────────────

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${baseName}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${baseName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// ─── Container App ───────────────────────────────────────────────────────────

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${baseName}-agent'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'github-app-private-key'
          value: githubAppPrivateKey
        }
        {
          name: 'webhook-secret'
          value: webhookSecret
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'agent'
          image: containerImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            { name: 'PORT', value: '3000' }
            { name: 'COSMOS_ENDPOINT', value: cosmosAccount.properties.documentEndpoint }
            { name: 'COSMOS_DATABASE', value: baseName }
            { name: 'GITHUB_APP_ID', value: githubAppId }
            { name: 'GITHUB_APP_PRIVATE_KEY', secretRef: 'github-app-private-key' }
            { name: 'WEBHOOK_SECRET', secretRef: 'webhook-secret' }
            { name: 'ALERT_REPO', value: alertRepo }
            { name: 'REPO_MAPPINGS', value: repoMappings }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 3000
              }
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 3000
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
}

// ─── RBAC: Cosmos DB Data Contributor for Container App ──────────────────────

// Built-in role: Cosmos DB Built-in Data Contributor
// See: https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac#built-in-role-definitions
var cosmosDataContributorRoleId = '00000000-0000-0000-0000-000000000002'

resource cosmosRoleAssignment 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmosAccount
  name: guid(cosmosAccount.id, containerApp.id, cosmosDataContributorRoleId)
  properties: {
    roleDefinitionId: '${cosmosAccount.id}/sqlRoleDefinitions/${cosmosDataContributorRoleId}'
    principalId: containerApp.identity.principalId
    scope: cosmosAccount.id
  }
}

// ─── Outputs ─────────────────────────────────────────────────────────────────

output agentUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output cosmosEndpoint string = cosmosAccount.properties.documentEndpoint
output containerAppPrincipalId string = containerApp.identity.principalId
