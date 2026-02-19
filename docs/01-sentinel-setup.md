# Microsoft Sentinel Setup Guide

## Prerequisites

- Azure Free Account (or existing subscription)
- Microsoft Entra ID with P2 trial
- Global Administrator access

## Step 1: Create Log Analytics Workspace

1. Go to: **Azure Portal** (https://portal.azure.com)

2. Search for: **"Log Analytics workspaces"**

3. Click **"+ Create"**

4. Configure:
   | Setting | Value |
   |---------|-------|
   | Subscription | Your Azure subscription |
   | Resource Group | Create new: `RG-Sentinel-Lab` |
   | Name | `LAW-Sentinel-Lab` |
   | Region | Same as your Entra ID |

5. Click **"Review + Create"** → **"Create"**

## Step 2: Enable Microsoft Sentinel

1. Search for: **"Microsoft Sentinel"**

2. Click **"+ Create"**

3. Select your workspace: `LAW-Sentinel-Lab`

4. Click **"Add"**

5. Wait 2-3 minutes for deployment

## Step 3: Connect Entra ID Data

1. In Sentinel, go to: **Configuration** → **Data connectors**

2. Search for: **"Microsoft Entra ID"**

3. Click **"Open connector page"**

4. Enable these log types:
   - ✅ Sign-in logs
   - ✅ Audit logs
   - ✅ Non-interactive sign-in logs
   - ✅ Service principal sign-in logs
   - ✅ Managed identity sign-in logs
   - ✅ Risky users
   - ✅ User risk events

5. Click **"Apply Changes"** for each section

## Step 4: Generate Activity & Verify Data

**Important:** Sentinel only ingests data from the moment the connector is enabled — no historical backfill!

1. **Generate activity:**
   - Sign in with a test user
   - Browse around Entra admin center
   - Make a small change (edit user property)

2. **Wait 5-10 minutes**

3. **Verify data is flowing:**
   - Go to: **Sentinel** → **General** → **Logs**
   - Run:
```kql
   SigninLogs
   | take 10
   | order by TimeGenerated desc
```

4. If results appear → Data is flowing ✅

## Sentinel Navigation Reference
```
Microsoft Sentinel
├── General
│   ├── Overview
│   ├── Logs              ← Run KQL queries here
│   └── Search
├── Threat management
│   ├── Incidents         ← View security incidents
│   ├── Workbooks         ← Dashboards
│   ├── Hunting           ← Threat hunting queries
│   └── Entity behavior
├── Content management
│   └── Content hub       ← Install solutions
└── Configuration
├── Data connectors   ← Connect data sources
├── Analytics         ← Detection rules
└── Automation        ← Playbooks
```
