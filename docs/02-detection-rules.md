# Detection Rules Documentation

## Overview

Created 4 custom analytics rules to detect various attack techniques. Built-in templates were evaluated but many required UEBA (User Entity Behavior Analytics) which takes 24+ hours to populate data.

## Built-in Templates Evaluation

| Rule | Status | Reason |
|------|--------|--------|
| Sign-ins from IPs that attempt sign-ins to disabled accounts | Skipped | Requires UEBA (BehaviorAnalytics table) |
| Brute force against Azure Portal | Skipped | Not applicable to scenario |
| Other UEBA-dependent rules | Skipped | UEBA requires 24+ hours to generate data |

**Decision:** Created custom KQL detection rules instead — demonstrates more skill and works immediately.

---

## Rule 1: Suspicious Sign-in from New Device

**File:** `detection-rules/suspicious-signin-new-device.kql`

### Overview

| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| MITRE ATT&CK | T1078 - Valid Accounts |
| Frequency | Every 1 hour |
| Lookback | 1 hour |

### Original Issue

Initial rule used `DeviceDetail.deviceId` which is often **empty** for browser-based sign-ins (especially InPrivate/Incognito).

### Solution

Changed detection logic to use **Browser + OS combination** instead of Device ID.

### Final Query
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| extend 
    Browser = tostring(DeviceDetail.browser),
    OS = tostring(DeviceDetail.operatingSystem)
| where isnotempty(Browser) and isnotempty(OS)
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated between (ago(14d) .. ago(1h))
    | where ResultType == 0
    | extend 
        Browser = tostring(DeviceDetail.browser),
        OS = tostring(DeviceDetail.operatingSystem)
    | distinct UserPrincipalName, Browser, OS
) on UserPrincipalName, Browser, OS
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    Browser,
    OS,
    AppDisplayName
```

---

## Rule 2: Multiple Failed Sign-in Attempts (Brute Force)

**File:** `detection-rules/brute-force-detection.kql`

### Overview

| Attribute | Value |
|-----------|-------|
| Severity | High |
| MITRE ATT&CK | T1110 - Brute Force |
| Frequency | Every 5 minutes |
| Lookback | 10 minutes |
| Threshold | 5+ failed attempts |

### Query
```kql
let threshold = 5;
let timeframe = 10m;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != 0
| summarize 
    FailedAttempts = count(),
    TargetUsers = make_set(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress, Location
| where FailedAttempts >= threshold
| project 
    IPAddress,
    Location,
    FailedAttempts,
    TargetUsers,
    FirstAttempt,
    LastAttempt,
    AttackDuration = LastAttempt - FirstAttempt
```

---

## Rule 3: New User Account Created

**File:** `detection-rules/new-user-created.kql`

### Overview

| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| MITRE ATT&CK | T1136 - Create Account |
| Frequency | Every 5 minutes |
| Lookback | 5 minutes |

### Query
```kql
AuditLogs
| where OperationName == "Add user"
| where Result == "success"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend TargetDisplayName = tostring(TargetResources[0].displayName)
| project 
    TimeGenerated,
    InitiatedBy,
    TargetUser,
    TargetDisplayName,
    OperationName,
    Result,
    CorrelationId
```

---

## Rule 4: User Added to Privileged Role

**File:** `detection-rules/privilege-escalation.kql`

### Overview

| Attribute | Value |
|-----------|-------|
| Severity | High |
| MITRE ATT&CK | T1078 - Valid Accounts (Privilege Escalation) |
| Frequency | Every 5 minutes |
| Lookback | 5 minutes |

### Original Issue

Role name is **not** in `TargetResources[0].displayName` or `TargetResources[1].displayName`. It's nested inside the **modifiedProperties** array.

### Solution

Used `mv-expand` to extract role name from `modifiedProperties` where `displayName == "Role.DisplayName"`.

### Final Query
```kql
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where ModifiedProperty.displayName == "Role.DisplayName"
| extend RoleName = tostring(ModifiedProperty.newValue)
| where RoleName has_any ("Admin", "Administrator", "Global", "Privileged", "Security")
| project 
    TimeGenerated,
    InitiatedBy,
    TargetUser,
    RoleName,
    OperationName
```

---

## Summary

| Rule | Status | Key Learning |
|------|--------|--------------|
| Suspicious Sign-in | ✅ Working | DeviceId often empty; use Browser+OS |
| Brute Force | ✅ Working | Straightforward implementation |
| New User Created | ✅ Working | Straightforward implementation |
| Privilege Escalation | ✅ Working | Role name in modifiedProperties; use mv-expand |
