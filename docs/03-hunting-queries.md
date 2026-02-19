# Hunting Queries Documentation

## Overview

Created 5 proactive threat hunting queries for manual investigation.

---

## Query 1: Sign-ins from Unusual Countries

**File:** `hunting-queries/unusual-locations.kql`

**Purpose:** Identify sign-ins from countries not typically seen

**MITRE:** T1078 - Valid Accounts
```kql
let knownCountries = dynamic(["US", "United States"]);
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where Country !in (knownCountries)
| summarize 
    SignInCount = count(),
    Users = make_set(UserPrincipalName),
    IPs = make_set(IPAddress)
    by Country
| order by SignInCount desc
```

---

## Query 2: Sign-ins Outside Business Hours

**File:** `hunting-queries/off-hours-signins.kql`

**Purpose:** Identify sign-ins outside 6 AM - 10 PM

**MITRE:** T1078 - Valid Accounts
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 22
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    HourOfDay,
    AppDisplayName
| order by TimeGenerated desc
```

---

## Query 3: Recently Created User Accounts

**File:** `hunting-queries/recent-accounts.kql`

**Purpose:** List all accounts created in past 7 days

**MITRE:** T1136 - Create Account
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add user"
| where Result == "success"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend TargetDisplayName = tostring(TargetResources[0].displayName)
| project 
    TimeGenerated,
    InitiatedBy,
    TargetUser,
    TargetDisplayName
| order by TimeGenerated desc
```

---

## Query 4: Sign-in to Admin Activity Chain

**File:** `hunting-queries/signin-admin-chain.kql`

**Purpose:** Find sign-ins quickly followed by admin actions

**MITRE:** T1078, T1136
```kql
let SignIns = SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| project SignInTime = TimeGenerated, UserPrincipalName, IPAddress;
let AdminActions = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has_any ("Add user", "Add member to role", "Update user", "Delete user")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project ActionTime = TimeGenerated, Actor, OperationName;
SignIns
| join kind=inner (AdminActions) on $left.UserPrincipalName == $right.Actor
| where ActionTime between (SignInTime .. SignInTime + 1h)
| project 
    SignInTime,
    UserPrincipalName,
    IPAddress,
    ActionTime,
    OperationName,
    TimeDelta = ActionTime - SignInTime
| order by SignInTime desc
```

---

## Query 5: Legacy Authentication Attempts

**File:** `hunting-queries/legacy-auth-attempts.kql`

**Purpose:** Identify usage of legacy authentication protocols

**MITRE:** T1078 - Valid Accounts
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients")
| summarize 
    AttemptCount = count(),
    SuccessCount = countif(ResultType == 0),
    FailCount = countif(ResultType != 0)
    by UserPrincipalName, ClientAppUsed, IPAddress
| order by AttemptCount desc
```
