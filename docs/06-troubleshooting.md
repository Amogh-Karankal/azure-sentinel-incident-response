# Troubleshooting Guide

## Common Issues and Solutions

---

### Issue: No Data After Enabling Connector

**Symptom:** Queries return empty results after enabling Entra ID data connector.

**Cause:** Connectors don't backfill historical data. Only ingests from enable moment.

**Solution:**
1. Generate activity (sign in with test user)
2. Wait 5-10 minutes
3. Run: `SigninLogs | take 10`

---

### Issue: "Failed to resolve table 'BehaviorAnalytics'"

**Symptom:** Built-in analytics rule shows semantic error.

**Cause:** Rule requires UEBA which isn't enabled or hasn't populated data yet.

**Solution:**
- Skip UEBA-dependent rules, OR
- Enable UEBA and wait 24+ hours, OR
- Create custom rules instead (recommended for labs)

---

### Issue: Detection Rule Not Firing

**Symptom:** Simulated attack but no incident created.

**Troubleshooting Steps:**

1. **Check if data exists:**
```kql
   SigninLogs
   | where TimeGenerated > ago(1h)
   | where UserPrincipalName contains "alex"
   | take 10
```

2. **Check rule query manually:**
   - Copy the rule query
   - Run in Logs
   - See if it returns results

3. **Common issues:**
   - DeviceId is empty → Use Browser+OS instead
   - Field is nested → Use mv-expand
   - Time range mismatch → Adjust lookback period

---

### Issue: Empty DeviceId in SigninLogs

**Symptom:** `DeviceDetail.deviceId` is empty, rule doesn't match.

**Cause:** Browser sign-ins (especially InPrivate) don't always report Device ID.

**Solution:** Use Browser + OS combination:
```kql
| extend 
    Browser = tostring(DeviceDetail.browser),
    OS = tostring(DeviceDetail.operatingSystem)
| where isnotempty(Browser) and isnotempty(OS)
```

---

### Issue: Empty RoleName in Privilege Escalation Rule

**Symptom:** Role assignment detected but RoleName is empty.

**Cause:** Role name is in `modifiedProperties` array, not top-level fields.

**Solution:**
```kql
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where ModifiedProperty.displayName == "Role.DisplayName"
| extend RoleName = tostring(ModifiedProperty.newValue)
```

---

### Issue: Map Visualization Not Showing Pins

**Symptom:** Workbook map loads but shows wrong location / no pins.

**Cause:** Map needs proper coordinate or country data.

**Solution:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| extend 
    Country = tostring(LocationDetails.countryOrRegion),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Country)
| summarize SignIns = count() by Country, Latitude, Longitude
```

Then configure Map Settings:
- Location info using: Latitude/Longitude
- Size by: SignIns

**Alternative:** Use table or bar chart if map is problematic.

---

### Issue: Sign-in Shows "FAILURE" but User Logged In

**Symptom:** Log shows FAILURE but user successfully accessed resources.

**Cause:** "FAILURE" means MFA was challenged, not that sign-in failed.

**Explanation:**
- Entry 1: FAILURE (MFA prompted)
- Entry 2: SUCCESS (MFA completed)

This is normal behavior — your policies are working!

---

### Issue: Ghost Sign-in with Empty Username

**Symptom:** SigninLogs entry with empty UserPrincipalName.

**Investigation Query:**
```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where isempty(UserPrincipalName)
| project TimeGenerated, ResultType, ResultDescription, IPAddress, UserType
```

**Common Causes:**
| ResultType | UserType | Meaning |
|------------|----------|---------|
| 50074 | Member | Abandoned MFA (user didn't complete) |
| Any | Empty | Service principal sign-in |
| Non-zero | Member | Failed sign-in before username captured |

**Usually not a security concern** if IP matches known network.

---

## Useful Diagnostic Queries

### Check Data Freshness
```kql
SigninLogs
| summarize LatestLog = max(TimeGenerated)
| extend MinutesAgo = datetime_diff('minute', now(), LatestLog)
```

### View Raw TargetResources Structure
```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "Add eligible member to role"
| project TargetResources
| take 1
```

### Check All Available Fields
```kql
SigninLogs
| getschema
```
