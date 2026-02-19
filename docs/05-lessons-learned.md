# Lessons Learned

## Technical Discoveries

### 1. Data Connectors Don't Backfill

**Discovery:** Sentinel data connectors only ingest data from the moment they're enabled — no historical backfill.

**Impact:** Initial queries returned empty results until fresh activity was generated.

**Solution:** Generate sign-in activity before running verification queries. Wait 5-10 minutes for data to appear.

---

### 2. Sign-in Log Terminology is Confusing

**Discovery:** "FAILURE" in sign-in logs doesn't mean the sign-in failed.

| Term | Actual Meaning |
|------|----------------|
| ResultType: FAILURE | MFA was challenged (user prompted) |
| ResultType: SUCCESS | Sign-in completed |
| ResultType: 50074 | Strong authentication required |
| ResultType: 50126 | Invalid username or password |

**Key Insight:** "FAILURE - Strong Authentication Required" followed by "SUCCESS" = MFA worked correctly!

---

### 3. Each MFA Sign-in Creates Multiple Log Entries

**Discovery:** A single sign-in with MFA generates 2 log entries:

1. Entry 1: FAILURE (MFA prompted)
2. Entry 2: SUCCESS (MFA completed)

**Impact:** Sign-in counts appear doubled. 2 sign-ins = 4 log entries.

---

### 4. Empty UserPrincipalName = Abandoned Sign-in

**Discovery:** Found log entries with empty UserPrincipalName.

**Investigation:** ResultType 50074 (MFA required), UserType "Member", IP from known network.

**Conclusion:** User started sign-in, received MFA prompt, but closed browser without completing. This is an abandoned authentication attempt — not a security concern.

---

### 5. DeviceId is Often Empty for Browser Sign-ins

**Discovery:** Initial "Suspicious Sign-in from New Device" rule didn't fire for test user Alex.

**Root Cause:** `DeviceDetail.deviceId` is frequently empty for browser-based sign-ins, especially in InPrivate/Incognito mode.

**Solution:** Rewrote rule to detect based on **Browser + OS combination** instead of Device ID:
```kql
| extend 
    Browser = tostring(DeviceDetail.browser),
    OS = tostring(DeviceDetail.operatingSystem)
```

---

### 6. Role Name is Hidden in modifiedProperties

**Discovery:** "User Added to Privileged Role" rule returned empty RoleName.

**Investigation:** Checked TargetResources[0], TargetResources[1] — both wrong.

**Root Cause:** Role name is nested inside `TargetResources[0].modifiedProperties` array, not at the top level.

**Solution:** Used `mv-expand` to extract from nested structure:
```kql
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where ModifiedProperty.displayName == "Role.DisplayName"
| extend RoleName = tostring(ModifiedProperty.newValue)
```

---

### 7. Built-in Rules Often Require UEBA

**Discovery:** Many built-in analytics rule templates showed error: "Failed to resolve table 'BehaviorAnalytics'"

**Root Cause:** These rules require User Entity Behavior Analytics (UEBA) which takes 24+ hours to populate data.

**Solution:** Created custom KQL rules instead. Better for:
- Quick lab setups
- Demonstrating KQL skills
- Tailored detection logic

---

### 8. Log Ingestion Has 5-30 Minute Delay

**Discovery:** Ran simulation, immediately checked logs — nothing appeared.

**Reality:** Sentinel log ingestion takes 5-30 minutes depending on log type and volume.

**Lesson:** Be patient during testing. Wait at least 10-15 minutes before troubleshooting "missing" data.

---

### 9. isManaged: false Means Unmanaged Device

**Discovery:** Investigation showed device with `isManaged: false`.

**Meaning:** Device is NOT enrolled in Microsoft Intune (MDM). No guarantee it meets security standards.

**Security Implication:** CA007 (Require Compliant Device) policy would block this in production if enabled.

---

### 10. Microsoft Authenticator Location Services

**Discovery:** MFA approval showed "Authenticator stopped working" error, then worked after enabling location.

**Explanation:** Microsoft Authenticator uses location verification as a fraud prevention feature. It shows WHERE the sign-in originated to help users identify suspicious requests.

---

## Process Improvements

### Detection Rule Development

1. **Test query in Logs first** before creating analytics rule
2. **Check if data exists** for the fields you're querying
3. **Start simple** and add complexity gradually
4. **Document the query logic** for future reference

### Incident Response

1. **Take screenshots** during investigation (before making changes)
2. **Document timestamps** for timeline reconstruction
3. **Update incident status** throughout investigation
4. **Write closing comments** with findings and actions

### Troubleshooting Approach

1. Check if data exists in the table
2. Verify field names and structure
3. Expand nested objects to find hidden data
4. Test query modifications incrementally

---

## Skills Gained

| Skill | Application |
|-------|-------------|
| KQL Query Writing | Created custom detection rules |
| Data Analysis | Investigated nested JSON structures |
| Troubleshooting | Fixed rule logic issues |
| Incident Response | Full investigation and remediation workflow |
| Documentation | Professional incident reports |
