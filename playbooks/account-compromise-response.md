# Account Compromise Response Playbook

## Trigger

Alert or report indicating potential account compromise.

## Severity Assessment

| Indicator | Severity |
|-----------|----------|
| Regular user account | Medium |
| Admin account | High |
| Service account | High |
| Multiple accounts | Critical |

---

## Response Steps

### 1. Initial Assessment (5 min)

- [ ] Identify the affected account
- [ ] Determine account type (user, admin, service)
- [ ] Check if account is currently active
- [ ] Review initial alert details

### 2. Containment (10 min)

- [ ] Disable the affected account
- [ ] Revoke all active sessions
- [ ] Block sign-ins from suspicious IPs (if identified)
- [ ] Document time of containment

### 3. Investigation (30-60 min)

- [ ] Review sign-in logs for affected account
```kql
  SigninLogs
  | where UserPrincipalName == "[ACCOUNT]"
  | where TimeGenerated > ago(24h)
  | project TimeGenerated, IPAddress, Location, ResultType, DeviceDetail
  | order by TimeGenerated desc
```

- [ ] Check for post-compromise activity
```kql
  AuditLogs
  | where TimeGenerated > ago(24h)
  | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
  | where Actor == "[ACCOUNT]"
  | project TimeGenerated, OperationName, TargetResources
  | order by TimeGenerated desc
```

- [ ] Look for persistence mechanisms
```kql
  AuditLogs
  | where OperationName in ("Add user", "Add member to role", "Add member to group")
  | where TimeGenerated > ago(24h)
  | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
  | where Actor == "[ACCOUNT]"
```

- [ ] Identify IOCs (IPs, user agents, timestamps)
- [ ] Check for lateral movement
- [ ] Take screenshots of evidence

### 4. Remediation (15 min)

- [ ] Reset password for affected account
- [ ] Review and remove suspicious MFA methods
- [ ] Delete any rogue accounts created
- [ ] Remove unauthorized role assignments
- [ ] Remove unauthorized group memberships

### 5. Recovery (10 min)

- [ ] Re-enable account (after securing)
- [ ] Notify user of incident
- [ ] Provide new credentials securely
- [ ] Monitor for 24-48 hours

### 6. Post-Incident (1-2 hours)

- [ ] Document full incident timeline
- [ ] Write incident report
- [ ] Update detection rules if needed
- [ ] Identify process improvements
- [ ] Conduct lessons learned review

---

## Escalation Criteria

| Condition | Action |
|-----------|--------|
| Admin account compromised | Escalate immediately to security lead |
| Data exfiltration suspected | Engage legal/compliance |
| Multiple accounts compromised | Declare major incident |
| Attacker still active | Engage incident response team |

---

## Communication Templates

### User Notification
```
Subject: Security Action Required - Your Account
Your account was involved in a security incident and has been temporarily secured.
Actions taken:

Your password has been reset
All active sessions have been revoked

Next steps:

Contact IT Security at [contact]
You will receive new credentials securely
Review your account activity when access is restored

If you have questions, please contact [security team].
```

### Incident Closure Comment Template
```
Incident investigated and contained.
Findings:

[Summary of what was found]
[Affected accounts/systems]
[Attack technique identified]

Actions Taken:

[List of containment actions]
[List of remediation actions]

Classification: [True Positive/False Positive] - [Category]
Status: Resolved
```
