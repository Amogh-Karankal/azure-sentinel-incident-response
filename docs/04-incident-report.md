# Security Incident Report

## Executive Summary

On February 16, 2026, a simulated security incident was executed and detected in the Microsoft Sentinel environment. The simulation included account compromise indicators, brute force attempts, persistence mechanisms, and privilege escalation. All attack techniques were successfully detected by custom analytics rules and resolved through proper incident response procedures.

---

## Incident Overview

| Incident ID | Type | Severity | Status |
|-------------|------|----------|--------|
| INC-001 | Suspicious Sign-in from New Device | Medium | Resolved |
| INC-002 | Multiple Failed Sign-in Attempts | High | Resolved |
| INC-003 | New User Account Created | Medium | Resolved |
| INC-004 | User Added to Privileged Role | High | Resolved |

---

## Incident 1: Suspicious Sign-in from New Device

### Details

| Field | Value |
|-------|-------|
| User | alex.security@[tenant].onmicrosoft.com |
| Source IP | [REDACTED] |
| Location | US (Phoenix area) |
| Browser | Chrome 145.0.0 |
| OS | Windows 10 |
| Device Managed | No (isManaged: false) |
| Time | Feb 16, 2026 5:56 PM |

### Investigation Findings

- Sign-in originated from new browser/OS combination
- Device was unmanaged (not enrolled in Intune)
- User successfully authenticated with MFA
- No subsequent malicious activity from this account

### Resolution
Incident investigated and contained.
Findings:

Suspicious sign-in from new device (Chrome 145, Windows 10)
Device unmanaged (isManaged: false)
User: alex.security
Location: US

Actions Taken:

Disabled compromised account
Revoked active sessions
Deleted rogue account (svc.backup)
Removed unauthorized role assignment

Classification: True Positive - Suspicious activity
Status: Resolved

---

## Incident 2: Multiple Failed Sign-in Attempts

### Details

| Field | Value |
|-------|-------|
| Target User | alex.security@[tenant].onmicrosoft.com |
| Source IP | [REDACTED] |
| Failed Attempts | 6 |
| ResultType | 50126 (Invalid password) |
| Time Window | ~5 minutes |

### Investigation Findings

- Brute force attack pattern detected
- Attacker did not successfully authenticate
- Password controls prevented compromise

### Resolution
Brute force attack detected against alex.security account.
Findings:

6 failed sign-in attempts from same IP
ResultType: 50126 (Invalid password)
Attacker did not gain access

Actions Taken:

Monitored for successful compromise (none found)
Account password verified as unchanged
No unauthorized access occurred

Classification: True Positive - Attack blocked by authentication controls
Status: Resolved

---

## Incident 3: New User Account Created

### Details

| Field | Value |
|-------|-------|
| Created Account | svc.backup@[tenant].onmicrosoft.com |
| Display Name | Backup Service |
| Created By | Admin account |
| Time | Feb 16, 2026 |

### Investigation Findings

- Suspicious account name mimicking service account
- Account created without group membership (hiding attempt)
- Persistence mechanism for continued access

### Resolution
Rogue account creation detected.
Findings:

Account created: svc.backup
Created by: [admin account]
Purpose: Attacker persistence mechanism

Actions Taken:

Deleted svc.backup account
Verified no other rogue accounts exist
Reviewed recent account creation activity

Classification: True Positive - Persistence attempt
Status: Resolved

---

## Incident 4: User Added to Privileged Role

### Details

| Field | Value |
|-------|-------|
| Target User | svc.backup@[tenant].onmicrosoft.com |
| Role Assigned | User Administrator |
| Assigned By | Admin account |
| Time | Feb 16, 2026 |

### Investigation Findings

- Rogue account received administrative privileges
- Privilege escalation technique detected
- Would allow attacker to create/modify user accounts

### Resolution
Unauthorized privilege escalation detected.
Findings:

User: svc.backup
Role assigned: User Administrator
Assigned by: [admin account]

Actions Taken:

Removed role assignment
Deleted svc.backup account
Reviewed all privileged role assignments

Classification: True Positive - Privilege escalation attempt
Status: Resolved

---

## Attack Timeline
```
Feb 16, 2026
│
├── 5:54 PM - Suspicious sign-in from new device (alex.security)
│             └── DETECTED by: Suspicious Sign-in from New Device rule
│
├── 5:55 PM - Multiple failed sign-in attempts (brute force)
│             └── DETECTED by: Multiple Failed Sign-in Attempts rule
│
├── 6:00 PM - Rogue account created (svc.backup)
│             └── DETECTED by: New User Account Created rule
│
├── 6:05 PM - Privileged role assigned to rogue account
│             └── DETECTED by: User Added to Privileged Role rule
│
├── 6:14 PM - Incidents reviewed and investigation started
│
├── 6:30 PM - Containment actions executed
│             ├── Disabled compromised account
│             ├── Revoked sessions
│             ├── Deleted rogue account
│             └── Removed role assignment
│
└── 6:54 PM - All incidents resolved and documented
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Valid Accounts | T1078 | Sign-in from new device |
| Credential Access | Brute Force | T1110 | 6 failed sign-in attempts |
| Persistence | Create Account | T1136 | svc.backup account created |
| Privilege Escalation | Valid Accounts | T1078 | User Administrator role assigned |

---

## Recommendations

### Immediate

1. ✅ Completed - Disabled compromised account
2. ✅ Completed - Revoked active sessions
3. ✅ Completed - Deleted rogue account
4. ✅ Completed - Removed unauthorized role

### Short-term

1. Enable alerts for sign-ins from new devices
2. Configure alert on new user account creation
3. Implement privileged role assignment monitoring
4. Conduct user security awareness training

### Long-term

1. Deploy phishing-resistant MFA (FIDO2 keys)
2. Implement Privileged Identity Management (PIM)
3. Enable device compliance requirements
4. Regular access reviews for privileged roles
