# Incident Investigation Report

## Summary

Potential brute-force activity was detected against the account `admin`.

## Timeline

| Time | Event |
|---|---|
| 10:12 | Failed login attempt |
| 10:13 | Failed login attempt |
| 10:14 | Failed login attempt |
| 10:15 | Failed login attempt |
| 10:16 | Failed login attempt |

## Source

- Source IP: `192.168.1.50`
- Target User: `admin`

## Severity

High

## MITRE ATT&CK

- Technique: `T1110`
- Name: Brute Force

## Impact

Multiple failed login attempts may indicate password guessing, brute-force activity, or password spraying.

## Recommendations

- Review authentication logs.
- Check whether the source IP is trusted.
- Enable account lockout policy.
- Block suspicious IP address if confirmed malicious.
- Review successful logins after the failed attempts.
