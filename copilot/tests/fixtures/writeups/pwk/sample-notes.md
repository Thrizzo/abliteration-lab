# Course notes — synthetic placeholder

Stand-in for personal course notes; used only to test that the `pwk` source is tagged and kept out of training data.

## Port scanning

Scan every TCP port before assuming the service list is complete.

```bash
nmap -p- -T4 192.168.50.10
```
