# Security policy

## Reporting a vulnerability in DanishRecon

Please do not open a public issue for a security problem in this tool. Use GitHub's
"Report a vulnerability" (Security tab > Advisories) on this repository. Include the
version (`pip show danishrecon`), what you did, and what happened.

## Responsible use

DanishRecon performs active security testing: port scans, crawling, form submission and
parameter fuzzing. Use it only against systems you own or have explicit written permission
to test. Unauthorized scanning is illegal in most jurisdictions. The authors accept no
liability for misuse.

Out of scope by design: exploitation, denial-of-service, credential brute-forcing, malware
execution, and traffic interception (ARP spoofing / MITM).
