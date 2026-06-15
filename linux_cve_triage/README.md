# Linux Kernel CVE Triage

Systematic triage of Linux kernel CVE announcements from <https://lore.kernel.org/linux-cve-announce/> to identify vulnerabilities likely to be exploitable for **Local Privilege Escalation (LPE)** or **Container Breakout**.

CVEs are analysed in reverse chronological order.

## Data Source

The linux-cve-announce mailing list posts one message per CVE with the affected version ranges and a link to the fix commit. The backing git repo can be cloned for bulk analysis:

```bash
git clone https://git.kernel.org/pub/scm/linux/security/vulns.git linux-vulns
```

Each file in `cve/published/` contains YAML with the CVE ID, affected versions, fix commits, and a one-line description.

## Triage Criteria

CVEs are scored against the criteria in `CRITERIA.md`. A CVE that passes all "must-have" filters and scores well on "signal" indicators gets a full write-up in its own subdirectory.

## Output

Each triaged CVE of interest gets a directory `CVE-YYYY-NNNNN/` containing:
- `analysis.md` — subsystem context, vulnerability mechanics, exploitability assessment
- Links to the fix commit and any public exploit research
