# SENTRY  Behavioral Detection for the 2016 Bangladesh Bank SWIFT Toolkit

**8 vendor-neutral SIGMA rules, a full reverse-engineering record, a validated simulation environment, and a regulatory mapping  for a malware family that had zero published detection content for eight years.**

> 📄 **Full technical write-up:** [SENTRY01.md](./SENTRY01.md)  the complete report (static analysis, Ghidra deep-dive, attribution, IOCs, all 8 rules explained, environment build, testing, GRC mapping).
> 📑 **Companion academic paper:** *link coming soon*

---

## What's in this repo

| Path | Contents |
|---|---|
| [`SENTRY01.md`](./SENTRY01.md) | The full technical report  read this first if you want the whole story |
| [`/rules`](./rules) | 8 SIGMA detection rules, ready to use with pySigma or [sigconverter.io](https://sigconverter.io) |
| [`/scripts`](./scripts) | Emulator scripts that reproduce each documented malware behavior (the real malware was never sourced or used) |
| [`/sysmon`](./sysmon) | Working Sysmon configuration used to validate the rules |
| [`/sql`](./sql) | Oracle schema, audit policy, and attack-simulation SQL used in the test environment |
| [`/docs`](./docs) | Per-folder detail docs explaining what each file does and how it maps to a specific rule |

## Quick summary

In 2016, an attacker used a three-binary Windows malware toolkit (`evtdiag.exe`, `evtsys.exe`, `nroff_b.exe`) to patch SWIFT Alliance Access's local Oracle database library in memory, delete fraudulent transaction records, and forge printed confirmations  enabling the attempted theft of $951M and the successful diversion of $81M from Bangladesh Bank. Despite extensive vendor and government forensic coverage since, no deployable detection content for this specific toolkit had ever been published.

This project:
- Extended the public reverse-engineering record of all three binaries (30+ findings not in prior public reports, including two corrections to the only peer-reviewed academic paper on this malware)
- Derived 8 SIGMA rules from the resulting behavior taxonomy, including 2 multi-event correlation rules
- Built and validated a full simulation environment (Windows + Oracle + the documented SWIFT Alliance Access file structure) since the real proprietary application cannot legally be obtained outside SWIFT membership
- Converted every rule to Splunk SPL, Microsoft Sentinel (KQL), and SentinelOne EDR syntax
- Mapped the resulting rules against SWIFT CSCF v2024, Morocco's DNSSI, Bank Al-Maghrib Directive 3/W/16, and ISO/IEC 27002

## Using the rules

Each file in [`/rules`](./rules) is a standard SIGMA rule. Convert to your SIEM's native query language with [pySigma](https://github.com/SigmaHQ/pySigma) or the free web interface at [sigconverter.io](https://sigconverter.io):

```bash
pip install pysigma pysigma-backend-splunk
sigma convert -t splunk rules/SENTRY_Rule1_liboradb_access.yml
```

## Reproducing the validation environment

See [`/docs/environment.md`](./docs/environment.md) for the full build walkthrough, or jump straight to [`/sql`](./sql) and [`/sysmon`](./sysmon) for the raw configuration files.

## Status

🔒 This repository was private during development. Now public and open for review, corrections, and reuse.

⚠️ **No real malware sample was ever sourced, downloaded, or executed at any point in this project.** All emulator scripts in `/scripts` were authored from scratch based on documented behavior from public forensic sources (BAE Systems, U.S. DOJ, Oosthoek & Doerr 2021).

## Corrections welcome

If you spot an error  especially in the reverse-engineering sections of [`SENTRY01.md`](./SENTRY01.md)  please open an issue. This project corrected two claims in prior peer-reviewed literature during its own development; get in touch if you find something here that needs the same treatment.

## Author

**Hazem Akkouh**  ENSA Kénitra, Morocco
