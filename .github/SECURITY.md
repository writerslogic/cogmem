# Security Policy

## Reporting a Vulnerability

We take the security of cogmem seriously — it stores rules that directly change agent
behavior and compile into guards that block tool calls, so a memory-integrity flaw is
a real exploit path. If you believe you have found a security vulnerability, please do
not open a public issue.

Please report vulnerabilities by:
- Opening a [draft security advisory](https://github.com/writerslogic/cogmem/security/advisories/new) on GitHub
- Contacting the WritersLogic security team at security@writerslogic.com

We will acknowledge your report within 48 hours and provide a timeline for a fix if
applicable.

## Scope of particular interest

- **Memory poisoning / provenance bypass.** Any way to get a tampered, forged, or
  unsigned memory accepted by the recall index when `provenance_enforce` is on, or to
  forge a transparency-log entry or inclusion receipt that verifies.
- **Identity key exposure.** The agent's Ed25519 key lives only at
  `vault/identity/agent.key`. Report any path that would log, transmit, or commit it.
- **Data exfiltration.** cogmem is local-first; report any code path in recall,
  capture, or provenance that sends memory contents off the machine.

## Security Practices

- The transparency log is hash-chained and signed; tamper-detection is covered by
  tests in `engine/test_provenance.py`.
- Apache-2.0 licensed with full provenance tracking.
