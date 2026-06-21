# Contributing to cogmem

Thank you for considering contributing to cogmem! A verifiable, self-improving memory
layer is only as good as the community that scrutinizes it, so contributions —
especially to the learning loop and the provenance layer — are very welcome.

## How Can I Contribute?

### Reporting Bugs
- Use the GitHub Issue Tracker.
- Describe the bug and provide steps to reproduce.
- Include environment details (OS, Python version).

### Suggesting Enhancements
- Open an issue to discuss your idea before implementing it.

### Pull Requests
1. Fork the repo.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes.
4. Push to the branch.
5. Open a Pull Request.

## Development Setup

cogmem's engine is pure Python (3.12+); recall uses local models, the provenance
layer uses `cryptography`.

```bash
python3 -m venv engine/.venv
engine/.venv/bin/pip install cryptography fastembed
engine/.venv/bin/python engine/test_provenance.py   # crypto/provenance tests
engine/.venv/bin/python engine/test_cogmem.py        # recall/index tests
```

## Style Guidelines
- **Python**: 4-space indentation, standard library first. Keep functions small and
  the data model (open markdown files) the source of truth.
- **Privacy first**: nothing a memory contains should leave the machine. Do not add
  network calls in the recall, capture, or provenance paths.
- **Provenance**: changes under `engine/provenance.py` must keep all tests in
  `engine/test_provenance.py` green; tamper-detection is a security property, not a
  nice-to-have.
- Commit messages: `<type>: <description>` (imperative, single line). Types: fix,
  feat, refactor, test, docs, perf, security, chore.

## Code of Conduct
This project adheres to a [Code of Conduct](./CODE_OF_CONDUCT.md). By participating,
you are expected to uphold it.
