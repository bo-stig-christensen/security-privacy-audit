# Contributing

Contributions that make audits more evidence-based, portable, privacy-preserving and useful are welcome.

- Open an issue to discuss substantial changes before implementation.
- Keep the `SKILL.md` portable and dependency-light; avoid product-specific or proprietary assumptions.
- Do not add examples containing real tokens, confidential repositories, customer identifiers or sensitive logs.
- Do not add actions that install or execute untrusted audit subjects as part of the default workflow.
- Add tests for Python helper changes; run `python -m unittest discover -s tests -v`.
- Avoid network access and additional dependencies in the offline helpers.
- Do not weaken risk disclaimers or represent static checks as guarantees.
- Prefer small PRs with a clear threat model and the specific finding or false positive addressed.

The repository is MIT licensed; by contributing, you agree that your contributions will be distributed under that license.
