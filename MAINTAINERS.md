# Maintainers

`autogov` is maintained by Liatrio's autogov team. Review and merge authority
for the repository is held by `@liatrio/tag-autogov` (see
[`CODEOWNERS`](CODEOWNERS)).

| Maintainer  | GitHub                                        | Role            |
| ----------- | --------------------------------------------- | --------------- |
| Ian Hundere | [@ianhundere](https://github.com/ianhundere)  | Lead maintainer |

Maintainers triage issues, review and merge pull requests, cut releases, and
respond to security reports.

## Review model & SLSA source posture

This project currently has one maintainer, so `@liatrio/tag-autogov`
effectively resolves to one person. Genuine two-party review (SLSA Source L4)
is not met today. The enforced and recorded controls on the protected branch
still support an honest **SLSA Source L3** claim.

AI-assisted review is tooling, not a second reviewing party. The repo's own
release flow self-verifies `source_review` at `min_approvals: 0` by disclosed
design, while the published policy bundle keeps the strict default for adopters
with real review teams.

## Contributing

Contributions are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Contributors with sustained, high-quality involvement may be invited to join as
maintainers.
