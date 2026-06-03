# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [2.0.0] - 2026-06-03

- security: bound URL-extraction regexes to stop polynomial ReDoS on the body
- security: parse From/Reply-To/Message-ID per RFC 5322 to stop domain spoofing
- fix: escape the dot in inAddrArpaToIP (correctness + ReDoS)
- fix: validate TLDs against haraka-tld Sets; rebuild extractors for modern gTLDs
- fix: don't record a pass after a reject
- fix: treat timeout="0" as the default instead of firing immediately
- chore: replace deprecated url.parse with WHATWG URL
- refactor: convert hook internals to async/await (dns.promises)
- dep: add @haraka/email-address
- fix: off-by-one in max_uris_per_list
- fix: typoed phase label in lookup_header_zones
- fix: hot-reload uribl.excludes
- doc: README documents not_ipv6_compatible zone option
- refactor: split do_lookups into 5 helpers
- chore: drop unused node:https import
- test: refactored against test-fixtures 1.7.0
- test: cover do_lookups and hooks via fixtures.dns
- test: raise coverage from 51 to 98%

### [1.0.10] - 2025-01-26

- prettier: move config into package.json

### [1.0.9] - 2025-01-08

- doc: mv Changes -> CHANGELOG.md, add CONTRIBUTORS
- ci: update to point to shared configs
- style: automated code formatting with prettier
- lint: remove duplicate / stale rules from .eslintrc
- dep: eslint-plugin-haraka -> @haraka/eslint-config
- populate [files] in package.json. Delete .npmignore.

### [1.0.8] - 2023-05-25

- doc(README) Update config file name #9

### 1.0.7 - 2023-01-05

- handle Spamhaus DQS (#5): add a dqs_key config option and a [dbl.dq.spamhaus.net] zone, disabled by default

### 1.0.6 - 2022-11-28

- test: increase timeout for DNSBL test

### 1.0.5 - 2022-08-29

- fix #2 change Spamhaus defaults to not assume errors as positives
- warn instead of debug when result do not validate

### [1.0.4] - 2022-07-23

- updated package.json

### 1.0.3 - 2022-07-23

- Import from Haraka

[1.0.3]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.3
[1.0.4]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.4
[1.0.6]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.6
[1.0.7]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.7
[1.0.8]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.8
[1.0.9]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.9
[1.0.10]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v1.0.10
[2.0.0]: https://github.com/haraka/haraka-plugin-uribl/releases/tag/v2.0.0
