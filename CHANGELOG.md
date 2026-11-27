# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The Scope page now shows a new domain's DNS proof record without a reload: the domains list updates itself every few seconds while it waits for the scanner, and shows the record as the separate Type, Name, and Value fields a DNS panel asks for.

## [0.1.0] - 2026-11-25

Initial public release.

### Added

- The scanner: a Kali Linux container that runs open-source scan tools against domains you own, behind an ownership statement, a DNS proof, an approval of each inventory, scope gates, and an egress firewall. It stores minimized, redacted evidence and publishes snapshots and reports.
- The brain: the web application (pages and JSON API) with accounts, sessions, sign-in limits, scope, schedules, findings, marks, version watch, and an audit log. It shares no network with the scanner.
- The analyst (optional, off until configured and confirmed): an AI assistant in the brain that writes run briefs, answers questions, and proposes marks that a person must accept. It supports Anthropic, OpenAI, Google Gemini, and Amazon Bedrock.
- The seeder (optional): lists host names from DNS services you control (Route 53, zone transfer, PowerDNS, zone files) for DNS-verified domains.
- The lab demo: a deliberately weak target on internal Docker networks, and end-to-end tests for the scanner and the web pages.
- Cloud examples: an AWS CloudFormation template and a Google Cloud script for one scanner host.

[Unreleased]: https://github.com/mgrofsky/momus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mgrofsky/momus/releases/tag/v0.1.0
