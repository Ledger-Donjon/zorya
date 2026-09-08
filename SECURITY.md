<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

## Scope

Zorya is a concolic execution framework for binary-level vulnerability analysis.It is a **research and analysis tool**, typically run by an analyst on binaries they have chosen to inspect. This policy covers vulnerabilities in Zorya itself, the concolic engine, the fuzzer, the MCP server, and the helper scripts, not vulnerabilities that Zorya *discovers* in third-party targets.

Because Zorya loads and executes untrusted binaries and their runtime state, we are especially interested in reports where analyzing a crafted target lets it escape the intended analysis boundary, for example arbitrary code execution in the host running Zorya, escape from the intended sandbox, or corruption of results outside the workspace.

## Supported Versions

Zorya is under active development (pre-1.0) and breaking changes may happen between releases. Security fixes are applied to the latest released version on the `main` branch only. There are no maintained long-term support branches.

## Reporting a Vulnerability

Report privately through GitHub private vulnerability reporting: open a report via the [Security advisories page](https://github.com/Ledger-Donjon/zorya/security/advisories/new) of the repository.

To help us triage quickly, please include:

- The affected component and version or commit hash (`git rev-parse HEAD`).
- A description of the issue and the security impact you observed.
- Reproduction steps, and where possible a minimal target binary or input that
  triggers the behavior.
- Any relevant logs, stack traces, or `results/` artifacts.

## What to Expect

Zorya is a research tool, so we do not commit to formal response deadlines. That said, we will do our best to acknowledge your report, let you know whether we
consider it in scope, and coordinate on a fix and disclosure timeline if it is. With your permission, we are happy to credit you once the issue is resolved.

Thank you for helping keep Zorya and its users safe.
