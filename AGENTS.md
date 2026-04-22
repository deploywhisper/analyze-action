# AGENTS.md

## Scope

This file governs the standalone action repository rooted here:

- `deploywhisper/analyze-action`

Treat this repository as the canonical source for the published GitHub
Marketplace action `deploywhisper/analyze-action@v1`.

## Purpose

This repository is intentionally separate from the main application repository
`deploywhisper/deploywhisper`.

Keep the boundary strict:

- This repo owns Marketplace action packaging and runtime only.
- The app repo owns the DeployWhisper server, UI, API, CLI, and application
  documentation.
- Do not reintroduce Marketplace action source files into the app repo.

## Repository Rules

- Keep the repository minimal and source-only.
- Preserve the root `action.yml` contract.
- Keep the runtime self-contained and Python-stdlib-only unless an explicit
  dependency change is approved.
- Do not add `.github/workflows/` here. Marketplace action repositories should
  remain workflow-free.
- Do not commit generated files such as `__pycache__/` or `*.pyc`.
- Keep public usage examples pointing to `deploywhisper/analyze-action@v1`.
- Treat `DEPLOYWHISPER_API_URL` as required for the current server-backed
  action design. `DEPLOYWHISPER_API_TOKEN` is optional unless the target API
  requires auth.

## Validation

When changing this repo:

- verify the action entrypoint can run from a non-repo working directory with
  `PYTHONPATH` pointed at the action root
- keep consumer-facing docs aligned with the published action behavior
- prefer testing from a separate consumer repository when validating release
  behavior

## Canonical Related Repositories

- App repo: `deploywhisper/deploywhisper`
- Action repo: `deploywhisper/analyze-action`
- Consumer smoke repo: `deploywhisper/action-smoke-consumer`
