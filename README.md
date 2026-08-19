# DeployWhisper Analyze Action

Submit changed infrastructure artifacts from GitHub pull requests to a
DeployWhisper API endpoint, consume the server's GitHub Action enforcement
decision, and maintain one stable pull request comment across reruns.

## Highlights

- Sends supported changed artifacts to `POST /api/v1/analyses`.
- Follows each successful analysis with `GET /api/v1/analyses/{report_id}/enforcement-decision?integration=github-action`.
- Supports explicit project and workspace scope inputs.
- Preserves advisory and warn modes as exit `0`, and returns non-zero only when
  the server's configured decision sets `should_block=true`.
- Posts or updates one DeployWhisper pull request comment.
- Uses only Python standard library modules inside the action runtime.

## Usage

```yaml
name: DeployWhisper

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  deploywhisper:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: deploywhisper/analyze-action@v1
        with:
          api-url: ${{ secrets.DEPLOYWHISPER_API_URL }}
          api-token: ${{ secrets.DEPLOYWHISPER_API_TOKEN }}
          project-key: payments
          workspace-key: prod
```

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `api-url` | Yes | DeployWhisper base URL or `/api/v1/analyses` endpoint. |
| `api-token` | No | Optional bearer token for the DeployWhisper API. |
| `project-key` | Recommended | Project key for project-scoped analysis. |
| `project-id` | Alternative | Numeric project id. Do not combine with `project-key`. |
| `workspace-key` | No | Optional project-local workspace or environment key. |
| `workspace-id` | Alternative | Optional numeric workspace id. Do not combine with `workspace-key`. |
| `allow-derived-project-scope` | No | Defaults to `true` for v1 compatibility. Set `false` to require explicit project scope. |
| `changed-files` | No | Optional comma/newline-separated file list. Defaults to PR diff discovery. |
| `working-directory` | No | Repository path containing the checked-out pull request. Defaults to `.`. |

## Outputs

| Output | Description |
| --- | --- |
| `created` | Whether a DeployWhisper report was created. |
| `changed-file-count` | Number of changed files detected. |
| `submitted-artifact-count` | Number of supported artifacts uploaded. |
| `accepted-artifact-count` | Number of artifacts accepted by the API. |
| `report-id` | Persisted DeployWhisper report id. |
| `report-link` | Report link. Publicly shareable only when `APP_BASE_URL` or `PUBLIC_APP_URL` is configured server-side; otherwise it may be local/private and consumers should treat it as optional. |
| `policy-status` | Raw `data.policy_output.status` returned by the enforcement-decision endpoint. |
| `configured-mode` | `data.configured_mode` for the `github-action` integration. |
| `effective-status` | `data.effective_status` after the configured mode ceiling is applied. |
| `should-block` | `data.should_block`. `true` causes the action to exit non-zero after outputs and summaries are written. |
| `severity` | Advisory severity. Uses `data.advisory.severity`, falling back to `data.share_summary.severity` when advisory is blank. |
| `recommendation` | Advisory recommendation. Uses `data.advisory.recommendation`, falling back to `data.share_summary.recommendation` when advisory is blank. |
| `share-summary-json` | JSON-encoded `data.share_summary.json_payload`. |
| `share-summary-markdown` | Markdown advisory summary. |
| `comment-id` | Pull request comment id when created or updated. |
| `comment-url` | Pull request comment URL when created or updated. |
| `comment-updated` | Whether an existing comment was updated. |
| `skipped-files` | JSON array of changed files skipped before upload. |

## Behavior

- Detects changed files from the pull request diff.
- Filters unsupported and sensitive files locally before upload.
- Submits explicit project and optional workspace scope when configured.
- Requires a valid persisted report id from `POST /api/v1/analyses`, then
  validates the `v1` enforcement-decision contract instead of re-deriving
  policy locally from advisory severity or recommendation.
- Fails closed when the enforcement-decision request is missing, malformed,
  operationally broken, or internally inconsistent with its own
  `effective_status`.
- Posts a concise advisory PR comment with verdict, Evidence Law status,
  top risks with evidence counts, blast radius, rollback, incident/public
  pattern matches, scanner context, uncertainty, and report links.
- Compares the latest report with the previous PR scan when the scan marker is
  valid, including same-commit reruns where rules, parsers, incidents, or inputs
  may have changed.
- Highlights finding-level deltas across reruns: new, resolved, and persistent
  findings are summarized in the PR comment when prior scan metadata is
  available.
- Treats malformed previous scan markers as absent so comment updates can still
  proceed.

## Exit Behavior

- `configured-mode=advisory` and `configured-mode=warn` always keep the action
  exit code at `0`.
- `configured-mode=soft-block` or `configured-mode=hard-block` return a non-zero
  exit only when the server's `should-block` output is `true`.
- Advisory outputs remain available even when the action exits non-zero for CI
  enforcement, so downstream steps can still inspect the report id, report
  link, and policy metadata.

## Marketplace Release

Publish immutable releases from semantic tags such as `v1.0.1`, then move the
major `v1` tag to the same reviewed commit for consumers:

```yaml
uses: deploywhisper/analyze-action@v1
```

See [PUBLISHING.md](./PUBLISHING.md) for the release checklist.
