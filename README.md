# DeployWhisper Analyze Action

Submit changed infrastructure artifacts from GitHub pull requests to a
DeployWhisper API endpoint, publish advisory outputs, and maintain one stable
pull request comment across reruns.

## Highlights

- Sends supported changed artifacts to `POST /api/v1/analyses`.
- Supports explicit project and workspace scope inputs.
- Keeps risk verdicts advisory: successful analysis exits `0` even when
  DeployWhisper recommends additional human review.
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

## Marketplace Release

Publish immutable releases from semantic tags such as `v1.0.1`, then move the
major `v1` tag to the same reviewed commit for consumers:

```yaml
uses: deploywhisper/analyze-action@v1
```

See [PUBLISHING.md](./PUBLISHING.md) for the release checklist.
