# DeployWhisper Analyze Action

Official GitHub Action for sending pull-request infrastructure changes to a
DeployWhisper API endpoint.

This directory is intentionally shaped like the future root of a dedicated
public Marketplace repository:

- root `action.yml`
- self-contained Python stdlib runtime
- no `.github/workflows/` directory

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
          project-key: payments
          workspace-key: prod
```

Required and optional inputs:

- `api-token`
- `project-key` or `project-id`: required for normal project-scoped analysis unless your DeployWhisper endpoint derives project scope from repository context
- `workspace-key` or `workspace-id`: optional project-local environment or deployment lane
- `allow-derived-project-scope`: defaults to `true` for v1 compatibility with endpoints that derive project scope; set to `false` to fail fast when `project-key` or `project-id` is missing
- `changed-files`
- `working-directory`

Outputs:

- `created`
- `changed-file-count`
- `submitted-artifact-count`
- `accepted-artifact-count`
- `report-id`
- `report-link`
- `severity`
- `recommendation`
- `share-summary-json`
- `share-summary-markdown`
- `comment-id`
- `comment-url`
- `comment-updated`
- `skipped-files`

## Behavior

- detects changed files from the pull-request diff
- filters to supported DeployWhisper artifacts locally before upload
- submits those artifacts to `POST /api/v1/analyses` with explicit project and optional workspace scope when configured
- posts a single markdown PR comment and updates that same comment on re-runs
- compares the latest report with the previous PR scan so the updated comment shows score and severity changes
- exits `0` when analysis succeeds, regardless of risk verdict
- uses only Python standard library modules inside the action runtime

## Publish

See [PUBLISHING.md](./PUBLISHING.md) for the exact GitHub-side steps to turn
this directory into a public Marketplace action repository.
