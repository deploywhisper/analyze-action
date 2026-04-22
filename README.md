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
```

Optional inputs:

- `api-token`
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
- `skipped-files`

## Behavior

- detects changed files from the pull-request diff
- filters to supported DeployWhisper artifacts locally before upload
- submits those artifacts to `POST /api/v1/analyses`
- exits `0` when analysis succeeds, regardless of risk verdict
- uses only Python standard library modules inside the action runtime

## Publish

See [PUBLISHING.md](./PUBLISHING.md) for the exact GitHub-side steps to turn
this directory into a public Marketplace action repository.
