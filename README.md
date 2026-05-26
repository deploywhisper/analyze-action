# DeployWhisper Analyze Action v1.0.0

  DeployWhisper Analyze Action submits changed infrastructure artifacts from GitHub pull requests to a DeployWhisper API endpoint, publishes advisory outputs, and
  maintains a single pull request comment across reruns.

  ## Highlights

  - Adds explicit project and workspace scope inputs:
    - `project-key`
    - `project-id`
    - `workspace-key`
    - `workspace-id`
  - Preserves v1 compatibility with `allow-derived-project-scope`, defaulting to `true`.
  - Validates malformed scope inputs before upload:
    - rejects conflicting `project-key` + `project-id`
    - rejects conflicting `workspace-key` + `workspace-id`
    - rejects non-numeric IDs
    - rejects newline characters in scope inputs
  - Maps GitHub Action outputs to the canonical DeployWhisper report contract.
  - Distinguishes workflow trigger types, including `workflow_dispatch`, `pull_request`, and `pull_request_target`.
  - Posts or updates one stable DeployWhisper PR comment.
  - Keeps risk verdicts advisory: successful analysis exits `0` even when DeployWhisper returns a high-risk recommendation.

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

  ## Inputs

  ┌─────────────────────────────┬─────────────┬─────────────────────────────────────────────────────────────────────────────────────┐
  │ Input                       │ Required    │ Description                                                                         │
  ├─────────────────────────────┼─────────────┼─────────────────────────────────────────────────────────────────────────────────────┤
  │ api-url                     │ Yes         │ DeployWhisper base URL or /api/v1/analyses endpoint.                                │
  │ api-token                   │ No          │ Optional bearer token for the DeployWhisper API.                                    │
  │ project-key                 │ Recommended │ Project key for project-scoped analysis.                                            │
  │ project-id                  │ Alternative │ Numeric project id. Do not combine with project-key.                                │
  │ workspace-key               │ No          │ Optional project-local workspace or environment key.                                │
  │ workspace-id                │ Alternative │ Optional numeric workspace id. Do not combine with workspace-key.                   │
  │ allow-derived-project-scope │ No          │ Defaults to true for v1 compatibility. Set false to require explicit project scope. │
  │ changed-files               │ No          │ Optional comma/newline-separated file list. Defaults to PR diff discovery.          │
  │ working-directory           │ No          │ Repository path containing checked-out pull request. Defaults to ..                 │
  └─────────────────────────────┴─────────────┴─────────────────────────────────────────────────────────────────────────────────────┘

  ## Outputs

  ┌──────────────────────────┬────────────────────────────────────────────────────┐
  │ Output                   │ Description                                        │
  ├──────────────────────────┼────────────────────────────────────────────────────┤
  │ created                  │ Whether a DeployWhisper report was created.        │
  │ changed-file-count       │ Number of changed files detected.                  │
  │ submitted-artifact-count │ Number of supported artifacts uploaded.            │
  │ accepted-artifact-count  │ Number of artifacts accepted by the API.           │
  │ report-id                │ Persisted DeployWhisper report id.                 │
  │ report-link              │ Shareable report link when configured server-side. │
  │ severity                 │ Canonical advisory severity.                       │
  │ recommendation           │ Canonical advisory recommendation.                 │
  │ share-summary-json       │ JSON-encoded share summary payload.                │
  │ share-summary-markdown   │ Markdown advisory summary.                         │
  │ comment-id               │ PR comment id when created or updated.             │
  │ comment-url              │ PR comment URL.                                    │
  │ comment-updated          │ Whether an existing comment was updated.           │
  │ skipped-files            │ JSON array of skipped changed files.               │
  └──────────────────────────┴────────────────────────────────────────────────────┘

  ## Notes

  - Requires actions/checkout@v4 with fetch-depth: 0 for PR diff discovery.
  - Requires pull-requests: write permission to publish PR comments.
  - The action filters unsupported or sensitive files locally before upload.
  - The action uses Python standard library only.


  **Marketplace Short Description**
  
  Submit pull request infrastructure changes to DeployWhisper for advisory risk analysis and PR review comments.

 

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
