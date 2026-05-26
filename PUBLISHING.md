# Publishing Checklist

Use this directory as the root content for a dedicated public GitHub repository,
for example `deploywhisper/analyze-action`.

## Repository requirements

1. Create a new public repository for the action.
2. Copy the contents of this directory into the root of that repository.
3. Do not add `.github/workflows/` to the action repository. GitHub Marketplace
   rejects action repositories that contain workflow files.

## Pre-publish verification

1. Push the repository content to a branch.
2. From a separate test repository, create a workflow that uses the action via:

   ```yaml
   - uses: <owner>/<repo>@<branch-or-tag>
     with:
       api-url: ${{ secrets.DEPLOYWHISPER_API_URL }}
       project-key: ${{ secrets.DEPLOYWHISPER_PROJECT_KEY }}
       workspace-key: ${{ secrets.DEPLOYWHISPER_WORKSPACE_KEY }}
   ```

3. Confirm the job:
   - checks out the PR branch
   - detects supported changed artifacts
   - POSTs to the DeployWhisper API
   - writes outputs and step summary
   - exits successfully on advisory results

## Marketplace release

1. Merge the tested branch in the dedicated public action repository.
2. Create and push an immutable semantic version tag, for example:

   ```bash
   git tag -a v1.0.1 -m "DeployWhisper Analyze Action v1.0.1"
   git push origin v1.0.1
   ```

3. Smoke the immutable tag from the separate consumer repository:

   ```yaml
   - uses: deploywhisper/analyze-action@v1.0.1
   ```

4. Move the major compatibility tag to the same reviewed commit:

   ```bash
   git tag -f v1 v1.0.1
   git push origin v1 --force
   ```

5. In GitHub UI for the action repository:
   - open the Releases page
   - draft a new release from the immutable semantic version tag
   - choose the option to publish the action to GitHub Marketplace
   - complete Marketplace metadata and publish

6. Smoke the moving major tag used by consumers:

   ```yaml
   - uses: deploywhisper/analyze-action@v1
   ```

## Post-publish follow-up

1. Update consumer docs to reference the dedicated public action repository.
2. Keep this extracted directory in sync with the published action repo, or
   stop mirroring and treat the action repo as the sole source of truth.
