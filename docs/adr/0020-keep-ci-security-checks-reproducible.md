# Keep CI security checks reproducible

The HarvestView browser job pins Ubuntu 24.04 because the pinned Playwright release supports that runner image. Update the image and browser tooling together when their support overlaps.

Use local `./` paths for reusable workflows. Scorecard can mistake the alternative self-repository notation for an unpinned dependency, so the zizmor configuration disables that specific rule.

Scorecard runs on changes to default-branch protection and refreshes its results on a schedule. The job needs access to commit and review history and check runs to compute its scores. Its scoped write permissions publish the public score and upload the SARIF results. CodeQL covers the same branches on push and pull requests and reads Actions metadata during analysis.
