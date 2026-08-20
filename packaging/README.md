# Release artifacts

Stable releases are created only from exact `vX.Y.Z` tags whose version matches
the workspace package version. The release workflow builds these archives:

| Component | Target | Archive |
| --- | --- | --- |
| CLI | Windows amd64 | `.zip` |
| CLI | Linux amd64 | `.tar.gz` |
| CLI | macOS amd64 | `.tar.gz` |
| CLI | macOS arm64 | `.tar.gz` |
| Host installer | Ubuntu 24.04 / Linux amd64 | `.tar.gz` |

The workflow refuses an incomplete or additional archive set. It then writes
`SHA256SUMS` and `release-manifest.json`. The manifest binds every archive hash
to its component, target, release tag, repository, and full source revision;
its format is defined by `release-manifest.schema.json`.

Publishing fails if the GitHub release already exists. This prevents a rerun
from replacing assets or the manifest under an existing stable version.
