# Releasing

This package follows semantic versioning. Releases are Go module tags such as
`v1.0.0`; there are no binary artifacts.

1. Confirm the intended commit is on the default branch and CI is green.
2. Review dependency, vulnerability, documentation, and live-test results.
3. Confirm installation examples and Siteverify documentation match the
   release.
4. Create a signed annotated semantic-version tag from the reviewed default
   branch commit and push that tag. The release-verification workflow rejects
   unsigned, lightweight, invalid semantic-version, or non-default-branch tags
   and reruns live and dependency checks.
5. Confirm release verification succeeds, then verify the version through the
   Go module proxy and pkg.go.dev.
6. Create the corresponding GitHub release notes.
7. Submit the released package to the public hCaptcha integrations list.

Do not tag from a dirty worktree or move an existing release tag. If a release
is incorrect, publish a new patch version instead. Keep the default branch
protected, require CI and an approving maintainer review, and retain release
provenance with the GitHub release.
