# Prepare
- add new O/S versions in pkg/rules/packages-to-build.yml if needed
- update Changelog.md with the release date, version X.Y.Z[-NNN] and release summary

# Make a release branch and test packaging
- git checkout -b release-vX.Y.Z[-xxx]
- cargo update
- bump application version in Cargo.toml to X.Y.Z[-xxx]
- cargo check (to bump the application version in Cargo.lock)
- pushd doc/manual
- make man
- popd
- git add Cargo.toml Cargo.lock Changelog.md pkg/rules/packages-to-build.yml doc/manual/build/man/*.*
- git commit
- git push
- in GH UI invoke the packaging workflow on the release branch
- make a PR for the branch and mention the workflow run URL in the descrption
- review the PR and ensure the workflow succeeds
- dog food: upgrade cascade.nlnetlabs.nl using a package attached as an output artifact to
  the workflow run

# Merge and release
- merge the release branch to main
- git checkout main
- cargo package (to test that it works)
- git push
- in GH UI invoke the packaging workklow on the release branch
- git tag -a -m "Release vX.Y.Z[-xxx]`)
- Verify that the release tag version is the same as the Cargo.toml version but with a `v` prefix
- cargo publish
- publish binary (DEB, RPM) packages via packaging VM

# Prepare for development
- git checkout -b prep-for-dev
- bump application version in Cargo.toml to next minor version with suffix `-dev`
- cargo check (to also bump the application version in Cargo.lock)
- git add Cargo.toml Cargo.lock
- git commit
- git push
