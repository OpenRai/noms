# Package names and publishing

## Registry names

| Registry | Name | Purpose |
| --- | --- | --- |
| npm | `@openrai/noms` | TypeScript library and `noms` executable |
| crates.io | `noms` | Rust library |
| crates.io | `noms-cli` | Rust `noms` executable |

The browser playground is private workspace package `@openrai/noms-site`; it is not published to npm.

Use pnpm for workspace installs, builds, and tests. The GitHub release workflow
uses npm only for the final registry publish: it creates a tarball in the
verified job, then the OIDC-enabled job publishes that exact artifact with the
npm CLI. Keep that step on npm 11.5.1 or newer and Node 22.14 or newer; the
workflow uses Node 24 and checks the npm CLI version. This keeps package-manager
operations reproducible through `pnpm-lock.yaml` while using npm's documented
trusted-publishing client.

After publication, install the native CLI with `cargo install noms-cli`; Cargo installs its `noms` binary. The Rust library is added to an application with `noms = "0.1"` in `Cargo.toml`.

The npm package `@openrai/noms` now exists. Before bootstrapping either crates.io crate, confirm its name is still available; registry names cannot be changed after publication.

## GitHub Actions identity

The publishing workflow is `.github/workflows/publish.yml`. Configure each registry publisher with:

| Field | Value |
| --- | --- |
| Provider | GitHub Actions |
| Organization or owner | `OpenRai` |
| Repository | `noms` |
| Workflow filename | `publish.yml` |
| GitHub environment | `release` |

The publishing jobs reference a GitHub Actions environment named `release`, and the registry trusted publishers are configured to require that environment. Keep the name matched, but do not add required reviewers: this project uses automated publishing for its solo maintainer. GitHub creates the environment automatically on first use; no secrets are needed. Optionally restrict deployments to the release tags `npm-v*`, `noms-v*`, and `noms-cli-v*`. Protect those tag patterns with a repository ruleset to prevent accidental updates or deletion. The workflow requests `contents: read` and `id-token: write` only in publishing jobs; it stores no registry token.

## npm trusted publisher

Release tags first run the shared conformance workflow on all three operating
systems, including the extended Linux campaign. Publishing also requires a
committed Standards revision whose specification, generator, and fixture hashes
match the vendored manifest. See the root README for the canonical development
and fixture-update commands. Configure `Required conformance` as a required
branch-protection check; workflow dependencies already gate publishing and Pages.

1. Ensure `@openrai/noms` exists on npm. npm’s trusted-publisher settings belong to an existing package.
2. Open the package’s **Settings → Trusted Publisher** section on npmjs.com.
3. Add a **GitHub Actions** publisher using the identity fields above.
4. Allow direct `npm publish`. This repository publishes the verified tarball automatically after conformance succeeds, using npm OIDC and provenance. Do not enable npm dist-tag management; the workflow does not run `npm dist-tag`.
5. Use Node.js 24 and npm 11.5.1 or newer in the workflow. The publish job checks the npm CLI version before requesting publication.
6. Confirm that the GitHub `release` environment name matches the OIDC configuration and that the release tag ruleset is active before creating a release tag.

npm requires the trusted publisher's first successful OIDC publish within two
days of configuration; otherwise the configuration expires. The package is
already bootstrapped, so the first OIDC publish can be the next tagged release.

The npm package now exists, so do not repeat the initial manual bootstrap. For a future package that has not yet been created, bootstrap its first version manually before adding the trusted publisher. Build and publish from the package directory:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm test
cd packages/typescript
npm publish
```

The registry currently shows a `0.0.0-stage` placeholder with the description
“Temporary package placeholder for staged publishing.” This is npm's
registry-managed bootstrap placeholder, not a NOMS release. The release
workflow does not edit it. A successful `npm-v<package-version>` release
publishes the version and description from `packages/typescript/package.json`
as a normal version; the placeholder can remain in the package's version
history.

Before publishing, confirm that `packages/typescript/package.json` has the CLI
entry as `"bin": { "noms": "dist/cli.js" }` (without a leading `./`). npm
11.17 reported that the entry was invalid and removed it when given
`"./dist/cli.js"`; inspect the packed `package.json` and confirm it retains the
`noms` entry:

```sh
npm pack
tar -xOf openrai-noms-*.tgz package/package.json
```

The executable already includes a Node shebang.

If npm returns 404 for the scoped publish, run `npm whoami` to check the active
account, then confirm that the `openrai` npm organization exists and that the
account has permission to publish `@openrai/noms`. The package's
`publishConfig.access` already sets public visibility; package configuration
does not create the organization or grant publishing rights. Do not share
`.npmrc` contents or registry tokens when troubleshooting.

After the package exists, the trusted publisher's workflow filename and environment must match the workflow exactly. npm checks that `packages/typescript/package.json` names this repository in its `repository.url`.

### Release an npm version

Use the root release command for the version change. Each command runs pnpm's
version tool for `@openrai/noms`, creates a commit, and creates the matching
`npm-v` tag. The working tree must be clean first; commit and push the
implementation and conformance changes before bumping the version.

Choose the bump from the change:

| Command | Version change | Use |
| --- | --- | --- |
| `pnpm release:npm:patch` | `0.1.0` → `0.1.1` | Backward-compatible fixes; use this for the first OIDC release. |
| `pnpm release:npm:minor` | `0.1.0` → `0.2.0` | Backward-compatible features. |
| `pnpm release:npm:major` | `0.1.0` → `1.0.0` | Breaking API changes. |

The current npm version is `0.1.0`, so the first OIDC validation release uses
`patch`. From the repository root, first run the full checks and push the
reviewed implementation changes:

```sh
pnpm install --frozen-lockfile
pnpm conformance
node scripts/check-fixtures.mjs --release
git status --short
```

Review and commit the release implementation files, then push `main`. After
that push succeeds, run the selected release command from the repository root.
For the first OIDC publish:

```sh
pnpm release:npm:patch
```

For the current version, pnpm creates commit `release: @openrai/noms 0.1.1`
and annotated tag `npm-v0.1.1`. Review the result before pushing:

```sh
git show --stat --oneline HEAD
git tag --list --points-at HEAD
git push origin main
git push origin npm-v0.1.1
```

Pushing the tag starts `.github/workflows/publish.yml`; creating a GitHub
Release page is not required. The workflow checks that the tag matches the
package version, reruns extended conformance, and publishes the verified npm
tarball through OIDC. Replace `patch` with `minor` or `major` when appropriate,
and push the exact tag pnpm reports. Never reuse or move a version or tag that
npm has already published.

## crates.io trusted publishers

crates.io requires each crate’s first version to be published manually. Log in locally with a crates.io token, then bootstrap `noms` first and `noms-cli` second so the CLI’s `noms` dependency can resolve:

```sh
cargo login
cargo publish --locked -p noms
cargo publish --locked -p noms-cli
```

After both crates exist:

1. Open each crate’s settings page on crates.io.
2. Add a GitHub Actions trusted publisher to `noms` and `noms-cli`, using the identity fields above.
3. Configure each crate separately, even though both use the same repository and workflow.
4. Push `noms-v<crate-version>` to publish `noms` or `noms-cli-v<crate-version>` to publish `noms-cli`.

The workflow obtains a short-lived token through `rust-lang/crates-io-auth-action`; no crates.io API token is stored in GitHub. Configure the publisher’s environment as `release` to match the GitHub Actions job.

### Release Rust crate versions

Use the root pnpm command to bump both Rust packages together. The command
updates the two manifests, the CLI's NOMS dependency, and `Cargo.lock`, then
creates one release commit and both matching tags. Start with a clean working
tree:

```sh
pnpm release:cargo:patch
```

Use `pnpm release:cargo:minor` or `pnpm release:cargo:major` when appropriate.
Review and push `main` and `noms-v<version>` first. Wait for the `noms` crate
publish to succeed before pushing `noms-cli-v<version>`; the CLI release
depends on that version being available from crates.io. Never reuse a version
or tag that has already been published.

The crates.io registry query found no existing `noms` or `noms-cli` crates at the time of implementation. Recheck immediately before publishing because names can be claimed by another publisher.

On Windows, set key-file ACLs so only the current user can read them; the CLIs can check POSIX mode bits but do not inspect Windows ACLs.

## GitHub Pages

Set the repository’s **Settings → Pages → Build and deployment → Source** to **GitHub Actions**. The `pages.yml` workflow builds `site/` and deploys it to `https://openrai.github.io/noms/` after changes land on `main`.

## Cross-language pipeline

After the initial releases, install the Rust executable and pipe a TypeScript signature directly into its verifier:

```sh
cargo install noms-cli
npx --yes --package @openrai/noms noms sign --key-file ./account-key.hex --message 'Hello Nano' |
  noms verify --account nano_... --message 'Hello Nano' --signature-stdin
```

To run the reverse direction, use `noms sign --key-file ./account-key.hex --message 'Hello Nano'` and pipe it to `npx --yes --package @openrai/noms noms verify --account nano_... --message 'Hello Nano' --signature-stdin`. Use only test keys in these examples.

Official references: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) and [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).
