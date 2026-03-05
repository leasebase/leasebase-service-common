# Contributing to @leasebase/service-common

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and
[semantic-release](https://github.com/semantic-release/semantic-release) to automate
versioning and changelog generation.

### Commit Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Release | Description |
|---|---|---|
| `feat` | minor | A new feature or export |
| `fix` | patch | A bug fix |
| `perf` | patch | Performance improvement |
| `docs` | none | Documentation only |
| `style` | none | Formatting, semicolons, etc. |
| `refactor` | none | Code change that neither fixes a bug nor adds a feature |
| `test` | none | Adding or correcting tests |
| `chore` | none | Build process or tooling changes |

### Breaking Changes

Append `!` after the type or add `BREAKING CHANGE:` in the footer to trigger a **major** release:

```
feat!: remove deprecated createApp options

BREAKING CHANGE: The `legacyMode` option has been removed.
```

### Examples

```
feat(middleware): add request-id middleware
fix(jwt): handle expired token edge case
perf(db): add connection pooling
docs: update API reference
```

## Releasing

Releases happen automatically when commits are merged to `main`:
1. Create a PR from your feature branch
2. Use conventional commit messages
3. Merge to `main`
4. semantic-release analyzes commits, bumps version, publishes to GitHub Packages, creates GitHub Release

The version in `package.json` is managed by semantic-release — do not edit it manually.
