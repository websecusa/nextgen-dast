# Contributing to nextgen-dast

Thanks for your interest in improving nextgen-dast. This document covers
how to file issues, submit pull requests, and what we expect from
contributions.

## Code of Conduct

Be professional. Be kind. Assume good faith. Disagreements about technical
direction are normal and welcome; personal attacks are not. The maintainer
reserves the right to remove comments, lock issues, or block users who
make the project unpleasant to participate in.

## Filing Issues

Before opening a new issue, please:

1. Search the existing issues to see whether your problem has already been
   reported.
2. Confirm you're running the latest `2.1.x` image — older images do not
   receive fixes.
3. Capture the version, host OS, deployment surface (reverse proxy in
   front?), and the relevant log lines from
   `./pentest.sh logs nextgen-dast`.

**Do not file security issues as public bug reports.** See `SECURITY.md`
for the private disclosure process.

When you file a bug, include:

- What you expected to happen.
- What actually happened.
- The shortest reliable reproduction (a `curl` command, a UI click-path,
  a minimal scan request body).
- The image tag (`docker inspect nextgen-dast | grep Image`).
- Any relevant log output, redacted of secrets.

Feature requests are welcome. Open an issue describing the use case
*before* writing a large patch — the maintainer may have context about why
something was done a particular way, or about work-in-progress that would
conflict.

## Pull Requests

### Where to Submit

The canonical repository is hosted at:

> <https://github.com/websecusa/nextgen-dast>

If a mirror exists on another forge (GitHub, GitLab, etc.), pull requests
filed there will be reviewed but may be transferred back to the canonical
repository for final merge.

### Branch and Tag Conventions

- `master` or `main`  is the active development branch.
- Release branches and tags follow the `MAJOR.MINOR.PATCH` pattern
  (e.g. `2.1.1`).
- Never bump the version, Docker tag, or release branch in a pull request
  unless the maintainer has explicitly asked for a release. Submit changes
  against the existing version.

### Style

- **Language:** US English in code, comments, documentation, and commit
  messages. (e.g. *artifact*, not *artefact*.)
- **Python:** PEP 8 with reasonable line-length tolerance. Match the
  surrounding code's conventions where they differ. No formatters are
  enforced; readability and clear naming matter more than mechanical
  formatting.
- **Comments:** Write comments that explain *why*, not *what*. The code
  already says what it does; comments should capture intent, invariants,
  and the reasoning behind non-obvious choices. Future maintainers should
  be able to understand the code without reading the commit history.
- **No author attribution in code.** The repository copyright is held by
  Tim Rice; contributor names belong in commit metadata and changelog
  entries, not in source file headers.
- **No machine-generated attribution.** Do not add `Co-Authored-By`
  trailers, AI assistant references, or generator comments to commits or
  source files.

### Commits

- Each commit should be one logical change. Split unrelated work into
  separate commits.
- Use imperative subject lines under 70 characters
  (`add saml metadata cache`, not `Added SAML metadata cache.`).
- Add a body if the *why* isn't obvious from the subject.
- Sign off your commits to certify the
  [Developer Certificate of Origin](https://developercertificate.org/):

  ```bash
  git commit -s -m "your message"
  ```

  The `-s` flag adds a `Signed-off-by: Your Name <you@example.com>`
  trailer that attests you wrote the change (or have the right to
  contribute it) under the project's license.

### Pull Request Description

Include in the description:

- What problem the change solves.
- The approach you took and any alternatives you considered.
- Testing you performed (manual steps, scan runs, schema migrations
  exercised).
- Any database schema changes — these need to be in `db/schema.sql` *and*
  in a migration step in `app/migrations.py`.
- Any changes to the Docker image surface (new system packages, new
  exposed ports, new env vars).

### Testing Expectations

- **Don't break the bootstrap path.** `sudo ./setup.sh` on a fresh host
  followed by login as `admin` must continue to work.
- **Don't break upgrades.** Existing deployments must be able to
  `./pentest.sh pull && ./pentest.sh up -d` and continue working without
  manual schema repair.
- **Schema changes are migrations.** Any new column, table, or index goes
  into `db/schema.sql` (for fresh installs) and `app/migrations.py` (for
  existing deployments). Both paths must converge to the same state.
- **Test against a real database.** Do not mock MariaDB in tests that
  exercise schema, advisory locks, or transaction boundaries — past
  incidents have shown mock/prod divergence to be a real risk.

## Security-Sensitive Changes

Some areas warrant extra scrutiny in review:

- Authentication, session management, password handling, SAML, recapture.
- The mitmproxy addon and the captured-flows storage path.
- The scanner subprocess invocations (command construction, user-supplied
  input).
- File and template rendering (Jinja2 escaping, PDF/HTML report
  generation).
- The admin password reset / bootstrap path.

If your change touches any of these, call it out in the PR description
and expect a more thorough review.

## What Goes Into the Image

Every functional change must land in the Docker image. The release pipeline
mirrors source into the repository, rebuilds the image at the existing
`2.1.1` tag, pushes to the registry, and commits both `master` and the
`2.1.1` branch. There is no "deploy a hot-fix patch on the host" path; if
it isn't in the image, it doesn't exist for users.

## License

By submitting a contribution, you agree that it will be distributed under
the project's existing license (Apache License 2.0) as described in
`LICENSE.md`, and you certify the contents of the
[Developer Certificate of Origin](https://developercertificate.org/) via
your `Signed-off-by` line.

## Maintainer

Tim Rice &lt;tim.j.rice@hackrange.com&gt;
