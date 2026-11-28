# Maintaining cfal/rustls

Each upstream stable release has a branch named
`reality/<version>-<upstream-commit-prefix>`, for example
`reality/0.23.46-f04804fa1334`. The branch starts at the exact upstream release
commit, not the moving `rel-0.23` head or breaking `main` development line.
Shoes pins the full patched commit ID. Published release branches and tags stay
reachable; upgrades never rebase or force-push a published branch.

Keep two logical patches on each new release: connection-owned REALITY support
with regression tests, and fork maintenance tooling. Squash corrective commits
only while preparing an unpublished branch. Fixes to an already published
release branch are ordinary fast-forward commits.

REALITY APIs are opt-in and connection-owned; ordinary TLS and QUIC retain the
upstream paths. Record padding is supported by the AWS-LC provider only.

## Upgrade Procedure

1. Start from the currently deployed release branch with a clean worktree.
   Add `https://github.com/rustls/rustls.git` as remote `upstream`, then fetch:
   `git fetch upstream rel-0.23 'refs/tags/v/0.23.*:refs/tags/upstream/v/0.23.*'`.
   The separate tag namespace identifies upstream releases, not fork tags.
2. Select a stable release, for example `upstream/v/0.23.47`, and run
   `bash .fork/rebase.sh upstream/v/0.23.47 "$HOME/tmp/rustls-upgrade"`.
   This creates a new version/hash-named branch and worktree. It never changes
   the source branch or pushes. Unreleased commits, downgrades, incompatible
   versions and non-linear patch histories are rejected. An existing candidate
   branch is not overwritten. Resolve conflicts there with `git rebase --continue`
   and review the printed range-diff and upstream security/release notes.
3. Commit resolutions and run `bash .fork/check.sh upstream/v/0.23.47` in the
   candidate. The gate refuses dirty inputs and non-release bases. Use an
   external `CARGO_TARGET_DIR` on constrained machines. Review finalized
   ClientHello/session-ID state, exact transcripts, provider-owned exchange
   binding, config isolation, and record padding/epochs. The minimal 28-byte
   EncryptedExtensions case must succeed; undersized records must still fail.
4. Point Shoes at the candidate revision and run its REALITY security, fallback,
   Vision, pinned Xray, sing-box, and ordinary TLS/QUIC suites. Do not infer
   Shoes compatibility from rustls tests alone.
5. Before publishing, fetch the source release branch and require it still to
   equal the `Source:` commit printed by the script. If it changed, prepare a
   new candidate containing those fixes. Push the new branch without force:
   `git push -u origin HEAD:refs/heads/reality/<version>-<upstream-prefix>`.
   Never overwrite an existing release branch or move a published tag. Update
   Shoes' exact commit pin and lockfile only after the commit is reachable.
6. Make the active release branch the fork's default when promoting it, so the
   maintenance documentation and scheduled workflow follow the deployed series.
   Remove the local candidate worktree after promotion; retain published refs.

The scheduled workflow fetches stable releases, validates a candidate, and
uploads a bundle and range-diff for review. If there is no newer release, it
validates the current branch. It never publishes refs, changes the default
branch or consumer pins, or includes unreleased `rel-0.23` commits. Fork Actions
must be enabled; disable inherited upstream scheduled jobs unless wanted.

## Consumer Contract

- `new_reality` does not supply authentication. The caller owns per-connection
  certificate policy and must verify HMAC/required ML-DSA and CertificateVerify.
- The server must synthesize in memory, validate the complete staged record
  layout, then publish bytes. On any pre-commit error discard the connection,
  including all queued ServerHello, CCS and alert records.
- `RealityUnsupported` describes template/peer incompatibility. Invalid local
  config or absent provider padding support is not permission to forward.
- No TLS 1.2, resumption, 0-RTT, ECH or HelloRetryRequest in authenticated REALITY.
  Server ALPN, client auth and `max_fragment_size` are rejected. REALITY omits
  the SNI acknowledgement; ordinary TLS keeps it. Browser profile emulation
  and target background probing are not implemented.
