#!/usr/bin/env bash
set -euo pipefail
# Hooks and rebase --exec export repository-local paths; never inherit them here.
while IFS= read -r variable; do
    unset "$variable"
done < <(git rev-parse --local-env-vars)
scripts=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$HOME/tmp"
scratch=$(mktemp -d "$HOME/tmp/rustls-rebase-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
git init -q --initial-branch=source "$scratch/repo"
cd "$scratch/repo"
git config user.name 'Rebase test'
git config user.email 'test@example.invalid'
git config commit.gpgsign false
git config core.hooksPath /dev/null
mkdir rustls
printf '[package]\nversion = "0.23.46"\n' > rustls/Cargo.toml
printf 'original\n' > shared
git add .
git commit -qm 'Upstream base'
first_upstream=$(git rev-parse HEAD)
git tag upstream/v/0.23.46
git update-ref refs/remotes/upstream/rel-0.23 HEAD
git branch upstream
printf 'fork\n' > shared
git commit -qam 'Fork patch'
original=$(git rev-parse HEAD)

git switch -q upstream
printf '[package]\nversion = "0.23.47"\n' > rustls/Cargo.toml
printf 'upstream\n' > shared
git commit -qam 'First upstream upgrade'
git tag upstream/v/0.23.47
git update-ref refs/remotes/upstream/rel-0.23 HEAD
git switch -q source
if bash "$scripts/rebase.sh" upstream "$scratch/conflict" > "$scratch/conflict.log" 2>&1; then
    printf 'Expected a rebase conflict\n' >&2
    exit 1
fi
grep -q 'git range-diff' "$scratch/conflict.log"
cd "$scratch/conflict"
printf 'resolved fork\n' > shared
git add shared
GIT_EDITOR=true git rebase --continue
[[ $(git merge-base HEAD upstream) == "$(git rev-parse upstream)" ]]

# The next upgrade must replay only the fork patch, even after manual recovery.
git -C "$scratch/repo" switch -q upstream
printf '[package]\nversion = "0.23.48"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Second upstream upgrade'
git -C "$scratch/repo" tag upstream/v/0.23.48
git -C "$scratch/repo" update-ref refs/remotes/upstream/rel-0.23 HEAD
caller=$(git rev-parse HEAD)
env GIT_DIR="$(git rev-parse --absolute-git-dir)" GIT_WORK_TREE="$PWD" \
    GIT_INDEX_FILE="$(git rev-parse --git-path index)" \
    bash "$scripts/rebase.sh" upstream "$scratch/clean"
cd "$scratch/clean"
[[ $(git rev-list --count upstream..HEAD) == 1 ]]
[[ $(git -C "$scratch/repo" rev-parse source) == "$original" ]]
[[ $(cat shared) == 'resolved fork' ]]
git merge-base --is-ancestor upstream HEAD
[[ $(git -C "$scratch/conflict" rev-parse HEAD) == "$caller" ]]
release=$(git rev-parse upstream)
[[ $(git branch --show-current) == "reality/0.23.48-${release:0:12}" ]]
candidate=$(git rev-parse HEAD)
if bash "$scripts/rebase.sh" upstream "$scratch/duplicate" > "$scratch/duplicate.log" 2>&1; then
    printf 'Expected an existing release branch to be preserved\n' >&2
    exit 1
fi
[[ ! -e "$scratch/duplicate" ]]
[[ $(git rev-parse HEAD) == "$candidate" ]]

if [[ ${1:-} != --nested ]]; then
    config=$(git rev-parse --git-path config)
    cp "$config" "$scratch/config-before"
    git show-ref > "$scratch/refs-before"
    index=$(git rev-parse --git-path index)
    cp "$index" "$scratch/index-before"
    env GIT_DIR="$(git rev-parse --absolute-git-dir)" GIT_WORK_TREE="$PWD" GIT_INDEX_FILE="$index" \
        bash "$scripts/test-rebase.sh" --nested > "$scratch/nested.log" 2>&1 || {
        cat "$scratch/nested.log"
        exit 1
    }
    cmp "$config" "$scratch/config-before"
    cmp "$index" "$scratch/index-before"
    git show-ref > "$scratch/refs-after"
    cmp "$scratch/refs-before" "$scratch/refs-after"
    git rebase --force-rebase -x "bash '$scripts/test-rebase.sh' --nested" upstream > "$scratch/exec.log" 2>&1 || {
        cat "$scratch/exec.log"
        exit 1
    }
    cmp "$config" "$scratch/config-before"
    [[ $(git rev-list --count upstream..HEAD) == 1 ]]
    [[ $(git -C "$scratch/repo" rev-parse source) == "$original" ]]
fi

printf 'uncommitted change\n' > shared
git add shared
if bash "$scripts/check.sh" upstream > "$scratch/dirty.log" 2>&1; then
    printf 'Expected staged changes to fail validation\n' >&2
    exit 1
fi
grep -q 'Commit the candidate' "$scratch/dirty.log"
git restore --source=HEAD --staged --worktree shared

git config status.showUntrackedFiles no
printf 'untracked release input\n' > untracked.rs
if bash "$scripts/check.sh" upstream > "$scratch/untracked.log" 2>&1; then
    printf 'Expected hidden untracked inputs to fail validation\n' >&2
    exit 1
fi
grep -q 'Commit the candidate' "$scratch/untracked.log"
if bash "$scripts/rebase.sh" upstream "$scratch/untracked" > "$scratch/untracked-rebase.log" 2>&1; then
    printf 'Expected hidden untracked inputs to prevent rebase preparation\n' >&2
    exit 1
fi
grep -q 'Commit or stash changes' "$scratch/untracked-rebase.log"
rm untracked.rs
git config --unset status.showUntrackedFiles

printf 'committed trailing whitespace \n' > invalid
git add invalid
git commit -qm 'Invalid conflict resolution'
if bash "$scripts/check.sh" upstream > "$scratch/check.log" 2>&1; then
    printf 'Expected committed whitespace to fail validation\n' >&2
    exit 1
fi
grep -q 'trailing whitespace' "$scratch/check.log"

git -C "$scratch/repo" switch -q upstream
printf 'unreleased upstream change\n' > "$scratch/repo/unreleased"
git -C "$scratch/repo" add unreleased
git -C "$scratch/repo" commit -qm 'Unreleased upstream commit'
git -C "$scratch/repo" update-ref refs/remotes/upstream/rel-0.23 HEAD
if bash "$scripts/rebase.sh" upstream "$scratch/unreleased" > "$scratch/unreleased.log" 2>&1; then
    printf 'Expected an unreleased target to be rejected\n' >&2
    exit 1
fi
grep -q 'not the upstream stable release' "$scratch/unreleased.log"
[[ ! -e "$scratch/unreleased" ]]
for base in upstream upstream/v/0.23.48; do
    if (cd "$scratch/repo" && bash "$scripts/check.sh" "$base") > "$scratch/unreleased-check.log" 2>&1; then
        printf 'Expected validation to reject an unreleased base, including with an older release argument\n' >&2
        exit 1
    fi
    grep -q 'Candidate must be based on' "$scratch/unreleased-check.log"
done
printf '[package]\nversion = "0.23.49"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Unfetched release'
git -C "$scratch/repo" update-ref refs/remotes/upstream/rel-0.23 HEAD
if bash "$scripts/rebase.sh" upstream "$scratch/unfetched" > "$scratch/unfetched.log" 2>&1; then
    printf 'Expected a target without an upstream release tag to be rejected\n' >&2
    exit 1
fi
grep -q 'Fetch upstream stable release tags' "$scratch/unfetched.log"
[[ ! -e "$scratch/unfetched" ]]

git -C "$scratch/repo" switch -qc breaking upstream
printf '[package]\nversion = "0.24.0"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Breaking upstream upgrade'
git -C "$scratch/repo" update-ref refs/remotes/upstream/rel-0.23 HEAD
if bash "$scripts/rebase.sh" breaking "$scratch/breaking" > "$scratch/breaking.log" 2>&1; then
    printf 'Expected a breaking upgrade to be rejected\n' >&2
    exit 1
fi
grep -q 'Refusing a breaking upgrade' "$scratch/breaking.log"
[[ ! -e "$scratch/breaking" ]]
if bash "$scripts/rebase.sh" "$first_upstream" "$scratch/stale" > "$scratch/stale.log" 2>&1; then
    printf 'Expected stale upstream targets to be rejected\n' >&2
    exit 1
fi
grep -q 'not an upgrade on upstream/rel-0.23' "$scratch/stale.log"
git -C "$scratch/repo" switch -qc offbranch upstream
printf '[package]\nversion = "0.23.50"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Unrelated release branch'
if bash "$scripts/rebase.sh" offbranch "$scratch/offbranch" > "$scratch/offbranch.log" 2>&1; then
    printf 'Expected unrelated upstream targets to be rejected\n' >&2
    exit 1
fi
grep -q 'not an upgrade on upstream/rel-0.23' "$scratch/offbranch.log"
git merge --no-ff -s ours -qm 'Unsupported fork merge' offbranch
if bash "$scripts/rebase.sh" upstream "$scratch/merged" > "$scratch/merged.log" 2>&1; then
    printf 'Expected merged fork patches to be rejected\n' >&2
    exit 1
fi
grep -q 'Fork patches must be a linear series' "$scratch/merged.log"
printf 'Stable release admission, branch preservation, rebase recovery, Git isolation, and candidate checks passed.\n'
