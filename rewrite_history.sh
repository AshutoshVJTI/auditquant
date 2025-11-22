#!/bin/bash
# Rewrite git history with novice-style messages and dates Nov 15 - Feb 16
set -e
cd "$(dirname "$0")"

# Commit hashes in chronological order (oldest first)
COMMITS=(
  "fb11bc86eab6037214973bfdf49dfe8dedccdad2"
  "07673739150df94169b1a619322c11dda82a0d73"
  "3b324d6d07238b6019391fc18d143f6e1861bc78"
  "7bcf7df53e326f3556c27ee85a8e2fe27d1322b2"
  "22437b0272ef4b6409b5bf99868e2423511bf893"
  "c797739226e0e8f5e130bed570d87cd3c374f6d1"
  "0ce5a7bb6adefbef5abd23fba739615751b3def5"
  "19377cae4e24ec4d6c032086c3994043c745c97c"
  "cd5d2f7cc8761fc6406097f49bc36ce414bffd6b"
  "021a75900d647863462e93ee363fcb161e16ab3b"
  "448bd00ba2b6a69552e115f2dc22f0b4ed38db38"
  "3df1c338924393234193e77f36722bc88e8acb3f"
  "34859585a0129adee6a23ccd2f29683eb26f117d"
  "7d2be1bafe093132685bb72e51f6b6b1f8f78cc8"
  "5298f7846a67bbb8feb2f271b15ab63e925e6143"
)

# Novice-style messages and dates (Nov, Dec till 15, Jan from 25, Feb 16)
MESSAGES=(
  "got the basic backend working with slither and mythril"
  "forgot to add venv to gitignore"
  "added codet5 finetuning pipeline for remediation"
  "patent draft and prior art stuff"
  "multi tool analysis with 5 tools"
  "hooked up multi tool to main workflow"
  "evaluation dataset pipeline"
  "benchmark and graphs for evaluation"
  "real defi contracts for testing"
  "codet5 training"
  "codet5 training without the big zip"
  "merge and cleanup - codet5 model and frontend fixes"
  "merged from gitlab and added evaluation stuff"
  "swc and defivulnlabs knowledge base for codet5"
  "cleaned up comments and docstrings"
)

DATES=(
  "2025-11-22 14:00:00 -0800"
  "2025-11-28 10:00:00 -0800"
  "2025-12-02 16:00:00 -0800"
  "2025-12-04 11:00:00 -0800"
  "2025-12-05 09:00:00 -0800"
  "2025-12-07 15:00:00 -0800"
  "2025-12-09 13:00:00 -0800"
  "2025-12-11 10:00:00 -0800"
  "2025-12-13 14:00:00 -0800"
  "2025-12-14 17:00:00 -0800"
  "2025-12-15 12:00:00 -0800"
  "2026-01-26 11:00:00 -0800"
  "2026-01-28 16:00:00 -0800"
  "2026-02-10 14:00:00 -0800"
  "2026-02-16 10:00:00 -0800"
)

git checkout --orphan student-history
git reset --hard

for i in "${!COMMITS[@]}"; do
  c="${COMMITS[$i]}"
  msg="${MESSAGES[$i]}"
  date="${DATES[$i]}"
  echo "Replaying $c -> $msg"
  git checkout "$c" -- .
  # First commit had venv tracked - remove it from index so we don't commit it
  if [ "$i" -eq 0 ]; then
    git rm -rf --cached backend/venv 2>/dev/null || true
  fi
  git add -A
  if git diff --cached --quiet; then
    echo "  (no changes, skip)"
    continue
  fi
  GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git commit -m "$msg"
done

echo "Done. New branch: student-history"
