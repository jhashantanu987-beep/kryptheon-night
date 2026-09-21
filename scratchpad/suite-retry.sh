#!/usr/bin/env bash
# Runs each check separately and retries the ones that died rather than failed.
#
# `npm run check` chains sixteen suites with `&&`, and `&&` cannot tell a
# failing check from a dropped connection - which has happened repeatedly on
# long runs against a remote database. A check that genuinely failed prints a
# FAIL line. A check whose link died prints no FAIL line at all, and is worth
# running again; a check that failed is not.

set -u
cd /c/Users/jhash/code/kryptheon-night
# KN_DATABASE_URL must already be in the environment.

PASSED=()
FAILED=()
DROPPED=()

for suite in "$@"; do
  file="${suite}.check.js"
  attempt=1
  while true; do
    started=$(date +%s)
    out=$(node "$file" 2>&1)
    code=$?
    took=$(( $(date +%s) - started ))

    if [ $code -eq 0 ]; then
      n=$(printf '%s\n' "$out" | grep -c '^PASS')
      echo "PASS  $suite  (${n} checks, ${took}s)"
      PASSED+=("$suite")
      break
    fi

    if printf '%s\n' "$out" | grep -q '^FAIL'; then
      echo "FAIL  $suite  (${took}s)"
      printf '%s\n' "$out" | grep -A3 '^FAIL' | sed 's/^/        /'
      FAILED+=("$suite")
      break
    fi

    # No FAIL line and a non-zero exit: the run did not finish. Almost always
    # the connection, occasionally a crash - either way the output is printed
    # so it is never silently retried away.
    echo "DIED  $suite  attempt ${attempt} (${took}s)"
    printf '%s\n' "$out" | tail -4 | sed 's/^/        /'
    if [ $attempt -ge 3 ]; then
      DROPPED+=("$suite")
      break
    fi
    attempt=$(( attempt + 1 ))
    sleep 3
  done
done

echo ""
echo "passed:  ${#PASSED[@]}   ${PASSED[*]:-}"
echo "failed:  ${#FAILED[@]}   ${FAILED[*]:-}"
echo "died:    ${#DROPPED[@]}   ${DROPPED[*]:-}"
[ ${#FAILED[@]} -eq 0 ] && [ ${#DROPPED[@]} -eq 0 ]
