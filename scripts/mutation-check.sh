#!/usr/bin/env bash
# Seeds one known bug at a time into LeashAccount.sol and checks that the invariant suite (not the unit tests)
# catches it. A surviving mutant means an invariant is too weak.
#
#   scripts/mutation-check.sh            # every mutant
#   scripts/mutation-check.sh cap-check  # one by name
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$root/contracts/src/LeashAccount.sol"
backup="$(mktemp)"
cp "$src" "$backup"
trap 'cp "$backup" "$src"; rm -f "$backup"' EXIT

export PATH="$PATH:$HOME/.foundry/bin"

# Not listed: the runtime ForbiddenTarget check. grantSession already refuses to allowlist the account or the
# EntryPoint, so removing it changes nothing observable (an equivalent mutant); it stays as defense in depth.
#
# name~original line fragment~replacement
mutants=(
  "cap-check~if (assetSpent > a.periodCap) {~if (false) {"
  "counterparty-check~if (cpSpent > limit) {~if (false) {"
  "charge-on-decrease~if (afterwards[j] < before[j]) _charge~if (false) _charge"
  "approval-restore~IERC20(a.token).forceApprove(a.spender, a.previous);~a;"
  "token-selector-gate~            revert ForbiddenTokenCall(target, selector);~            return (target, false);"
  "allowlist~if (!p.allowed) revert CallNotAllowed(target, selector);~p;"
  "recipient-pin~if (p.selfArg != 0) {~if (false) {"
  "session-signer~signer != key) return SIG_VALIDATION_FAILED~signer == address(0)) return SIG_VALIDATION_FAILED"
  "passkey-check~if (escalatedWord == 1 && !_isPasskeySignature(userOpHash, passkeyAuth))~if (false)"
  "zero-value-ping~if (c.value == 0) revert MalformedCall();~c;"
)

only="${1:-}"
caught=0
survived=0
for m in "${mutants[@]}"; do
  IFS='~' read -r name from to <<<"$m"
  [[ -n "$only" && "$only" != "$name" ]] && continue
  cp "$backup" "$src"
  if ! grep -qF -- "$from" "$src"; then
    echo "!! $name: fragment not found, update the script"
    exit 1
  fi
  python3 - "$src" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
open(path, "w").write(text.replace(old, new, 1))
PY
  if ! (cd "$root/contracts" && forge build >/dev/null 2>&1); then
    echo "!! $name: mutant does not compile, update the script"
    exit 1
  fi
  if (cd "$root/contracts" && forge test --match-contract Invariant >/dev/null 2>&1); then
    echo "SURVIVED  $name"
    survived=$((survived + 1))
  else
    echo "caught    $name"
    caught=$((caught + 1))
  fi
done

echo "$caught caught, $survived survived"
[[ $survived -eq 0 ]]
