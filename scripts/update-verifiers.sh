#!/usr/bin/env bash
set -euo pipefail

# Copies verifier contracts from verifier-contracts/ into contracts/passport/verifiers2/noir/
# and renames them from Z_NOIR_PASSPORT_{params}Verifier.sol → NoirRegisterIdentity_{params}.sol,
# replacing `contract UltraVerifier` with `contract NoirRegisterIdentity_{params}`.

SRC_DIR="verifier-contracts"
DEST_DIR="contracts/passport/verifiers2/noir"

if [ ! -d "$SRC_DIR" ]; then
  echo "Error: $SRC_DIR directory not found"
  exit 1
fi

mkdir -p "$DEST_DIR"

count=0

for src_file in "$SRC_DIR"/Z_NOIR_PASSPORT_*Verifier.sol; do
  [ -f "$src_file" ] || continue

  # Extract filename without path
  basename=$(basename "$src_file")

  # Extract params: Z_NOIR_PASSPORT_{params}Verifier.sol → {params}
  params="${basename#Z_NOIR_PASSPORT_}"
  params="${params%Verifier.sol}"

  contract_name="NoirRegisterIdentity_${params}"
  dest_file="${DEST_DIR}/${contract_name}.sol"

  # Copy and rename contract UltraVerifier → contract NoirRegisterIdentity_{params}
  sed "s/contract UltraVerifier/contract ${contract_name}/" "$src_file" > "$dest_file"

  count=$((count + 1))
done

echo "Updated $count verifier contracts in $DEST_DIR"
