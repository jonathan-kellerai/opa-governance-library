#!/usr/bin/env bash
# opa bench baseline for SoFA and SoFREP policies
# Usage: ./bench.sh [--count N]
# Requires: opa (https://www.openpolicyagent.org/docs/latest/#running-opa)

set -euo pipefail

COUNT="${1:-10}"

echo "=== OPA Benchmark Baseline ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "OPA version: $(opa version 2>&1 | head -1)"
echo ""

echo "--- SoFA: data.sofa.standard.summary ---"
opa bench \
  --data sofa/standard/schema.json \
  --data sofa/standard/sofa.rego \
  --input sofa/standard/testdata/valid_input.json \
  --count "$COUNT" \
  'data.sofa.standard.summary' 2>&1 || echo "(bench failed — input file may be missing; run with valid_input.json)"

echo ""
echo "--- SoFA: data.sofa.standard.deny ---"
opa bench \
  --data sofa/standard/schema.json \
  --data sofa/standard/sofa.rego \
  --input sofa/standard/testdata/valid_input.json \
  --count "$COUNT" \
  'data.sofa.standard.deny' 2>&1 || echo "(bench failed — see above)"

echo ""
echo "--- SoFREP: data.sofrep.standard.summary ---"
opa bench \
  --data sofrep/standard/schema.json \
  --data sofrep/standard/sofrep.rego \
  --input sofrep/standard/testdata/valid_input.json \
  --count "$COUNT" \
  'data.sofrep.standard.summary' 2>&1 || echo "(bench failed — input file may be missing; run with valid_input.json)"

echo ""
echo "--- SoFREP: data.sofrep.standard.deny ---"
opa bench \
  --data sofrep/standard/schema.json \
  --data sofrep/standard/sofrep.rego \
  --input sofrep/standard/testdata/valid_input.json \
  --count "$COUNT" \
  'data.sofrep.standard.deny' 2>&1 || echo "(bench failed — see above)"

echo ""
echo "--- OPA Test Performance ---"
echo "SoFA:"
time opa test sofa/standard/ -v 2>&1 | tail -1
echo ""
echo "SoFREP:"
time opa test sofrep/standard/ -v 2>&1 | tail -1

echo ""
echo "=== Benchmark complete ==="
