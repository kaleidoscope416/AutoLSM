#!/usr/bin/env bash
# Non-interactive wrapper for demo.sh — auto-answers all prompts
# Usage: bash demo-auto.sh

set -uo pipefail

# Run demo.sh with yes to auto-answer all "按 Enter" prompts
# Use stdbuf to disable output buffering
cd /root/AutoLSM
yes "" | stdbuf -oL bash scripts/demo.sh 2>&1
EXIT_CODE=$?

echo ""
echo "============================================"
echo "  Demo script exited with code: $EXIT_CODE"
echo "============================================"
