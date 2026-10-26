#!/usr/bin/env bash
cd /home/kali/d5bundle

echo "START_TIME: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" > scripts/full_run_meta.txt
echo "SHELL_PID: $$" >> scripts/full_run_meta.txt

export CRYPTO_PROFILE=prod
export PYTHONUNBUFFERED=1

/home/kali/d5-venv/bin/python3 scripts/run_live_256_acceptance_linux.py --execute-live-acceptance > scripts/full_run_stdout.log 2>&1
EXIT_CODE=$?

echo "EXIT_CODE: $EXIT_CODE" >> scripts/full_run_meta.txt
echo "END_TIME: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> scripts/full_run_meta.txt
echo "$EXIT_CODE" > scripts/full_run_exit_code.txt
