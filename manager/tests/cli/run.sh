#!/usr/bin/env bash

. utils.sh

# if no arguments are given then use case-*.sh, otherwise use the files given
if [ $# -eq 0 ]; then
    files=$(find . -maxdepth 1 -type f -name "workflow-*.sh" | sort)
else
    files=$@
fi

if [ -z "$files" ]; then
    echo "No test files found"
    exit 1
fi

title "Test scripts to run:"
for script in $files; do
    echo "   $script"
done
echo

# run all scripts in the current directory named workflow-*.sh and exit on first failure
status=0
for script in $files; do
    bash -c "./$script" || { status=1; break; }
done

if [ $status -eq 0 ]; then
    echo -e "${SUCCESS}All tests passed${RESET}"
else
    echo -e "${ERROR}Some tests failed${RESET}"
fi

exit $status