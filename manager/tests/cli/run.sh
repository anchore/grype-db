#!/usr/bin/env bash

. utils.sh

# run all scripts in the current directory named case-*.sh and exit on first failure
status=0
for script in $(find . -maxdepth 1 -type f -name "case-*.sh" | sort); do
    bash -c "./$script" || { status=1; break; }
done

if [ $status -eq 0 ]; then
    echo -e "${SUCCESS}All tests passed${RESET}"
else
    echo -e "${ERROR}Some tests failed${RESET}"
fi

exit $status