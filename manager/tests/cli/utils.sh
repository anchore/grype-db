#!/usr/bin/env bash
set -u

ERROR="\033[1;31m"
SUCCESS="\033[1;32m"
STEP="\033[1;33m"
HEADER="\033[1;34m"
TITLE="\033[1;35m"
RESET="\033[0m"

i=0

stdout_files=()
stderr_files=()



function _run_and_capture() {
    stdout_tmp_file=$(mktemp /tmp/grype-db-manager-test-stdout.XXXXXX)
    stderr_tmp_file=$(mktemp /tmp/grype-db-manager-test-stderr.XXXXXX)
    stdout_files+=( $stdout_tmp_file )
    stderr_files+=( $stderr_tmp_file )

    echo -e "${STEP}$i| Running $@${RESET}"

    # we want to capture stdout and stderr to files but also print them to the screen in realtime. Using tee is the
    # best resource for this, but there is an added challenge of needing the return code of the original command
    # (which is now in a subshell). The "exit PIPESTATUS[0]" solves this by promoting the first command's return
    # code as the subshell's return code.
    ($@  | tee $stdout_tmp_file ; exit ${PIPESTATUS[0]}) 3>&1 1>&2 2>&3 | tee $stderr_tmp_file
    rc=${PIPESTATUS[0]}
    return $rc
}

function run() {
    _run_and_capture $@
    rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${SUCCESS}Success${RESET}"
    else
        echo -e "${ERROR}Failed: expected zero return code but got $rc${RESET}"
        exit 1
    fi
    ((i++))
}

function run_expect_fail() {
    _run_and_capture $@
    rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${ERROR}Failed: expected non-zero return code but got $rc${RESET}"
        exit 1
    else
        echo -e "${SUCCESS}Success: exited with non-zero return code: $rc${RESET}"
    fi
    ((i++))
}

function last_stdout_file() {
    echo ${stdout_files[${#stdout_files[@]} - 1]}
}

function last_stderr_file() {
    echo ${stderr_files[${#stderr_files[@]} - 1]}
}

function last_stdout() {
    cat $(last_stdout_file)
}

function last_stderr() {
    cat $(last_stderr_file)
}

function assert_not_empty() {
    output_file=$1
    len=$(cat $output_file | wc -l | tr -d ' ')
    if [[ "$len" -gt 0 ]]; then
        return
    fi
    echo -e "${ERROR}Unexpected length $len${RESET}"
    exit 1
}

function assert_contains() {
    output_file=$1
    target=$2
    is_in_file=$(cat $output_file | grep -c "$target")
    if [ $is_in_file -eq 0 ]; then
        echo -e "${ERROR}Target not found in contents '$target'${RESET}"
        echo -e "${ERROR}...contents:\n$(cat $output_file)${RESET}"
        exit 1
    fi
}

function assert_does_not_contain() {
    output_file=$1
    target=$1
    is_in_file=$(cat $output_file | grep -c "$target")
    if [ $is_in_file -ne 0 ]; then
        echo -e "${ERROR}Target found in contents '$target'${RESET}"
        echo -e "${ERROR}...contents:\n$(cat output_file)${RESET}"
        exit 1
    fi
}

function header() {
    echo -e "${HEADER}$@${RESET}"
}

function title() {
    echo -e "${TITLE}$@${RESET}"
}

function end_testing() {
    echo "cleaning up temp files created:"
    for i in ${!stdout_files[@]}; do
        echo "   " ${stdout_files[$i]}
        rm ${stdout_files[$i]}
    done

    for i in ${!stderr_files[@]}; do
        echo "   " ${stderr_files[$i]}
        rm ${stderr_files[$i]}
    done

    echo -e "\n${SUCCESS}PASS${RESET}"
}
