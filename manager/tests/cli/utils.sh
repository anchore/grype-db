#!/usr/bin/env bash

ERROR="\033[1;31m"
SUCCESS="\033[1;32m"
TITLE="\033[1;35m"
RESET="\033[0m"

i=0

temp_files=()

function run() {
    tmp_file=$(mktemp /tmp/grype-db-manager-test.XXXXXX)
    temp_files+=( $tmp_file )
    echo -e "${TITLE}$i| Running $@${RESET}"
    $@ | tee $tmp_file
    rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ]; then
        echo -e "${SUCCESS}Success${RESET}"
    else
        echo -e "${ERROR}Failed: expected zero return code but got $rc${RESET}"
        exit 1
    fi
    ((i++))
}

function run_expect_fail() {
    tmp_file=$(mktemp /tmp/grype-db-manager-test.XXXXXX)
    temp_files+=( $tmp_file )
    echo -e "${TITLE}$i| Running $@${RESET}"
    $@ | tee $tmp_file
    rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ]; then
        echo -e "${ERROR}Failed: expected non-zero return code but got $rc${RESET}"
        exit 1
    else
        echo -e "${SUCCESS}Success: exited with non-zero return code: $rc)${RESET}"
        exit 1
    fi
    ((i++))
}

function last_output_file() {
    echo ${temp_files[${#temp_files[@]} - 1]}
}

function last_output() {
    cat $(last_output_file)
}

function assert_last_output_not_empty() {
    len=$(last_output | wc -l | tr -d ' ')
    if [[ "$len" -gt 0 ]]; then
        return
    fi
    echo -e "${ERROR}Unexpected length $len${RESET}"
    exit 1
}

function assert_last_output_length() {
    expected=$1
    len=$(last_output | wc -l | tr -d ' ')
    if [[ "$len" == "$expected" ]]; then
        return
    fi
    echo -e "${ERROR}Unexpected length $len != $expected${RESET}"
    exit 1
}

function assert_last_output_contains() {
    target=$1
    is_in_file=$(cat $(last_output_file) | grep -c "$target")
    if [ $is_in_file -eq 0 ]; then
        echo -e "${ERROR}Target not found in contents '$target'${RESET}"
        echo -e "${ERROR}...contents:\n$(last_output)${RESET}"
        exit 1
    fi
}

function assert_last_output_does_not_contain() {
    target=$1
    is_in_file=$(cat $(last_output_file) | grep -c "$target")
    if [ $is_in_file -ne 0 ]; then
        echo -e "${ERROR}Target found in contents '$target'${RESET}"
        echo -e "${ERROR}...contents:\n$(last_output)${RESET}"
        exit 1
    fi
}

function end_testing() {
    echo "cleaning up temp files created:"
    for i in ${!temp_files[@]}; do
        echo "   " ${temp_files[$i]}
        rm ${temp_files[$i]}
    done

    echo -e "\n${SUCCESS}PASS${RESET}"
}
