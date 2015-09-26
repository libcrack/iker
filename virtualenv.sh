#!/usr/bin/env bash
venv="env"
[[ "$BASH_SOURCE" == "$0" ]] && {
    myself="$(readlink -m ${0#-*})"
    echo "Usage: . $myself" > /dev/stderr
    exit 1
} || {
    [[ -d "$venv" ]] || virtualenv -p /usr/bin/python3.4 "$venv"
    echo ">> Entering virtual environment \"$venv\"" > /dev/stdout
    source "$venv/bin/activate"
}
