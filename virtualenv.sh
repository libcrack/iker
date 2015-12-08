#!/usr/bin/env bash
venv="env"
v=3.5
[[ "$BASH_SOURCE" == "$0" ]] && {
    myself="$(readlink -m ${0#-*})"
    echo "Usage: . $myself" > /dev/stderr
    exit 1
} || {
    [[ -d "$venv" ]] || virtualenv -p "/usr/bin/python${v}" "$venv"
    echo ">> Entering virtual environment \"$venv\"" > /dev/stdout
    source "$venv/bin/activate"
}
