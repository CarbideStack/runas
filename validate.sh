#!/usr/bin/env bash

clear_screen() {
    if [[ -t 1 && -x /usr/bin/clear ]]; then
        /usr/bin/clear
    fi
}

configurations=(
    "Systemd+PAM|use_pam"
    "Systemd+Shadow|"
    "ScopeX+PAM|use_pam,backend_scopex"
    "ScopeX+Shadow|backend_scopex"
    "Run0+PAM|use_pam,backend_run0"
    "Run0+Shadow|backend_run0"
)

list_configurations() {
    for index in "${!configurations[@]}"; do
        IFS='|' read -r name _ <<< "${configurations[index]}"
        printf '%d: %s\n' "$((index + 1))" "$name"
    done
}

with_askpass=false
continue_builds=false
selected=()

for argument in "$@"; do
    case $argument in
        --with-askpass)
            with_askpass=true
            ;;
        --continue)
            continue_builds=true
            ;;
        -l|--list)
            list_configurations
            exit 0
            ;;
        *[!0-9]*|"")
            echo "Usage: $0 [--with-askpass] [--continue] [--list|build-number]" >&2
            exit 2
            ;;
        *)
            if (( ${#selected[@]} != 0 )); then
                echo "Usage: $0 [--with-askpass] [--continue] [--list|build-number]" >&2
                exit 2
            fi

            build_number=$((10#$argument))

            if (( build_number < 1 || build_number > ${#configurations[@]} )); then
                echo "Unknown build number: $argument" >&2
                list_configurations >&2
                exit 2
            fi

            selected=("$((build_number - 1))")
            ;;
    esac
done

if (( ${#selected[@]} == 0 )); then
    selected=("${!configurations[@]}")
fi

if $with_askpass; then
    for index in "${selected[@]}"; do
        IFS='|' read -r name features <<< "${configurations[index]}"
        configurations[index]="$name|${features:+$features,}with_askpass_support"
    done
fi

clear_screen

for position in "${!selected[@]}"; do
    index=${selected[position]}
    IFS='|' read -r name features <<< "${configurations[index]}"

    while true; do
        echo "Checking $name"
        printf '%*s\n' "$((9 + ${#name}))" '' | tr ' ' '-'

        command=(cargo check)

        if [[ -n $features ]]; then
            command+=(--features "$features")
        fi

        if [[ ,$features, == *,use_pam,* ]]; then
            RUSTFLAGS="-l pam" "${command[@]}"
        else
            "${command[@]}"
        fi

        echo "===================="
        echo

        if $continue_builds; then
            break
        fi

        if (( position + 1 < ${#selected[@]} )); then
            prompt="Press Enter to continue, or R to re-run: "
        else
            prompt="Press Enter to finish, or R to re-run: "
        fi

        while true; do
            read -r -p "$prompt" choice || exit $?

            case $choice in
                "")
                    break 2
                    ;;
                [Rr])
                    break
                    ;;
                *)
                    echo "Please press Enter or type R."
                    ;;
            esac
        done

        clear_screen
    done

    if ! $continue_builds; then
        clear_screen
    fi
done
