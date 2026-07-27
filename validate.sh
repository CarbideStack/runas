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

case $# in
    0)
        selected=("${!configurations[@]}")
        ;;
    1)
        case $1 in
            -l|--list)
                list_configurations
                exit 0
                ;;
            *[!0-9]*|"")
                echo "Usage: $0 [--list|build-number]" >&2
                exit 2
                ;;
            *)
                build_number=$((10#$1))

                if (( build_number < 1 || build_number > ${#configurations[@]} )); then
                    echo "Unknown build number: $1" >&2
                    list_configurations >&2
                    exit 2
                fi

                selected=("$((build_number - 1))")
                ;;
        esac
        ;;
    *)
        echo "Usage: $0 [--list|build-number]" >&2
        exit 2
        ;;
esac

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

    clear_screen
done
