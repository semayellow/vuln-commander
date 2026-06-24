#!/usr/bin/env bash
set -euo pipefail

scanner="${1:?scanner name is required}"
relative_install_path="${2:?scanner install path is required}"
relative_queries_path="${3:-}"
root_dir="/vuln-commander"
target_path="${root_dir}/${relative_install_path}"
version_file="${target_path}.version"
queries_target_path=""
queries_version_file=""
queries_url=""
github_token="${GITHUB_TOKEN:-}"

if [[ -n "$relative_queries_path" ]]; then
    queries_target_path="${root_dir}/${relative_queries_path}"
    queries_version_file="${queries_target_path}.version"
fi

if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
elif command -v python3.12 >/dev/null 2>&1; then
    python_bin="python3.12"
elif command -v python >/dev/null 2>&1; then
    python_bin="python"
else
    echo "Python is required to parse scanner release metadata" >&2
    exit 1
fi

latest_release_json() {
    local repository="$1"
    local response_file="${tmp_dir}/release.json"
    local curl_args=(
        -fsSL
        --retry 5
        --retry-delay 2
        --retry-all-errors
        -H "Accept: application/vnd.github+json"
        -H "X-GitHub-Api-Version: 2022-11-28"
        -H "User-Agent: vuln-commander-scanner-installer"
    )

    if [[ -n "$github_token" ]]; then
        curl_args+=(-H "Authorization: Bearer ${github_token}")
    fi

    if ! curl "${curl_args[@]}" "https://api.github.com/repos/${repository}/releases/latest" -o "$response_file"; then
        echo "Failed to fetch latest ${scanner} release from GitHub." >&2
        if scanner_cached_artifacts_exist; then
            echo "Using cached ${scanner} artifacts." >&2
            exit 0
        fi

        echo "No cached ${scanner} artifacts found. Set GITHUB_TOKEN if GitHub rate limiting returns 403." >&2
        exit 1
    fi

    cat "$response_file"
}

json_field() {
    local field="$1"
    "$python_bin" -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

asset_url() {
    local pattern="$1"
    "$python_bin" -c '
import json
import re
import sys

pattern = re.compile(sys.argv[1])
release = json.load(sys.stdin)
for asset in release["assets"]:
    if pattern.search(asset["name"]):
        print(asset["browser_download_url"])
        break
else:
    raise SystemExit(f"No release asset matched {pattern.pattern!r}")
' "$pattern"
}

install_binary_from_tarball() {
    local url="$1"
    local binary_name="$2"
    local destination="$3"
    local archive="${tmp_dir}/${binary_name}.tar.gz"
    local curl_args=(
        -fL
        --retry 5
        --retry-delay 2
        --retry-all-errors
        -H "User-Agent: vuln-commander-scanner-installer"
    )

    if [[ -n "$github_token" ]]; then
        curl_args+=(-H "Authorization: Bearer ${github_token}")
    fi

    if ! curl "${curl_args[@]}" "$url" -o "$archive"; then
        echo "Failed to download ${scanner} release asset from GitHub." >&2
        if [[ -x "$destination" ]]; then
            echo "Using cached ${scanner} binary at ${relative_install_path}." >&2
            exit 0
        fi

        echo "No cached ${scanner} binary found. Set GITHUB_TOKEN if GitHub rate limiting returns 403." >&2
        exit 1
    fi

    tar -xzf "$archive" -C "$tmp_dir"

    local binary_path
    binary_path="$(find "$tmp_dir" -type f -name "$binary_name" -perm -111 | head -n 1)"
    if [[ -z "$binary_path" ]]; then
        echo "Could not find ${binary_name} in ${url}" >&2
        exit 1
    fi

    mkdir -p "$(dirname "$destination")"
    install -m 0755 "$binary_path" "$destination"
}

install_kics_queries() {
    local url="$1"
    local destination="$2"
    local archive="${tmp_dir}/kics-source.tar.gz"
    local source_dir="${tmp_dir}/kics-source"
    local curl_args=(
        -fL
        --retry 5
        --retry-delay 2
        --retry-all-errors
        -H "Accept: application/vnd.github+json"
        -H "User-Agent: vuln-commander-scanner-installer"
    )

    if [[ -n "$github_token" ]]; then
        curl_args+=(-H "Authorization: Bearer ${github_token}")
    fi

    mkdir -p "$source_dir"
    if ! curl "${curl_args[@]}" "$url" -o "$archive"; then
        echo "Failed to download KICS source archive with queries." >&2
        if [[ -d "$destination" ]]; then
            echo "Using cached KICS queries at ${relative_queries_path}." >&2
            return 0
        fi

        echo "No cached KICS queries found. Set GITHUB_TOKEN if GitHub rate limiting returns 403." >&2
        exit 1
    fi

    tar -xzf "$archive" -C "$source_dir"

    local source_queries_path
    source_queries_path="$(find "$source_dir" -type d -path '*/assets/queries' | head -n 1 || true)"
    if [[ -z "$source_queries_path" ]]; then
        echo "Could not find KICS assets/queries in source archive" >&2
        exit 1
    fi

    mkdir -p "$(dirname "$destination")"
    rm -rf "$destination"
    cp -R "$source_queries_path" "$destination"
}

scanner_cached_artifacts_exist() {
    [[ -x "$target_path" ]] || return 1

    if [[ "$scanner" == "kics" ]]; then
        [[ -n "$queries_target_path" && -d "$queries_target_path" ]] || return 1
    fi

    return 0
}

scanner_cache_is_valid() {
    [[ -x "$target_path" && -f "$version_file" && "$(cat "$version_file")" == "$tag" ]] || return 1

    if [[ "$scanner" == "kics" ]]; then
        [[ -n "$queries_target_path" ]] || return 1
        [[ -d "$queries_target_path" ]] || return 1
        [[ -f "$queries_version_file" && "$(cat "$queries_version_file")" == "$tag" ]] || return 1
    fi

    return 0
}

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

case "$scanner" in
    trivy)
        release_json="$(latest_release_json aquasecurity/trivy)"
        tag="$(printf '%s' "$release_json" | json_field tag_name)"
        version="${tag#v}"
        url="$(printf '%s' "$release_json" | asset_url '^trivy_[0-9.]+_Linux-64bit\.tar\.gz$')"
        ;;
    kics)
        if [[ -z "$queries_target_path" ]]; then
            echo "KICS queries install path is required" >&2
            exit 1
        fi
        release_json="$(latest_release_json Checkmarx/kics)"
        tag="$(printf '%s' "$release_json" | json_field tag_name)"
        url="$(printf '%s' "$release_json" | asset_url '^kics_[0-9.]+_linux_amd64\.tar\.gz$')"
        queries_url="$(printf '%s' "$release_json" | json_field tarball_url)"
        ;;
    noseyparker)
        release_json="$(latest_release_json praetorian-inc/noseyparker)"
        tag="$(printf '%s' "$release_json" | json_field tag_name)"
        url="$(printf '%s' "$release_json" | asset_url '^noseyparker-v[0-9.]+-x86_64-unknown-linux-gnu\.tar\.gz$')"
        ;;
    *)
        echo "Unsupported scanner: ${scanner}" >&2
        exit 1
        ;;
esac

if scanner_cache_is_valid; then
    echo "${scanner} ${tag} is already installed at ${relative_install_path}"
    exit 0
fi

echo "Installing ${scanner} ${tag} to ${relative_install_path}"
install_binary_from_tarball "$url" "$scanner" "$target_path"

if [[ "$scanner" == "kics" ]]; then
    install_kics_queries "$queries_url" "$queries_target_path"
    printf '%s' "$tag" > "$queries_version_file"
fi

printf '%s' "$tag" > "$version_file"
