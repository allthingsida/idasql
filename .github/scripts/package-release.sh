#!/usr/bin/env bash
set -euo pipefail

incoming="${1:?usage: package-release.sh <incoming-dir> <output-dir>}"
output="${2:?usage: package-release.sh <incoming-dir> <output-dir>}"
version="0.0.18.1"

mkdir -p "${output}" package-work
incoming="$(realpath "${incoming}")"
output="$(realpath "${output}")"
work="$(realpath package-work)"

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "required file is missing: $1" >&2
    exit 1
  fi
}

require_matching_manifest() {
  local expected="$1"
  local actual="$2"
  local ida_version="$3"

  if ! diff --brief \
    <(jq --sort-keys . "${expected}") \
    <(jq --sort-keys . "${actual}") >/dev/null; then
    echo "manifest mismatch for IDA ${ida_version}: $(dirname "$(dirname "${actual}")")" >&2
    exit 1
  fi
}

mapfile -t ida_cmake_shas < <(
  find "${incoming}" -type f -name ida-cmake-sha.txt -print0 \
    | xargs -0 cat \
    | tr -d '\r' \
    | sed '/^$/d' \
    | sort -u
)
metadata_count="$(
  find "${incoming}" -type f -name build-metadata.json | wc -l | tr -d ' '
)"
if [[ "${metadata_count}" != "10" ]]; then
  echo "expected metadata from 10 matrix builds, found ${metadata_count}" >&2
  exit 1
fi
if [[ "${#ida_cmake_shas[@]}" != "1" ]]; then
  echo "matrix builds resolved different ida-cmake revisions:" >&2
  printf '  %s\n' "${ida_cmake_shas[@]}" >&2
  exit 1
fi
printf '%s\n' "${ida_cmake_shas[0]}" > "${output}/IDA_CMAKE_SHA.txt"

release_archives=()

for ida in 92 93 94; do
  ida_version="${ida:0:1}.${ida:1:1}"
  linux="${incoming}/build-ida${ida}-linux-x86_64"
  macos="${incoming}/build-ida${ida}-macos-arm64"
  windows="${incoming}/build-ida${ida}-windows-x86_64"
  arm64="${incoming}/build-ida${ida}-windows-arm64"

  for platform_dir in "${linux}" "${macos}" "${windows}"; do
    require_file "${platform_dir}/plugin/ida-plugin.json"
    require_matching_manifest \
      "${linux}/plugin/ida-plugin.json" \
      "${platform_dir}/plugin/ida-plugin.json" \
      "${ida_version}"
  done
  if [[ "${ida}" == "94" ]]; then
    require_file "${arm64}/plugin/ida-plugin.json"
    require_matching_manifest \
      "${linux}/plugin/ida-plugin.json" \
      "${arm64}/plugin/ida-plugin.json" \
      "${ida_version}"
  fi

  jq -e \
    --arg version "${version}" \
    --arg ida_version "${ida_version}" \
    '.plugin.version == $version and .plugin.idaVersions == $ida_version' \
    "${linux}/plugin/ida-plugin.json" >/dev/null

  bundle_name="idasql-v${version}-ida${ida}"
  bundle_dir="${work}/${bundle_name}"
  mkdir -p \
    "${bundle_dir}/windows-x86_64/cli" \
    "${bundle_dir}/windows-x86_64/plugin" \
    "${bundle_dir}/linux-x86_64/cli" \
    "${bundle_dir}/linux-x86_64/plugin" \
    "${bundle_dir}/macos-arm64/cli" \
    "${bundle_dir}/macos-arm64/plugin"

  require_file "${windows}/plugin/idasql.dll"
  require_file "${linux}/plugin/idasql.so"
  require_file "${macos}/plugin/idasql.dylib"
  require_file "${windows}/cli/idasql.exe"
  require_file "${linux}/cli/idasql"
  require_file "${macos}/cli/idasql"

  for platform_dir in \
    "${bundle_dir}/windows-x86_64/plugin" \
    "${bundle_dir}/linux-x86_64/plugin" \
    "${bundle_dir}/macos-arm64/plugin"; do
    cp "${linux}/plugin/ida-plugin.json" "${platform_dir}/"
  done
  cp "${windows}/plugin/idasql.dll" \
    "${bundle_dir}/windows-x86_64/plugin/"
  cp "${windows}/cli/idasql.exe" \
    "${bundle_dir}/windows-x86_64/cli/"
  cp "${linux}/plugin/idasql.so" \
    "${bundle_dir}/linux-x86_64/plugin/"
  cp "${linux}/cli/idasql" \
    "${bundle_dir}/linux-x86_64/cli/"
  cp "${macos}/plugin/idasql.dylib" \
    "${bundle_dir}/macos-arm64/plugin/"
  cp "${macos}/cli/idasql" \
    "${bundle_dir}/macos-arm64/cli/"
  chmod 0755 \
    "${bundle_dir}/linux-x86_64/cli/idasql" \
    "${bundle_dir}/macos-arm64/cli/idasql"

  bundle_files=(
    "${bundle_name}/windows-x86_64/cli/idasql.exe"
    "${bundle_name}/windows-x86_64/plugin/ida-plugin.json"
    "${bundle_name}/windows-x86_64/plugin/idasql.dll"
    "${bundle_name}/linux-x86_64/cli/idasql"
    "${bundle_name}/linux-x86_64/plugin/ida-plugin.json"
    "${bundle_name}/linux-x86_64/plugin/idasql.so"
    "${bundle_name}/macos-arm64/cli/idasql"
    "${bundle_name}/macos-arm64/plugin/ida-plugin.json"
    "${bundle_name}/macos-arm64/plugin/idasql.dylib"
  )

  if [[ "${ida}" == "94" ]]; then
    require_file "${arm64}/plugin/idasql.dll"
    require_file "${arm64}/cli/idasql.exe"
    mkdir -p \
      "${bundle_dir}/windows-arm64/cli" \
      "${bundle_dir}/windows-arm64/plugin"
    cp "${linux}/plugin/ida-plugin.json" \
      "${bundle_dir}/windows-arm64/plugin/"
    cp "${arm64}/plugin/idasql.dll" \
      "${bundle_dir}/windows-arm64/plugin/"
    cp "${arm64}/cli/idasql.exe" \
      "${bundle_dir}/windows-arm64/cli/"
    bundle_files+=(
      "${bundle_name}/windows-arm64/cli/idasql.exe"
      "${bundle_name}/windows-arm64/plugin/ida-plugin.json"
      "${bundle_name}/windows-arm64/plugin/idasql.dll"
    )
  fi

  bundle_zip="${output}/${bundle_name}.zip"
  rm -f "${bundle_zip}"
  (
    cd "${work}"
    zip -X -D -9 "${bundle_zip}" "${bundle_files[@]}"
  )

  diff -u \
    <(printf '%s\n' "${bundle_files[@]}" | sort) \
    <(zipinfo -1 "${bundle_zip}" | sort)
  release_archives+=("${bundle_name}.zip")
done

(
  cd "${output}"
  sha256sum "${release_archives[@]}" > SHA256SUMS.txt
)

echo "Resolved ida-cmake: ${ida_cmake_shas[0]}"
cat "${output}/SHA256SUMS.txt"
