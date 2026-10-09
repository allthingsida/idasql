#!/usr/bin/env bash
#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
set -euo pipefail

incoming="${1:?usage: package-release.sh <incoming-dir> <output-dir> [reviewed-revisions.json]}"
output="${2:?usage: package-release.sh <incoming-dir> <output-dir> [reviewed-revisions.json]}"
reviewed_revisions="${3:-}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(realpath "${script_dir}/../..")"
version_header="${repo_root}/src/common/idasql_version.hpp"
manifest_template="${repo_root}/ida-plugin.json.in"
version="$(
  sed -nE \
    's/^#define[[:space:]]+IDASQL_VERSION_STRING[[:space:]]+"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' \
    "${version_header}"
)"
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "could not read a three-component IDASQL_VERSION_STRING from ${version_header}" >&2
  exit 1
fi

mkdir -p "${output}"
incoming="$(realpath "${incoming}")"
output="$(realpath "${output}")"
work="$(mktemp -d "${output}/.package-work.XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "required file is missing: $1" >&2
    exit 1
  fi
}

if [[ -n "${reviewed_revisions}" ]]; then
  require_file "${reviewed_revisions}"
  reviewed_revisions="$(realpath "${reviewed_revisions}")"
fi
require_file "${manifest_template}"

render_expected_manifest() {
  local ida_version="$1"
  local destination="$2"

  sed \
    -e "s|@TOOL_VERSION_STRING@|${version}|g" \
    -e "s|@IDASQL_TARGET_IDA_VERSION@|${ida_version}|g" \
    "${manifest_template}" > "${destination}"
  if grep -Eq '@[A-Za-z0-9_]+@' "${destination}"; then
    echo "unresolved CMake placeholder in configured manifest for IDA ${ida_version}" >&2
    exit 1
  fi
  jq -e \
    --arg version "${version}" \
    --arg ida_version "${ida_version}" \
    '."$schema" == "https://hcli.docs.hex-rays.com/schemas/ida-plugin.json"
      and .IDAMetadataDescriptorVersion == 1
      and .plugin.name == "IDASQL"
      and .plugin.version == $version
      and .plugin.entryPoint == "idasql"
      and .plugin.idaVersions == $ida_version
      and .plugin.platforms == [
        "windows-x86_64",
        "linux-x86_64",
        "macos-aarch64"
      ]' \
    "${destination}" >/dev/null
}

require_matching_manifest() {
  local expected="$1"
  local actual="$2"
  local ida_version="$3"

  require_file "${actual}"
  if ! diff --brief \
    <(jq --sort-keys . "${expected}") \
    <(jq --sort-keys . "${actual}") >/dev/null; then
    echo "manifest does not match ida-plugin.json.in for IDA ${ida_version}: ${actual}" >&2
    exit 1
  fi
}

require_metadata() {
  local artifact_dir="$1"
  local ida_version="$2"
  local sdk_ref="$3"
  local platform="$4"
  local metadata="${artifact_dir}/build-metadata.json"
  local sha_file="${artifact_dir}/ida-cmake-sha.txt"

  require_file "${metadata}"
  require_file "${sha_file}"
  jq -e \
    --arg ida_version "${ida_version}" \
    --arg sdk_ref "${sdk_ref}" \
    --arg platform "${platform}" \
    '.ida_version == $ida_version
      and .sdk_ref == $sdk_ref
      and .platform == $platform
      and (.sdk_sha | test("^[0-9a-fA-F]{40}$"))
      and (.ida_cmake_origin | test("allthingsida/ida-cmake"))
      and (.ida_cmake_sha | test("^[0-9a-fA-F]{40}$"))
      and (.libxsql_origin | test("0xeb/libxsql"))
      and (.libxsql_sha | test("^[0-9a-fA-F]{40}$"))
      and (.fastmcpp_origin | test("0xeb/fastmcpp"))
      and (.fastmcpp_sha | test("^[0-9a-fA-F]{40}$"))' \
    "${metadata}" >/dev/null

  local file_sha metadata_sha
  file_sha="$(tr -d '\r\n' < "${sha_file}")"
  metadata_sha="$(jq -r '.ida_cmake_sha' "${metadata}")"
  if [[ "${file_sha}" != "${metadata_sha}" ]]; then
    echo "ida-cmake provenance mismatch in ${artifact_dir}" >&2
    exit 1
  fi
}

require_single_revision() {
  local label="$1"
  local field="$2"
  shift 2

  local revisions=()
  mapfile -t revisions < <(
    jq -r ".${field}" "$@" | tr -d '\r' | sort -u
  )
  if [[ "${#revisions[@]}" != "1" ]]; then
    echo "matrix builds resolved different ${label} revisions:" >&2
    printf '  %s\n' "${revisions[@]}" >&2
    exit 1
  fi
  printf '%s\n' "${revisions[0]}"
}

require_reviewed_dependency() {
  local dependency="$1"
  local actual="$2"
  local expected
  expected="$(jq -r --arg dependency "${dependency}" \
    '.dependencies[$dependency].sha' "${reviewed_revisions}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unapproved ${dependency} revision: ${actual} (reviewed ${expected})" >&2
    exit 1
  fi
}

require_reviewed_sdk() {
  local ida_version="$1"
  local sdk_ref="$2"
  local sdk_sha="$3"
  local expected_ref expected_sha
  expected_ref="$(jq -r --arg ida_version "${ida_version}" \
    '.ida_sdks[$ida_version].ref' "${reviewed_revisions}")"
  expected_sha="$(jq -r --arg ida_version "${ida_version}" \
    '.ida_sdks[$ida_version].sha' "${reviewed_revisions}")"
  if [[ "${sdk_ref}" != "${expected_ref}" ]]; then
    echo "unapproved IDA ${ida_version} SDK ref: ${sdk_ref} (reviewed ${expected_ref})" >&2
    exit 1
  fi
  if [[ "${sdk_sha}" != "${expected_sha}" ]]; then
    echo "unapproved IDA ${ida_version} SDK revision: ${sdk_sha} (reviewed ${expected_sha})" >&2
    exit 1
  fi
}

create_archive() {
  local archive_path="$1"
  local source_dir="$2"
  shift 2
  local files=("$@")

  (
    cd "${source_dir}"
    zip -X -D -9 "${archive_path}" "${files[@]}"
  )
  diff -u \
    <(printf '%s\n' "${files[@]}" | sort) \
    <(zipinfo -1 "${archive_path}" | sort)
}

mapfile -t metadata_files < <(
  find "${incoming}" -type f -name build-metadata.json -print | sort
)
if [[ "${#metadata_files[@]}" != "12" ]]; then
  echo "expected metadata from 12 matrix builds, found ${#metadata_files[@]}" >&2
  exit 1
fi

mapfile -t ida_cmake_sha_files < <(
  find "${incoming}" -type f -name ida-cmake-sha.txt -print | sort
)
if [[ "${#ida_cmake_sha_files[@]}" != "12" ]]; then
  echo "expected ida-cmake provenance from 12 matrix builds, found ${#ida_cmake_sha_files[@]}" >&2
  exit 1
fi

mapfile -t ida_cmake_shas < <(
  cat "${ida_cmake_sha_files[@]}" | tr -d '\r' | sed '/^$/d' | sort -u
)
if [[ "${#ida_cmake_shas[@]}" != "1" ]]; then
  echo "matrix builds resolved different ida-cmake revisions:" >&2
  printf '  %s\n' "${ida_cmake_shas[@]}" >&2
  exit 1
fi

libxsql_sha="$(
  require_single_revision "libxsql" "libxsql_sha" "${metadata_files[@]}"
)"
fastmcpp_sha="$(
  require_single_revision "fastmcpp" "fastmcpp_sha" "${metadata_files[@]}"
)"

if [[ -n "${reviewed_revisions}" ]]; then
  jq -e '
    .schema == 1
      and (.dependencies.ida_cmake.sha | test("^[0-9a-f]{40}$"))
      and (.dependencies.libxsql.sha | test("^[0-9a-f]{40}$"))
      and (.dependencies.fastmcpp.sha | test("^[0-9a-f]{40}$"))
      and (.ida_sdks["9.2"].sha | test("^[0-9a-f]{40}$"))
      and (.ida_sdks["9.3"].sha | test("^[0-9a-f]{40}$"))
      and (.ida_sdks["9.4"].sha | test("^[0-9a-f]{40}$"))' \
    "${reviewed_revisions}" >/dev/null
  require_reviewed_dependency "ida_cmake" "${ida_cmake_shas[0]}"
  require_reviewed_dependency "libxsql" "${libxsql_sha}"
  require_reviewed_dependency "fastmcpp" "${fastmcpp_sha}"
  cp "${reviewed_revisions}" "${output}/REVIEWED_REVISIONS.json"
fi

printf '%s\n' "${version}" > "${output}/VERSION.txt"
printf '%s\n' "${ida_cmake_shas[0]}" > "${output}/IDA_CMAKE_SHA.txt"
jq -n \
  --arg ida_cmake "${ida_cmake_shas[0]}" \
  --arg libxsql "${libxsql_sha}" \
  --arg fastmcpp "${fastmcpp_sha}" \
  '{
    ida_cmake_sha: $ida_cmake,
    libxsql_sha: $libxsql,
    fastmcpp_sha: $fastmcpp
  }' > "${output}/DEPENDENCY_REVISIONS.json"
jq -s 'sort_by(.ida_version, .platform)' "${metadata_files[@]}" \
  > "${output}/BUILD_METADATA.json"

release_archives=()

for ida in 92 93 94; do
  ida_version="${ida:0:1}.${ida:1:1}"
  case "${ida}" in
    92) sdk_ref="v9.2.0-sdk.1" ;;
    93) sdk_ref="v9.3.0-sdk.3" ;;
    94) sdk_ref="v9.4.0-release" ;;
  esac

  linux_x64="${incoming}/build-ida${ida}-linux-x86_64"
  linux_arm64="${incoming}/build-ida${ida}-linux-arm64"
  macos="${incoming}/build-ida${ida}-macos-arm64"
  windows="${incoming}/build-ida${ida}-windows-x86_64"
  windows_arm64="${incoming}/build-ida${ida}-windows-arm64"

  require_metadata "${linux_x64}" "${ida_version}" "${sdk_ref}" "linux-x86_64"
  require_metadata "${macos}" "${ida_version}" "${sdk_ref}" "macos-arm64"
  require_metadata "${windows}" "${ida_version}" "${sdk_ref}" "windows-x86_64"
  artifact_dirs=("${linux_x64}" "${macos}" "${windows}")
  if [[ "${ida}" != "92" ]]; then
    require_metadata "${linux_arm64}" "${ida_version}" "${sdk_ref}" "linux-arm64"
    artifact_dirs+=("${linux_arm64}")
  fi
  if [[ "${ida}" == "94" ]]; then
    require_metadata \
      "${windows_arm64}" "${ida_version}" "${sdk_ref}" "windows-arm64"
    artifact_dirs+=("${windows_arm64}")
  fi

  sdk_metadata=()
  for artifact_dir in "${artifact_dirs[@]}"; do
    sdk_metadata+=("${artifact_dir}/build-metadata.json")
  done
  sdk_sha="$(
    require_single_revision \
      "IDA ${ida_version} SDK" "sdk_sha" "${sdk_metadata[@]}"
  )"
  if [[ -n "${reviewed_revisions}" ]]; then
    require_reviewed_sdk "${ida_version}" "${sdk_ref}" "${sdk_sha}"
  fi

  expected_manifest="${work}/ida${ida}-ida-plugin.json"
  render_expected_manifest "${ida_version}" "${expected_manifest}"
  for artifact_dir in "${artifact_dirs[@]}"; do
    require_matching_manifest \
      "${expected_manifest}" \
      "${artifact_dir}/plugin/ida-plugin.json" \
      "${ida_version}"
  done

  require_file "${windows}/plugin/idasql.dll"
  require_file "${linux_x64}/plugin/idasql.so"
  require_file "${macos}/plugin/idasql.dylib"
  require_file "${windows}/cli/idasql.exe"
  require_file "${linux_x64}/cli/idasql"
  require_file "${macos}/cli/idasql"
  if [[ "${ida}" != "92" ]]; then
    require_file "${linux_arm64}/plugin/idasql.so"
    require_file "${linux_arm64}/cli/idasql"
  fi
  if [[ "${ida}" == "94" ]]; then
    require_file "${windows_arm64}/plugin/idasql.dll"
    require_file "${windows_arm64}/cli/idasql.exe"
  fi

  # HCLI native archives require the descriptor and all supported host
  # binaries in the same directory, with no enclosing version directory.
  plugin_name="idasql-v${version}-ida${ida}-plugin"
  plugin_dir="${work}/${plugin_name}"
  mkdir -p "${plugin_dir}"
  cp "${expected_manifest}" "${plugin_dir}/ida-plugin.json"
  cp "${windows}/plugin/idasql.dll" "${plugin_dir}/"
  cp "${linux_x64}/plugin/idasql.so" "${plugin_dir}/"
  cp "${macos}/plugin/idasql.dylib" "${plugin_dir}/"
  plugin_files=(
    "ida-plugin.json"
    "idasql.dll"
    "idasql.so"
    "idasql.dylib"
  )
  plugin_archive="${output}/${plugin_name}.zip"
  create_archive "${plugin_archive}" "${plugin_dir}" "${plugin_files[@]}"
  release_archives+=("${plugin_name}.zip")

  # CLI programs are manual downloads, not IDA plugin packages. Keep them in a
  # descriptor-free archive whose paths state the host architecture.
  cli_name="idasql-v${version}-ida${ida}-cli-manual"
  cli_dir="${work}/${cli_name}"
  mkdir -p \
    "${cli_dir}/windows-x86_64" \
    "${cli_dir}/linux-x86_64" \
    "${cli_dir}/macos-arm64"
  printf '%s\n' \
    "IDASQL ${version} command-line tools for IDA ${ida_version}." \
    "This is a manual CLI archive, not an HCLI plugin package." \
    "Copy the executable for your host architecture next to the IDA executable." \
    > "${cli_dir}/INSTALL.txt"
  cp "${windows}/cli/idasql.exe" "${cli_dir}/windows-x86_64/"
  cp "${linux_x64}/cli/idasql" "${cli_dir}/linux-x86_64/"
  cp "${macos}/cli/idasql" "${cli_dir}/macos-arm64/"
  chmod 0755 \
    "${cli_dir}/linux-x86_64/idasql" \
    "${cli_dir}/macos-arm64/idasql"
  cli_files=(
    "INSTALL.txt"
    "windows-x86_64/idasql.exe"
    "linux-x86_64/idasql"
    "macos-arm64/idasql"
  )
  if [[ "${ida}" != "92" ]]; then
    mkdir -p "${cli_dir}/linux-arm64"
    cp "${linux_arm64}/cli/idasql" "${cli_dir}/linux-arm64/"
    chmod 0755 "${cli_dir}/linux-arm64/idasql"
    cli_files+=("linux-arm64/idasql")
  fi
  if [[ "${ida}" == "94" ]]; then
    mkdir -p "${cli_dir}/windows-arm64"
    cp "${windows_arm64}/cli/idasql.exe" "${cli_dir}/windows-arm64/"
    cli_files+=("windows-arm64/idasql.exe")
  fi
  cli_archive="${output}/${cli_name}.zip"
  create_archive "${cli_archive}" "${cli_dir}" "${cli_files[@]}"
  release_archives+=("${cli_name}.zip")

  # HCLI does not currently model Linux or Windows ARM64 native entry points.
  # Publish those plugin binaries separately for explicit manual installation.
  if [[ "${ida}" != "92" ]]; then
    arm_name="idasql-v${version}-ida${ida}-arm64-plugin-manual"
    arm_dir="${work}/${arm_name}"
    mkdir -p "${arm_dir}/linux-arm64"
    printf '%s\n' \
      "IDASQL ${version} ARM64 plugins for IDA ${ida_version}." \
      "This is a manual installation archive, not an HCLI plugin package." \
      "Copy the binary for your host architecture into IDA's plugins directory." \
      "The archive intentionally has no ida-plugin.json descriptor." \
      > "${arm_dir}/INSTALL.txt"
    cp "${linux_arm64}/plugin/idasql.so" "${arm_dir}/linux-arm64/"
    arm_files=(
      "INSTALL.txt"
      "linux-arm64/idasql.so"
    )
    if [[ "${ida}" == "94" ]]; then
      mkdir -p "${arm_dir}/windows-arm64"
      cp "${windows_arm64}/plugin/idasql.dll" "${arm_dir}/windows-arm64/"
      arm_files+=("windows-arm64/idasql.dll")
    fi
    arm_archive="${output}/${arm_name}.zip"
    create_archive "${arm_archive}" "${arm_dir}" "${arm_files[@]}"
    release_archives+=("${arm_name}.zip")
  fi
done

(
  cd "${output}"
  checksum_files=(
    "${release_archives[@]}"
    "VERSION.txt"
    "IDA_CMAKE_SHA.txt"
    "DEPENDENCY_REVISIONS.json"
    "BUILD_METADATA.json"
  )
  if [[ -f REVIEWED_REVISIONS.json ]]; then
    checksum_files+=("REVIEWED_REVISIONS.json")
  fi
  sha256sum "${checksum_files[@]}" > SHA256SUMS.txt
)

echo "IDASQL version: ${version}"
echo "Resolved ida-cmake: ${ida_cmake_shas[0]}"
echo "Resolved libxsql: ${libxsql_sha}"
echo "Resolved fastmcpp: ${fastmcpp_sha}"
cat "${output}/SHA256SUMS.txt"
