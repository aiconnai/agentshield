#!/usr/bin/env bash
set -euo pipefail

tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$tag" ]]; then
  echo "Usage: $0 v<version>"
  echo "GITHUB_REF_NAME may be used instead of an explicit argument."
  exit 2
fi

version="${tag#v}"
if [[ "$tag" == "$version" ]]; then
  echo "Release tag must start with 'v'; got '$tag'"
  exit 1
fi

cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
if [[ -z "$cargo_version" ]]; then
  echo "Could not read package version from Cargo.toml"
  exit 1
fi

if [[ "$version" != "$cargo_version" ]]; then
  echo "Release tag $tag does not match Cargo.toml version $cargo_version"
  exit 1
fi

release_notes="docs/releases/${version}.md"
if [[ ! -f "$release_notes" ]]; then
  echo "Missing release notes file: $release_notes"
  exit 1
fi

if ! grep -Fq "$version" README.md; then
  echo "README.md does not mention release version $version"
  exit 1
fi

docker_image="ghcr.io/aiconnai/agentshield"
docker_tag="${docker_image}:${version}"
if ! grep -Fq "$docker_tag" README.md; then
  echo "README.md does not document Docker tag $docker_tag"
  exit 1
fi

release_workflow=".github/workflows/release.yml"
docker_workflow=".github/workflows/docker.yml"

if ! grep -Fq 'REGISTRY: ghcr.io' "$docker_workflow"; then
  echo "Docker workflow must publish to the ghcr.io registry"
  exit 1
fi

# shellcheck disable=SC2016 # Match the literal GitHub Actions expression.
if ! grep -Fq 'IMAGE_NAME: ${{ github.repository }}' "$docker_workflow"; then
  echo "Docker workflow must publish the repository image as ${docker_image}"
  exit 1
fi

if ! grep -Fq 'uses: docker/metadata-action@' "$docker_workflow"; then
  echo "Docker workflow must derive canonical image tags with docker/metadata-action"
  exit 1
fi

if ! grep -Fq 'type=semver,pattern={{version}}' "$docker_workflow"; then
  echo "Docker workflow must publish ${docker_image}:<version> without the leading v"
  exit 1
fi

if ! grep -Fq 'type=raw,value=latest' "$docker_workflow"; then
  echo "Docker workflow must publish ${docker_image}:latest"
  exit 1
fi

if grep -Fq 'docker/build-push-action@' "$release_workflow"; then
  echo "Release workflow must not duplicate Docker publishing"
  exit 1
fi

if ! grep -Fq -- "--features full" .github/workflows/release.yml; then
  echo "Release workflow must build binaries with --features full"
  exit 1
fi

if ! grep -Fq -- "--features full" Dockerfile; then
  echo "Dockerfile must build the image with --features full"
  exit 1
fi

if ! grep -Fq "wrap" README.md; then
  echo "README.md must document wrap support for full-feature builds"
  exit 1
fi

changelog_header="## [${version}]"
if ! grep -Fq "$changelog_header" CHANGELOG.md; then
  echo "CHANGELOG.md does not contain entry $changelog_header"
  exit 1
fi

echo "Release invariants passed for $tag"
