#!/usr/bin/env bash
# Installs cryptosis from GitHub Releases into ~/.local/bin (no sudo).
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/turiya-fps/cryptosis/main/install.sh | bash
#
# Environment:
#   CRYPTOSIS_VERSION         release tag to install (e.g. v0.1.0); default: latest
#   CRYPTOSIS_INSTALL_DIR     default: ~/.local/bin
#   CRYPTOSIS_REQUIRE_COSIGN  1 = fail unless the cosign signature is verified
#
# The sha256 check only proves the archive matches checksums.txt from the same
# release. If cosign is installed, the script also verifies that checksums.txt
# was signed by this repository's release workflow for that tag.
set -euo pipefail

REPO="turiya-fps/cryptosis"
tmp="" # global: the EXIT trap runs after main returns

main() {
	local install_dir="${CRYPTOSIS_INSTALL_DIR:-$HOME/.local/bin}"
	local os arch tag version archive

	need curl
	need tar
	os="$(detect_os)"
	arch="$(detect_arch)"
	tag="${CRYPTOSIS_VERSION:-$(latest_tag)}"
	[[ "$tag" == v* ]] || tag="v$tag"
	[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a release tag: $tag"
	version="${tag#v}"
	archive="cryptosis_${version}_${os}_${arch}.tar.gz"

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT

	say "Downloading cryptosis $tag ($os/$arch)"
	local base="https://github.com/$REPO/releases/download/$tag"
	fetch "$base/$archive" "$tmp/$archive"
	fetch "$base/checksums.txt" "$tmp/checksums.txt"

	verify_sha256 "$tmp" "$archive"
	verify_cosign "$tmp" "$base" "$tag"

	tar -xzf "$tmp/$archive" -C "$tmp" cryptosis
	mkdir -p "$install_dir"
	# Copy next to the destination, then rename: never a half-written binary.
	cp "$tmp/cryptosis" "$install_dir/.cryptosis.new"
	chmod 0755 "$install_dir/.cryptosis.new"
	mv -f "$install_dir/.cryptosis.new" "$install_dir/cryptosis"

	say "Installed $("$install_dir/cryptosis" --version) to $install_dir/cryptosis"
	case ":$PATH:" in
	*":$install_dir:"*) ;;
	*) say "Note: $install_dir is not on your PATH; add it in your shell profile." ;;
	esac
	command -v gpg >/dev/null 2>&1 || say "Note: gpg (GnuPG >= 2.2.17) was not found; cryptosis needs it."
}

say() { printf '%s\n' "$*" >&2; }
die() {
	say "install.sh: $*"
	exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"; }

detect_os() {
	case "$(uname -s)" in
	Linux) echo linux ;;
	Darwin) echo darwin ;;
	*) die "unsupported OS: $(uname -s) (linux and macOS only)" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*) die "unsupported architecture: $(uname -m) (amd64 and arm64 only)" ;;
	esac
}

# The /releases/latest page redirects to /releases/tag/<tag>.
latest_tag() {
	local url
	url="$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
		die "could not determine the latest release"
	[[ "$url" == */releases/tag/* ]] || die "no release found (got $url)"
	echo "${url##*/}"
}

verify_sha256() {
	local dir="$1" archive="$2" expected actual
	expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$dir/checksums.txt")"
	[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "$archive is not listed in checksums.txt"
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "$dir/$archive" | awk '{ print $1 }')"
	elif command -v shasum >/dev/null 2>&1; then
		actual="$(shasum -a 256 "$dir/$archive" | awk '{ print $1 }')"
	else
		die "sha256sum or shasum is required"
	fi
	[[ "$actual" == "$expected" ]] || die "checksum mismatch for $archive"
	say "sha256 OK"
}

verify_cosign() {
	local dir="$1" base="$2" tag="$3"
	if ! command -v cosign >/dev/null 2>&1; then
		[[ "${CRYPTOSIS_REQUIRE_COSIGN:-0}" == 1 ]] && die "cosign is required (CRYPTOSIS_REQUIRE_COSIGN=1) but not installed"
		say "cosign not found: skipping signature check (sha256 alone does not prove who built the release)"
		return
	fi
	fetch "$base/checksums.txt.sigstore.json" "$dir/checksums.txt.sigstore.json"
	cosign verify-blob \
		--bundle "$dir/checksums.txt.sigstore.json" \
		--certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$tag" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		"$dir/checksums.txt" >/dev/null 2>&1 || die "cosign signature verification FAILED for checksums.txt"
	say "cosign signature OK (signed by $REPO release workflow, $tag)"
}

main "$@"
