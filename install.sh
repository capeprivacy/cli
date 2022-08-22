#!/bin/sh

set -e

main() {
	if ! command -v tar >/dev/null; then
		echo "Error: tar is required to install Cape" 1>&2
		exit 1
	fi

	cape_install="${CAPE_INSTALL:-$HOME/.cape}"
	if [ "$OS" = "Windows_NT" ]; then
		target="Windows_x86_64"
	else
		case $(uname -sm) in
		"Darwin x86_64") target="Darwin_x86_64" ;;
		"Darwin arm64") target="Darwin_arm64" ;;
		"Linux aarch64")
			echo "Error: Official Cape builds for Linux aarch64 are not available" 1>&2
			exit 1
			;;
		"Linux x86_64")
			target="Linux_x86_64"
			cape_install="${CAPE_INSTALL:-$HOME/.local}"
			;;
		*)
			target="Linux_arm64"
			cape_install="${CAPE_INSTALL:-$HOME/.local}"
		esac
	fi

	if [ $# -eq 0 ]; then
		cape_uri="https://github.com/capeprivacy/cli/releases/latest/download/cape_${target}.tar.gz"
	else
		cape_uri="https://github.com/capeprivacy/cli/releases/download/${1}/cape_${target}.tar.gz"
	fi

	bin_dir="$cape_install/bin"
	exe="$bin_dir/cape"

	if [ ! -d "$bin_dir" ]; then
		mkdir -p "$bin_dir"
	fi

	echo "$cape_uri"
	curl --fail --location --progress-bar --output "$exe.tar.gz" "$cape_uri"
	tar -C "$bin_dir" -xzf "$exe.tar.gz"
	chmod +x "$exe"
	rm "$exe.tar.gz"

	echo "Cape was installed successfully to $exe"
	if command -v cape >/dev/null; then
		echo "Run 'cape --help' to get started"
	else
		case $SHELL in
		/bin/zsh) shell_profile=".zshrc" ;;
		*) shell_profile=".bashrc" ;;
		esac
		echo "Manually add the directory to your \$HOME/$shell_profile (or similar)"
		echo "  export CAPE_INSTALL=\"$cape_install\""
		echo "  export PATH=\"\$CAPE_INSTALL/bin:\$PATH\""
		echo "Run '$exe --help' to get started"
	fi

}
main "$@"
