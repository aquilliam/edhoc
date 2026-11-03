#!/bin/sh
# Builds the libedhoc peer as interop/.build/libedhoc/peer.
set -eu

REPO=https://github.com/kamil-kielbasa/libedhoc.git
COMMIT=0363bd3af02265e919e888b60ccffb4606b68f16 # v2.3.3

here=$(cd "$(dirname "$0")" && pwd)
out="$here/../.build/libedhoc"
src="$out/src"

if [ ! -d "$src/.git" ]; then
	git clone -q "$REPO" "$src"
fi
git -C "$src" fetch -q origin
git -C "$src" checkout -q "$COMMIT"
git -C "$src" submodule update -q --init --depth 1 externals/zcbor externals/Unity externals/compact25519
git -C "$src" submodule update -q --init --recursive --depth 1 externals/mbedtls

# mbedTLS generates part of its source with Python scripts.
if [ ! -x "$out/venv/bin/python" ]; then
	python3 -m venv "$out/venv"
	"$out/venv/bin/pip" install -q -r "$src/externals/mbedtls/tf-psa-crypto/scripts/basic.requirements.txt"
fi

cmake -S "$here" -B "$out/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
	-DLIBEDHOC_SRC="$src" -DPython3_EXECUTABLE="$out/venv/bin/python" \
	-Wno-dev -Wno-deprecated >/dev/null
cmake --build "$out/build" --target peer >/dev/null
cp "$out/build/peer" "$out/peer"
echo "$out/peer"
