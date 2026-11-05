#!/bin/sh
# Bitbox MK2 simulator (Linux): Renode 1.16.1 + the sim/ scripts of bitbox-mk2-semi (MIT, portkit contributors).
# Nothing from semi is copied into this repo; it is cloned next to it at a pinned commit.
#
#   tools/sim_setup.sh [workdir]      (default: ../mk2-sim)
#   then, from the workdir:
#   python3 -I semi/sim/run.py --image <BITBOXMK2.BIN> --repl mk2.repl --sd semi/out/sim/mk2_sd.img \
#       wait 15 shot pads tap 32 210 wait 1 shot after
#   screenshots: semi/out/sim/<name>.png. About 20x slower than real time (15 s of boot = ~4 min).
#   Encoder is not modelled; keys: K0 = HOME, K1 = INFO; touch via tap/touch/release (screen coordinates).
set -e
SEMI_COMMIT=b7dfa9ab815342914ade82585756bd701b0c99d7
RENODE_URL=https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-portable-dotnet.tar.gz
W=${1:-$(dirname "$0")/../../mk2-sim}
mkdir -p "$W" && cd "$W"
command -v sfdisk >/dev/null && command -v mkfs.vfat >/dev/null && command -v mcopy >/dev/null || \
    sudo apt-get install -y fdisk dosfstools mtools
if [ ! -x renode/renode ]; then
    curl -sSL -o renode.tgz "$RENODE_URL" && mkdir -p renode && tar xzf renode.tgz -C renode --strip-components=1
fi
mkdir -p "$HOME/tools" && ln -sfn "$PWD/renode" "$HOME/tools/renode"     # semi's run.py looks there
[ -d semi ] || git clone https://github.com/semierendonmez-commits/bitbox-mk2-semi.git semi
git -C semi checkout -q "$SEMI_COMMIT"
[ -f semi/out/sim/mk2_sd.img ] || python3 -I semi/sim/mk2_card.py semi/out/sim/mk2_sd.img
echo "ready: $PWD"
