#!/usr/bin/env python3
"""
Patch bitbox mk2 2.3.4: the per-pad MIDI controls of the bitbox micro patch.

This is a port, not a rewrite. The hook generators, the frozen machine code and
the encoders all come from patch_micro.py, which must sit in the same folder.
What this file owns is the MK2 side: where each piece of the micro patch lands
in BITBOXMK2.bin, and the checks that prove it.

How the addresses were found
----------------------------
The two images are one code base built on the same day for the same chip
(STM32H7, image base 0x08040000). Both were disassembled and aligned
instruction by instruction; every address below is the MK2 twin of the micro
address named beside it. The functions the hooks enter were then compared
whole, byte for byte, with branch targets and literal-pool addresses mapped
across:

  class A handler   FUN_080b10b8 -> 0x080b2110   identical (one routing
                                                  constant differs, 0xe -> 0xb,
                                                  in code the hooks never touch)
  class B handler   FUN_080b74ec -> 0x080b8614   identical
  class B setter    FUN_080b6ce8 -> 0x080b7e10   identical
  send taper        0x080a04c0   -> 0x080a1868   identical

Same frames, same registers, same value slot, same field offsets -- so the
micro hooks' code is used unchanged and only their branch targets move.

STAGE 1 covers what lives inside those functions:

  CC 79-83   granular        CC 87      sustain       CC 91-93  LFO
  CC 84/85   delay/reverb    CC 88/89   loop          CC 120/123 stop pad
  CC 86      reverse         CC 90      play through

STAGE 2 adds what hangs off the MIDI dispatcher, on MIDI channel 1 except
the delay switches:

  CC 40-46   compressor (46 = auto makeup)
  CC 50-57,59  master EQ and filter
  CC 108-111 delay beat sync, ping-pong, filter, filter width (any channel)

The objects these reach -- delay, compressor, EQ, the set-parameter call --
are byte-identical on the MK2. The dispatcher that feeds them is not: it was
compiled with a smaller stack frame, so the CC event sits at sp+0x40..0x50
instead of sp+0x78..0x88. Those hooks are therefore re-assembled from the
micro patcher's own sources with MK2 constants, and the result is frozen in
FROZEN_MK2 below so building needs no toolchain. `--reassemble` (needs clang)
rebuilds them and refuses if the frozen bytes have drifted.

STAGE 3 adds the rest of the 2.3.9-mod set: Settings rows (Clk Loss, Preset
BPM, OSD, Keep CCs on page 3; ProgChange's NEW ONLY), the Character chain
(CC 14-29, channel 1), the pop-up and CPU bar, and Keep CCs. Their hooks are
patch_micro.py's own functions, re-run with every micro address in their
source swapped through CODE_MAP / RAM_MAP (anything unmapped refuses), and the
Character C object relocated pair by pair (CHR_RELOC). All patch RAM moves up
by RAM_DELTA, as one block, to clear the MK2's larger stack.

From 2.3.10-mod (cc13): the Character runs from its 2.3.10 object (chr10,
relocated by CHR10_RELOC), with the compressor types (CC 47 / 48, hooks Da,
Dg, Q) and the master bus kept across power-off (cc13-15 hook S; from cc16
2.3.10's own hook T). The pop-up and the CPU bar are drawn by the MK2's own
landscape renderer (osd_sync replaced, hook K's bar rewritten).

cc15 adds the Clip modes (2.3.10's hook R, apply_clip_modes): Vinyl, Jungle,
Key Lock, Manual tempo, Live Flip and the hold buttons, per Clip pad. cc16
adds the themes (hook T, which also carries the saved master bus): a Theme
row on a fifth Tools tab, Custom from theme.tml, the pop-up and the CPU bar
in the theme's colours.

Not here: Flip UI (the MK2 flips its screen and touch natively) and CC 89.

tools/emu_check_mk2.py runs the hooks in an emulator; run it before flashing.

Usage: patch_mk2.py <BITBOXMK2.bin> <out.bin> [-v] [--font=FILE.otf[:SIZE]] [--reassemble]
"""
import hashlib, os, struct, subprocess, sys, tempfile

sys.dont_write_bytecode = True        # no __pycache__ next to the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import patch_micro as pm                # noqa: E402  the hook generators

BASE = 0x08040000
STOCK_SHA = "35ab7995ad0eca8484f3b28bc76389f10b2037dbb21a4a394e950d9329073e86"
STOCK_SIZE = 674896
VERSION = "2.3.4-cc24"                  # 10 characters: see pm.VER_DISPLAY_MAX

# CCs left out of this build. 2026-10-27, cc1 on hardware: CC 89 (Loop
# Crossfade) on a Sample pad gave sudden full-scale distorted output at any
# value above 0. The code it reaches is byte-identical to the micro's and to
# the stock Loop Fade encoder's path, so the cause is not yet known. It stays
# out until it is -- a CC that can do that is not shipped on a guess.
DISABLED_CCS = {89}

# --- every micro address this stage uses, and its MK2 twin -----------------
MK2 = {
    # hook sites (bne.w to the stock default) and where they return
    0x080b2316: 0x080b336e,   # class A hook
    0x080b1110: 0x080b2168,   # class A return
    0x080b7cd6: 0x080b8dfe,   # class B hook
    0x080b7554: 0x080b867c,   # class B return
    # the class A cases the arms branch into
    0x080b30a2: 0x080b40fa,   # granular density
    0x080b3108: 0x080b4160,   # grain size
    0x080b2ab8: 0x080b3b10,   # window
    0x080b30e6: 0x080b413e,   # scatter
    0x080b314a: 0x080b41a2,   # pan random
    0x080b2bee: 0x080b3c46,   # sustain
    0x080b2fd0: 0x080b4028,   # loop crossfade
    0x080b31a0: 0x080b41f8,   # loop mode
    0x080b2f2e: 0x080b3f86,   # LFO wave
    0x080b2938: 0x080b3990,   # LFO beat sync
    0x080b2ed6: 0x080b3f2e,   # LFO retrigger
    # stop, class B's setter, the send taper
    0x080b209c: 0x080b30f4,   # stop, class A
    0x080b77ee: 0x080b8916,   # stop, class B
    0x080b6ce8: 0x080b7e10,   # class B set-parameter
    0x080a04c0: 0x080a1868,   # dB -> linear taper
}

# --- splash ------------------------------------------------------------------
# The MK2 packs its product strings tighter than the micro, but the two slots
# we write are still 16 bytes each:
#   0x080c68e0  "bitbox mk2"     line 1, 12-byte slot -- left alone
#   0x080c68ec  "by 1010music"   line 2, up to 0x080c68fc
#   0x080c68fc  "2.3.4"          line 3, up to the pointer table at 0x080c690c
ATTRIB_VA, ATTRIB_STOCK, ATTRIB_NEW = 0x080c68ec, "by 1010music", "community fw"
VER_VA, VER_STOCK = 0x080c68fc, "2.3.4"
PRODUCT_VA, PRODUCT = 0x080c68e0, "bitbox mk2"
PTR_TABLE_VA = 0x080c690c

# --- STAGE 2: the MIDI dispatcher and what it reaches ------------------------
# Values the micro generators read as module globals, as they are on the MK2.
# Each is proved by a guard in STAGE2_GUARDS or by the checks in stage2().
STAGE2 = {
    # The dispatcher's CC event, built at 0x080953fc..0x0809542a (micro
    # 0x08093ee6..0x08093f14): type byte, then channel, CC number and value.
    "MSG_TYPE_SP": 0x40,      # micro 0x78
    "MSG_CHAN_SP": 0x48,      # micro 0x80
    "MSG_CC_SP":   0x4c,      # micro 0x84
    "MSG_VAL_SP":  0x50,      # micro 0x88
    # The engine. 164 literal-pool pairs agree on it (micro 0x24022978).
    "MANAGER": 0x24023cb8,
    "SCAN_LO": 0x24023cb8 + 0xa000,   # derived from MANAGER at import in pm,
    "SCAN_HI": 0x24023cb8 + 0xa400,   # so they must be restated here
    "SETPARAM_FN":  0x08094de4,       # micro 0x080937f4, identical
    "MIDI_POST_FN": 0x0809656c,       # micro 0x080950c0, identical thunk
    "MIDI_POST_CALL": 0x0809542a,     # micro 0x08093f14
    # The session's compressor on/off byte moved down 0x68 with the rest of
    # the session's tail (proved by the literal at 0x08098400). The compressor
    # object itself is still at session+0xfb38 (0x080983a0), so the limiter
    # proof offsets 0xffa0/0xffa4 (compressor +0x468/+0x46c) are unchanged.
    "COMP_ONOFF_OFF": 0x28c58,        # micro 0x28cc0
    "COMP_DSP_FN":   0x080ba43c,      # micro 0x080b9b04, identical
    "COMP_DSP_CALL": 0x080983a8,      # micro 0x08097056
    # (Auto makeup's flag, and every other patch-RAM address, moves with the
    # whole patch-RAM block: see RAM_DELTA below.)
    # The EQ class: identical code, 0x19c further up (0x198 from the handler).
    "EQ_HANDLER": 0x080bb3b8,
    "EQ_VTABLE": 0x080df27c,
    "EQ_VT_HANDLER": 0x080df288,
    "EQ_DESIGNERS": [0, 0x080ba930, 0x080baa74, 0x080bad34, 0x080bb0f8, 0x080bafb4],
}

# (MK2 address, stock bytes, what they prove). Checked before anything is
# written; each is the MK2 twin of a guard the micro patcher already makes,
# plus the dispatcher frame this stage depends on.
STAGE2_GUARDS = (
    (0x080953fc, "07232046cdf844908df84030aff72ef90346012120461293"
                 "aff739f9034620461393aff78ef9034631463868149301f09ff8",
     "the CC event: type 7 at sp+0x40, then sp+0x48/0x4c/0x50, then the post"),
    (0x08095506, "8df84030cdf84490", "a note-on uses the same frame, type 5"),
    (0x0809656c, "0346", "the post thunk's first act is mov r3, r0"),
    (0x080953aa, "4af20427", "the dispatcher's engine pointer is this+0xa204"),
    (0x080a8e88, "ab2b00f0", "the delay handles filter/width at 0xab/0xac"),
    (0x080983a0, "4ff6383051464044", "the compressor is session+0xfb38"),
    (0x08098400, "588c0200", "the on/off byte is session+0x28c58"),
    (0x080ba6c0, "04f58560", "the compressor's threshold is +0x428"),
    (0x080ba6f8, "000080c0", "the compressor's stock default, -4.0"),
    (0x080ba6dc, "48f6a043", "the limiter's release, 36000, at +0x46c"),
    (0x08095666, "4af20428", "the session pointer lives at engine+0xa204"),
    (0x080ba776, "05600546", "the EQ ctor stores its vtable"),
    (0x080df27c, "19a90b08", "the EQ vtable's first slot"),
    (0x080bafb4, "01eb8103", "the EQ H Cut designer's entry"),
    (0x080bb094, "c1ed126a", "the EQ b0 coefficient slot"),
    (0x080bb0dc, "db0fc940", "2*pi: the EQ's frequency is in Hz"),
    (0x080baf68, "cdcc4c3d", "0.05: the EQ's gain is in dB"),
    (0x080bb3d2, "c18b2846", "the EQ handler's audio fetch"),
    (0x080bdce4, "48f40224", "malloc's heap start, 0x2402f448"),
    (0x080bdce0, "98a50624", "malloc's heap end, 0x2406a598"),
    (0x08040000, "98ad0624", "the initial stack pointer, 0x2406ad98"),
)
STACK_TOP = 0x2406ad98
HEAP_HI = 0x2406a598
# The uncached pool, replayed as the micro patcher does: twelve constant-size
# requests (bl 0x08046cb8), top-down from 0x24080000 in 32-byte steps.
POOL_ALLOC = 0x08046cb8
POOL_CALLS = {0x08042214: 0x20, 0x080427b6: 0x800, 0x080427cc: 0x1000,
              0x080427e2: 0x1000, 0x08043cb8: 0x23c, 0x0808b258: 0x58,
              0x0808b262: 0x58, 0x0808e408: 0x58, 0x0809892c: 0xc400,
              0x080989e0: 0x58, 0x080a3a7c: 0x200, 0x080ab9f8: 0x58}
POOL_FLOOR = 0x24080000 - sum((n + 0x1f) & ~0x1f for n in POOL_CALLS.values())

# The type gate. The note and CC paths share the post call, so without it a
# note on channel 1 reads as a CC to the compressor and EQ. The micro has this
# gate inside Keep CCs (hook P); until Keep CCs is ported it is a hook of its
# own. r3 is dead at the call: the thunk's first act is mov r3, r0.
GATE_SRC = """
    .syntax unified
    .thumb
    .section .text
    .global _sT
    .thumb_func
_sT:
    ldrb    r3, [sp, #{type:#x}]       /* 7 = a CC */
    cmp     r3, #7
    bne     1f                         /* a LOCAL label, never tstock: see below */
    .global tcc
tcc:
    .short  0, 0                       /* b.w hook F: the CC chain */
1:
    .global tstock
tstock:
    .short  0, 0                       /* b.w the stock post, as before */
"""
# 2.3.4-cc3 shipped this with `bne tstock`. A branch to a .global symbol is
# left by the assembler as a relocation, and nothing here applies relocations,
# so it became `bne.w` to itself: every non-CC message (notes, clock) spun the
# MIDI thread forever and the watchdog rebooted the module. clang_asm() now
# refuses any object that carries a relocation.

# --- patch RAM: one block, moved as a whole ------------------------------------
# The micro keeps all of its RAM between its main stack (top 0x240692a8) and
# its uncached pool (floor 0x2406f4e0): 0x24069400 up. The MK2's stack ends
# higher, at 0x2406ad98, so 0x24069400-0x2406ad98 is stack here: Keep CCs, the
# OSD's UI-side area and (2.3.10) the Jungle and compressor areas would sit in
# it. Every patch-RAM address therefore moves up by RAM_DELTA, together, so
# their layout -- and every offset the hooks and the C object compute between
# them -- is unchanged. 0x24069400 + 0x1a00 = 0x2406ae00 clears the stack; the
# micro's highest byte (2.3.10, 0x2406f080) lands at 0x24070a80, under the MK2
# pool floor 0x24070dc0. check_ram() proves both for every range in use.
RAM_DELTA = 0x1a00
MICRO_RAM_WIN = (0x24069400, 0x2406f4e0)      # micro: just above its stack .. its pool


def ram_shift(v):
    lo, hi = MICRO_RAM_WIN
    return v + RAM_DELTA if lo <= v < hi else v


# --- STAGE 3: Settings rows, Clk Loss, Preset BPM, Program Change, CPU bar,
# --- Character, the OSD and Keep CCs (the 2.3.9-mod set) ---------------------
# Stock RAM objects, micro -> MK2, each proved by literal-pool pairs (the count)
# or as an offset from one that is.
RAM_MAP = {
    0x24022978: 0x24023cb8,   # MANAGER, the engine (164 pairs)
    0x2402c978: 0x2402dcb8,   # SCAN_LO = MANAGER + 0xa000
    0x2402cd78: 0x2402e0b8,   # SCAN_HI = MANAGER + 0xa400
    0x24013cb0: 0x24015170,   # SESSION_MGR (118 pairs)
    0x24015f28: 0x240173e8,   # SONG_STORE = SESSION_MGR + 0x2278 (offset unchanged, 24 pairs)
    0x2401bc80: 0x2401d040,   # GLOBAL_STORE = SESSION_MGR + 0x7fd0 -> +0x7ed0 (22 pairs)
    0x2401bcb4: 0x2401d074,   # SESSION_DIRTY = SESSION_MGR + 0x8004 -> +0x7f04 (45 pairs)
    0x24022578: 0x240238b8,   # PC_MANAGER (64 pairs)
    0x240228a4: 0x24023be4,   # PC_LIST = PC_MANAGER + 0x32c (17 pairs)
    0x24022908: 0x24023c48,   # PC_PENDING = PC_MANAGER + 0x390
    0x2402290c: 0x24023c4c,   # PC_CURRENT = PC_MANAGER + 0x394 (offset unchanged, 23)
    0x24002e7c: 0x24004280,   # DISPLAY_OBJ (32 pairs)
    0x24002f24: 0x24004328,   # DISPLAY_OBJ + 0xa8, its DMA2D (literal 0x08042868 / 0x080435f4)
    0x24009c80: 0x2400b084,   # the SD card object (literal 0x0808c920 / 0x0808c5a4)
    0x24022970: 0x24023cb0,   # the tml read's FIL = MANAGER - 8 (literal 0x0808ee94 / 0x0808e598)
}
# Stock RAM the chr10 object names that is the same on the MK2: the palette
# (0x24000000, literal 0x080426a4 / 0x08043430), the SDRAM allocator's pointer
# (0x24000088, literal 0x08042df0 / 0x08043b7c), the UI object (0x24000dc8,
# literal 0x08040e80 / 0x08040e84).
RAM_SAME = {0x24000000, 0x24000004, 0x24000088, 0x24000dc8}
RAM_ALLOWED = {0x24000000, 0x2407c000, 0x24080000}   # bounds checks, not objects

# Every micro flash address stage 3 reads, guards, calls or branches to. "eq":
# the aligned instructions match; "~": same instruction, MK2 frame offsets;
# "lit": the literal-pool word paired with it; "manual": data, found by hand
# (the font, the OFF/ON strings, the LFO labels, the EQ vtable, the font
# descriptor's initialiser, the Character site's context).
CODE_MAP = {
    0x08042488: 0x08042384,   # lit
    0x08042900: 0x0804368c,   # eq
    0x080439de: 0x0804476a,   # eq
    0x080442c4: 0x08044fe0,   # eq
    0x08044328: 0x08045044,   # eq
    0x08044eb8: 0x08045bd4,   # eq
    0x0804565c: 0x08046378,   # eq
    0x0805bbb4: 0x0805b950,   # eq
    0x08069e4e: 0x0806a24e,   # eq
    0x08069e7c: 0x0806a27c,   # eq
    0x08069ed4: 0x0806a2d4,   # eq
    0x0806a8c2: 0x0806acba,   # eq
    0x0806abbc: 0x0806afb2,   # eq
    0x0806b054: 0x0806b448,   # eq
    0x0806d6e0: 0x0806dae4,   # lit
    0x0806dc14: 0x0806e018,   # lit
    0x0807aa9c: 0x0807ca10,   # eq
    0x0807af2c: 0x0807cde8,   # eq
    0x0807c258: 0x0807e114,   # eq
    0x0807c26e: 0x0807e12a,   # eq
    0x0807c298: 0x0807e154,   # eq
    0x0807c4e0: 0x0807e2f4,   # eq
    0x0807c538: 0x0807e3d0,   # lit
    0x0807c5be: 0x0807e456,   # eq
    0x0807c7e8: 0x0807e680,   # eq
    0x0807d51c: 0x0807f91e,   # eq
    0x0807f768: 0x08082088,   # eq
    0x0807f874: 0x08082194,   # eq
    0x0807f892: 0x080821b2,   # eq
    0x0807f98c: 0x080822ac,   # eq
    0x0807f994: 0x080822b4,   # eq
    0x0807fa74: 0x08082394,   # lit
    0x080894d0: 0x08089388,   # eq
    0x080894d4: 0x0808938c,   # eq
    0x080894fa: 0x080893b2,   # eq
    0x080894fe: 0x080893b6,   # eq
    0x0808951e: 0x080893d6,   # eq
    0x08089e08: 0x08089cc0,   # eq
    0x08089ef4: 0x08089dac,   # eq
    0x08089efe: 0x08089db6,   # eq
    0x0808aa0c: 0x0808a8c4,   # eq
    0x0808b4e8: 0x0808b2c4,   # eq
    0x0808bd52: 0x0808ba46,   # eq
    0x0808c460: 0x0808c0e4,   # eq
    0x080937f4: 0x08094de4,   # eq
    0x080939cc: 0x08094fbc,   # eq
    0x080939d0: 0x08094fc0,   # eq
    0x08093d30: 0x080952c4,   # eq
    0x08093e72: 0x08095388,   # eq
    0x08093e82: 0x08095398,   # eq
    0x08093e94: 0x080953aa,   # eq
    0x08093ee6: 0x080953fc,   # eq
    0x08093eea: 0x08095400,   # ~
    0x08093eee: 0x08095404,   # ~
    0x08093f10: 0x08095426,   # eq
    0x08093f14: 0x0809542a,   # eq
    0x08093fea: 0x08095506,   # ~
    0x080950c0: 0x0809656c,   # eq
    0x0809654e: 0x080979e8,   # eq
    0x08096cf8: 0x08098170,   # manual
    0x08096d04: 0x0809817a,   # eq
    0x08096d26: 0x0809819c,   # eq
    0x0809702c: 0x080983fc,   # lit
    0x08097056: 0x08098388,   # eq
    0x0809705a: 0x0809838c,   # eq
    0x08097b8c: 0x08098f18,   # eq
    0x08097bdc: 0x08098f68,   # eq
    0x080a04c0: 0x080a1868,   # eq
    0x080a3328: 0x080a46d0,   # eq
    0x080a396c: 0x080a4d14,   # eq
    0x080a6258: 0x080a7438,   # eq
    0x080a625c: 0x080a743c,   # eq
    0x080a6372: 0x080a7552,   # eq
    0x080a6376: 0x080a7556,   # eq
    0x080a6522: 0x080a7702,   # eq
    0x080a6526: 0x080a7706,   # eq
    0x080a65e6: 0x080a77c6,   # eq
    0x080a65ea: 0x080a77ca,   # eq
    0x080a6674: 0x080a7854,   # eq
    0x080a6678: 0x080a7858,   # eq
    0x080a6712: 0x080a78f2,   # eq
    0x080a6716: 0x080a78f6,   # eq
    0x080a67a0: 0x080a7980,   # eq
    0x080a67a4: 0x080a7984,   # eq
    0x080a67d6: 0x080a79b6,   # eq
    0x080a67da: 0x080a79ba,   # eq
    0x080a67e6: 0x080a79c6,   # eq
    0x080a7ca8: 0x080a8e88,   # eq
    0x080a83a4: 0x080a9584,   # eq
    0x080a83e2: 0x080a95c2,   # eq
    0x080ac35e: 0x080ad53e,   # eq
    0x080ac766: 0x080ad946,   # eq
    0x080b2316: 0x080b336e,   # eq
    0x080b27c2: 0x080b381a,   # eq
    0x080b42ac: 0x080b53d4,   # eq
    0x080b55ac: 0x080b66d4,   # eq
    0x080b57f6: 0x080b691e,   # eq
    0x080b58fc: 0x080b6a24,   # eq
    0x080b742a: 0x080b8552,   # eq
    0x080b7cd6: 0x080b8dfe,   # eq
    0x080b9b04: 0x080ba43c,   # eq
    0x080ba794: 0x080ba930,   # eq
    0x080ba8d8: 0x080baa74,   # eq
    0x080bab98: 0x080bad34,   # eq
    0x080bae18: 0x080bafb4,   # eq
    0x080baf5c: 0x080bb0f8,   # eq
    0x080bb220: 0x080bb3b8,   # eq
    0x080bf664: 0x080c0784,   # manual
    0x080c0030: 0x080c1104,   # manual
    0x080c0034: 0x080c1108,   # manual
    0x080c478c: 0x080c58dc,   # manual
    0x080e259c: 0x080df27c,   # manual
    0x080e25a8: 0x080df288,   # manual
    0x080e3e64: 0x080e4c24,   # manual
}
# 2.3.10 (cc13): what the compressor types, the saved master bus and the
# chr10 object's externs read, call or guard. Function entries checked by
# their first 16 bytes, call sites by their targets, data by its bytes.
CODE_MAP.update({
    0x08042dc0: 0x08043b4c,   # eq: the SDRAM bump allocator (clip_x_alloc)
    0x08042e58: 0x08043be4,   # eq: malloc
    0x08042ebc: 0x08043c48,   # eq: free
    0x0804440c: 0x08045128,   # eq: the SD card check
    0x0804a500: 0x0804a614,   # eq: HAL EnableCLUT
    0x0804a536: 0x0804a64a,   # eq: its wait
    0x0804a8b0: 0x0804a9c4,   # call target: HAL ConfigCLUT (boot's call, 0x080433d8)
    0x08056edc: 0x08056c78,   # eq: f_open
    0x080576a6: 0x08057442,   # eq: f_close
    0x0807d3c0: 0x0807f824,   # eq: handler B's SetParam call
    0x0807d3ec: 0x0807f850,   # eq: handler B's settings.tml write
    0x0808c154: 0x0808bdd8,   # eq: the settings.tml write
    0x0808ed14: 0x0808e418,   # call target: the tml write (whole block at -0x8fc)
    0x0808edc4: 0x0808e4c8,   # call target: the tml read
    0x0809a008: 0x0809b394,   # eq: the streamer's read
    0x0809d06c: 0x0809e3fc,   # eq: ~XMLDocument
    0x0809d608: 0x0809e998,   # eq: FirstChildElement
    0x0809dca8: 0x0809f038,   # eq: Attribute
    0x0809e50c: 0x0809f89c,   # eq: XMLDocument()
    0x080a2064: 0x080a340c,   # lit: the compressor override slot's default (MK2 literal 0x080ba5d0)
    0x080a31e0: 0x080a4588,   # eq: the bus frame count
    0x080a3288: 0x080a4630,   # eq: the bus fetch
    0x080a45ac: 0x080a5954,   # eq: a sample's frame count
    0x080a82b8: 0x080a9498,   # eq: the bus descriptor
    0x080b40fc: 0x080b5224,   # eq: the clip timing
    0x080b490c: 0x080b5a34,   # eq: the segment start
    0x080b7554: 0x080b867c,   # eq: hook B's no-match exit (CLIP_CC_RET)
    0x080b9b24: 0x080ba45c,   # eq: the compressor DSP's descriptor call
    0x080b9b2a: 0x080ba462,   # eq: ... frame count
    0x080b9b3e: 0x080ba476,   # eq: ... fetch
    0x080c5e64: 0x080c7134,   # manual: "settings.tml"
    0x080e3d98: 0x080e4b58,   # manual: the palette's flash image (Stock)
    0x0809f45c: 0x080a07ec,   # eq: exp2, the pitch factor's (cc15)
    0x08070866: 0x08071602,   # eq: the renderer's dirty test (themes, cc16)
    0x080708a0: 0x0807163c,   # eq: its draw of the widget tree
    0x0808d000: 0x0808cc84,   # eq: the file thread's settings save job
    0x0808d018: 0x0808cc9c,   # eq: its settings load job
    0x0808e6d2: 0x0808e33a,   # eq: the file thread's call of the save job
    0x0808e6e4: 0x0808e34c,   # eq: ... of the load job
})
# The micro's third SESSION_MGR literal (0x080921e8) has no aligned twin; the
# other two do, and 78 literals in the MK2 hold the MK2's value.
SESSION_MGR_GUARDS_MK2 = (0x0806dae4, 0x0806e018)
# Guards whose bytes legitimately differ on the MK2, each read and checked by
# hand: the dispatcher frame (0x40.. not 0x78..), the engine in r5 not r4,
# branch and literal offsets that moved. micro address -> MK2 bytes.
GUARD_BYTES_MK2 = {
    0x08093e82: "4af6106315f80390",   # movw r3,#0xae10; ldrb sb,[r5,r3]: the ready byte
    0x08093f10: "38681493",           # ldr r0,[r7]; str r3,[sp,#0x50]
    0x08093ee6: "07232046cdf844908df84030",   # type 7 at sp+0x40, +4 = 0
    0x080950c0: "034603484ff48062184413f005b8",   # the thunk, key 0x400
    0x080a83e2: "04221044fbf7a5bb",   # key 0x400 is queue +4
    0x0807c26e: "a94817f0caf8",       # LoadBank asks it, with the literal
    0x08093d30: "03f050be",           # through this tail call
    0x0807f892: "08a9284612f001ff",   # the UI dispatcher reads it with r5
    0x080939cc: "03f0acbf",           # through this tail call
    0x08093eea: "cdf844908df84030",   # type 7 for a CC at +0x40 ...
    0x08093fea: "8df84030cdf84490",   # ... type 5 for a note-on, same tail
    0x08042488: "b83c0224",           # the audio task's engine literal: MANAGER
}
# The Character's site: `movs r1,#0xb; mov r0,sl; bl; mov r1,r0; mov r0,r4`
# (micro: #0xe and vmov r0,s17 -- the reverb return's buffer index and where
# the engine is kept differ; nblock only reads r0 at the call).
CHR_SITE_CONTEXT_MK2 = (0x08098170, "504611f091f901462046")

# The Character C object builds these addresses with movw/movt pairs:
# (section, movw offset, movt offset, micro value). Each is checked before it
# is rewritten; nothing else in the object addresses flash or stock RAM.
# Found by a disassembly that resynchronises past undecodable words AND a
# brute-force halfword scan, which agree on all 27. cc5's first build had 24:
# a plain linear sweep stopped a third of the way into chr_osd_tick, and the
# OSD wrote to two unmoved micro addresses -- inside the MK2's stack. Caught
# in emulation (UC_HOOK_MEM_WRITE), never flashed.
CHR_RELOC = (
    (".text.chr_osd_tick", 0x000c, 0x0014, 0x240694a8),
    (".text.chr_osd_tick", 0x0184, 0x018c, 0x2406c358),
    (".text.chr_osd_tick", 0x01c0, 0x01c8, 0x2406c308),
    (".text.chr_osd_tick", 0x05b2, 0x05c0, 0x2406c358),
    (".text.chr_osd_tick", 0x063a, 0x0644, 0x240694a8),
    (".text.chr_osd_tick", 0x0664, 0x0668, 0x080bf564),   # font - 0x100
    (".text.chr_osd_tick", 0x0a0c, 0x0a10, 0x240694a8),
    (".text.chr_osd_tick", 0x0b46, 0x0b4c, 0x080c478c),   # LFO labels
    (".text.chr_osd_tick", 0x0b90, 0x0b98, 0x2406c358),
    (".text.chr_osd_tick", 0x0b94, 0x0b9c, 0x240694a8),
    (".text.chr_osd_tick", 0x1012, 0x101a, 0x2406a620),
    (".text.chr_osd_tick", 0x11fa, 0x1200, 0x2406c358),
    (".text.chr_osd_tick", 0x1dea, 0x1df2, 0x2406c358),
    (".text.chr_osd_tick", 0x1e00, 0x1e04, 0x240694a8),
    (".text.osd_sync", 0x000a, 0x001a, 0x24069860),
    (".text.chr_cc", 0x001a, 0x002e, 0x2406c308),
    (".text.chr_cc", 0x00ba, 0x00be, 0x2406c20c),
    (".text.chr_cc", 0x0122, 0x012a, 0x2406c204),
    (".text.chr_cc", 0x0172, 0x017c, 0x2406c20c),
    (".text.chr_cc", 0x0178, 0x0182, 0x2406c204),
    (".text.chr_cc", 0x0340, 0x0344, 0x2406c20c),
    (".text.store_ok", 0x0006, 0x000e, 0x2406c200),
    (".text.store_seed", 0x0000, 0x0006, 0x2406c204),
    (".text.chr_block", 0x0044, 0x004c, 0x2406c204),
    (".text.chr_block", 0x04d4, 0x04da, 0x2406c204),
    (".text.chr_block", 0x07d8, 0x07e0, 0x2406c204),
    (".text.slot_reset", 0x0002, 0x0008, 0x2406c254),
)
CHR_FLASH = {0x080bf564: 0x080c0684, 0x080c478c: 0x080c58dc}

# The 2.3.10 object (chr10: the Character, the compressor types, the Clip
# modes, the themes and the saved master bus in one) builds 194 addresses
# with movw/movt pairs: (section, movw offset, movt offset, micro value).
# Generated as CHR_RELOC was (resync disassembly, cross-checked by the
# halfword scan; they differ on three, all looked at: two build 0x24000088
# with movs+movt, the same on the MK2, and one movw sits after a literal pool
# the disassembly misreads -- clip_read+0x1aa6, added by hand). Each value
# moves by ram_shift, RAM_MAP or CODE_MAP, or is in RAM_SAME; anything else
# refuses. No literal-pool word in the object holds an address.
CHR10_RELOC = (
    ('.text.chr_block', 0x004a, 0x0052, 0x2406c2a8),
    ('.text.chr_block', 0x0284, 0x0292, 0x2406c2a8),
    ('.text.chr_block', 0x04ea, 0x0500, 0x2406c2a8),
    ('.text.chr_cc', 0x001c, 0x0030, 0x2406c308),
    ('.text.chr_cc', 0x00bc, 0x00c0, 0x2406c304),
    ('.text.chr_cc', 0x00f4, 0x00fa, 0x2406a708),
    ('.text.chr_cc', 0x017e, 0x0186, 0x2406c204),
    ('.text.chr_cc', 0x01be, 0x01c6, 0x2406c204),
    ('.text.chr_cc', 0x01c2, 0x01d0, 0x2406c304),
    ('.text.chr_cc', 0x03d8, 0x03dc, 0x2406c304),
    ('.text.chr_cc', 0x05c8, 0x05cc, 0x2406c304),
    ('.text.chr_osd_tick', 0x0010, 0x0018, 0x2406a64c),
    ('.text.chr_osd_tick', 0x0022, 0x002e, 0x2406a748),
    ('.text.chr_osd_tick', 0x005e, 0x0062, 0x2401bc80),
    ('.text.chr_osd_tick', 0x00fc, 0x0108, 0x080c5e64),
    ('.text.chr_osd_tick', 0x0104, 0x010c, 0x24022578),
    ('.text.chr_osd_tick', 0x0116, 0x011e, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x0296, 0x02a6, 0x080e3d98),
    ('.text.chr_osd_tick', 0x0332, 0x033a, 0x2406a64c),
    ('.text.chr_osd_tick', 0x034c, 0x0354, 0x2406a64c),
    ('.text.chr_osd_tick', 0x037e, 0x0386, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x03aa, 0x03cc, 0x2406a64c),
    ('.text.chr_osd_tick', 0x041e, 0x0426, 0x24002f24),
    ('.text.chr_osd_tick', 0x0538, 0x053c, 0x24000dc8),
    ('.text.chr_osd_tick', 0x055c, 0x0564, 0x24069420),
    ('.text.chr_osd_tick', 0x06b8, 0x06c0, 0x2406c358),
    ('.text.chr_osd_tick', 0x06f4, 0x06fc, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x07b8, 0x07bc, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x07d2, 0x07d6, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x0834, 0x083c, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x0862, 0x0866, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x0c4a, 0x0c58, 0x2406c358),
    ('.text.chr_osd_tick', 0x0cd2, 0x0cdc, 0x24069420),
    ('.text.chr_osd_tick', 0x0cfe, 0x0d02, 0x080bf564),
    ('.text.chr_osd_tick', 0x10e6, 0x10f6, 0x2406c358),
    ('.text.chr_osd_tick', 0x1138, 0x113e, 0x080c478c),
    ('.text.chr_osd_tick', 0x1182, 0x1186, 0x2406c358),
    ('.text.chr_osd_tick', 0x1192, 0x119e, 0x24069420),
    ('.text.chr_osd_tick', 0x13d4, 0x13dc, 0x2406bd28),
    ('.text.chr_osd_tick', 0x14ae, 0x14b2, 0x2406a748),
    ('.text.chr_osd_tick', 0x1a22, 0x1a30, 0x2406c358),
    ('.text.chr_osd_tick', 0x1ed2, 0x1eda, 0x2406a64c),
    ('.text.chr_osd_tick', 0x1eec, 0x1ef4, 0x2406a64c),
    ('.text.chr_osd_tick', 0x2010, 0x2018, 0x2406bd28),
    ('.text.chr_osd_tick', 0x2014, 0x201c, 0x2406c0d0),
    ('.text.chr_osd_tick', 0x223a, 0x223e, 0x2406c358),
    ('.text.chr_osd_tick', 0x2258, 0x225c, 0x24069420),
    ('.text.chr_osd_tick', 0x2364, 0x236c, 0x24069420),
    ('.text.chr_osd_tick', 0x2828, 0x2830, 0x2406c358),
    ('.text.chr_osd_tick', 0x2de6, 0x2dee, 0x2406c358),
    ('.text.chr_osd_tick', 0x2e9c, 0x2ea4, 0x2406c358),
    ('.text.chr_osd_tick', 0x2ecc, 0x2ed4, 0x2406c358),
    ('.text.chr_post', 0x0014, 0x0018, 0x2406c200),
    ('.text.chr_post', 0x005a, 0x0060, 0x2406c210),
    ('.text.chr_post', 0x0124, 0x0128, 0x2406a710),
    ('.text.chs_rows', 0x0006, 0x000e, 0x2406c200),
    ('.text.chs_rows', 0x00c0, 0x00c8, 0x2406a700),
    ('.text.clip_beats', 0x000e, 0x0014, 0x2406bb08),
    ('.text.clip_cc', 0x005c, 0x0064, 0x2406bb18),
    ('.text.clip_cc', 0x0114, 0x0128, 0x2406c311),
    ('.text.clip_cc', 0x011c, 0x012c, 0x2406c308),
    ('.text.clip_cc', 0x016c, 0x0174, 0x2406bb18),
    ('.text.clip_cc', 0x01fa, 0x0202, 0x2406c308),
    ('.text.clip_cc', 0x021c, 0x0220, 0x2406c311),
    ('.text.clip_cc', 0x0274, 0x0284, 0x2406c311),
    ('.text.clip_cc', 0x0278, 0x0288, 0x2406c308),
    ('.text.clip_cc', 0x0326, 0x032a, 0x2406c311),
    ('.text.clip_cc', 0x05aa, 0x05b2, 0x2406a200),
    ('.text.clip_cc', 0x06b6, 0x06bc, 0x2406c311),
    ('.text.clip_cc', 0x07ce, 0x07d2, 0x2406a200),
    ('.text.clip_cc', 0x07e0, 0x07e4, 0x2406ef10),
    ('.text.clip_jgl', 0x0006, 0x000a, 0x2406a200),
    ('.text.clip_jgl_cycle', 0x0008, 0x0010, 0x2406bd08),
    ('.text.clip_jgl_head', 0x0040, 0x0048, 0x2406a640),
    ('.text.clip_loaded', 0x0004, 0x000c, 0x2406bb08),
    ('.text.clip_loaded', 0x0014, 0x001c, 0x2406be3c),
    ('.text.clip_loaded', 0x0052, 0x0060, 0x24015f28),
    ('.text.clip_loaded', 0x0056, 0x0066, 0x2406bffc),
    ('.text.clip_loaded', 0x02aa, 0x02b0, 0x2406a400),
    ('.text.clip_man_set', 0x0000, 0x0008, 0x2406a6b0),
    ('.text.clip_mode_bpm', 0x0004, 0x000c, 0x2406a6b0),
    ('.text.clip_rate', 0x000c, 0x0014, 0x2406bb00),
    ('.text.clip_rate', 0x00fa, 0x00fe, 0x2406a200),
    ('.text.clip_rate', 0x0124, 0x0128, 0x2406ef00),
    ('.text.clip_rate', 0x0184, 0x018c, 0x2406a200),
    ('.text.clip_rate', 0x0530, 0x0534, 0x2406bffc),
    ('.text.clip_read', 0x001e, 0x0026, 0x2406bf38),
    ('.text.clip_read', 0x007a, 0x007e, 0x2406bf38),
    ('.text.clip_read', 0x0110, 0x0114, 0x2406a200),
    ('.text.clip_read', 0x012e, 0x0132, 0x2406ef00),
    ('.text.clip_read', 0x0158, 0x015e, 0x2406bf38),
    ('.text.clip_read', 0x0202, 0x0206, 0x2406bf52),
    ('.text.clip_read', 0x03f6, 0x03fa, 0x2406bf52),
    ('.text.clip_read', 0x0402, 0x0406, 0x2406bf38),
    ('.text.clip_read', 0x040e, 0x0412, 0x2406bf52),
    ('.text.clip_read', 0x0490, 0x0498, 0x2406bf38),
    ('.text.clip_read', 0x04fc, 0x0504, 0x2406bf38),
    ('.text.clip_read', 0x0586, 0x058c, 0x2406bf38),
    ('.text.clip_read', 0x05ba, 0x05be, 0x2406bf52),
    ('.text.clip_read', 0x05d2, 0x05d8, 0x2406bf38),
    ('.text.clip_read', 0x05ea, 0x05f0, 0x2406bf38),
    ('.text.clip_read', 0x060e, 0x0612, 0x2406bf38),
    ('.text.clip_read', 0x0626, 0x062c, 0x2406bf52),
    ('.text.clip_read', 0x0638, 0x063c, 0x2406bf52),
    ('.text.clip_read', 0x064e, 0x0654, 0x2406bf38),
    ('.text.clip_read', 0x0668, 0x066e, 0x2406bf52),
    ('.text.clip_read', 0x067c, 0x0680, 0x2406bf52),
    ('.text.clip_read', 0x069a, 0x06a0, 0x2406bf38),
    ('.text.clip_read', 0x0830, 0x0836, 0x2406bf38),
    ('.text.clip_read', 0x14ca, 0x14ce, 0x2406bf52),
    ('.text.clip_read', 0x17ce, 0x17d4, 0x2406bf52),
    ('.text.clip_read', 0x1892, 0x1898, 0x2406bf52),
    ('.text.clip_read', 0x18a0, 0x18a4, 0x2406bf38),
    ('.text.clip_read', 0x18ac, 0x18b2, 0x2406bf52),
    ('.text.clip_read', 0x18c2, 0x18c8, 0x2406bf52),
    ('.text.clip_read', 0x18da, 0x18e0, 0x2406bf52),
    ('.text.clip_read', 0x18f2, 0x18f8, 0x2406bf52),
    ('.text.clip_read', 0x190a, 0x1910, 0x2406bf52),
    ('.text.clip_read', 0x1922, 0x1928, 0x2406bf52),
    ('.text.clip_read', 0x193a, 0x193e, 0x2406bf52),
    ('.text.clip_read', 0x194a, 0x194e, 0x2406bf52),
    ('.text.clip_read', 0x195a, 0x195e, 0x2406bf52),
    ('.text.clip_read', 0x196c, 0x1970, 0x2406bf52),
    ('.text.clip_read', 0x197e, 0x1982, 0x2406bf52),
    ('.text.clip_read', 0x1990, 0x1994, 0x2406bf52),
    ('.text.clip_read', 0x19a2, 0x19a6, 0x2406bf52),
    ('.text.clip_read', 0x1a08, 0x1a10, 0x2406bf52),
    ('.text.clip_read', 0x1a50, 0x1a58, 0x2406bf52),
    ('.text.clip_read', 0x1aa6, 0x1aaa, 0x2406bf52),
    ('.text.clip_read', 0x1ac8, 0x1acc, 0x2406bf38),
    ('.text.clip_read', 0x1ad4, 0x1ada, 0x2406bf52),
    ('.text.clip_read', 0x1aea, 0x1af0, 0x2406bf52),
    ('.text.clip_read', 0x1b02, 0x1b08, 0x2406bf52),
    ('.text.clip_read', 0x1b1a, 0x1b1e, 0x2406bf52),
    ('.text.clip_read', 0x1b32, 0x1b36, 0x2406bf52),
    ('.text.clip_read', 0x1b4a, 0x1b50, 0x2406bf52),
    ('.text.clip_read', 0x1b60, 0x1b64, 0x2406bf52),
    ('.text.clip_read', 0x1b6c, 0x1b70, 0x2406bf52),
    ('.text.clip_read', 0x1b78, 0x1b7c, 0x2406bf52),
    ('.text.clip_read', 0x1b86, 0x1b8a, 0x2406bf52),
    ('.text.clip_read', 0x1b94, 0x1b98, 0x2406bf52),
    ('.text.clip_read', 0x1ba2, 0x1ba6, 0x2406bf52),
    ('.text.clip_read', 0x1bb0, 0x1bb4, 0x2406bf52),
    ('.text.clip_read', 0x1bc8, 0x1bd0, 0x2406bf38),
    ('.text.clip_read', 0x1bde, 0x1be4, 0x2406bf38),
    ('.text.clip_read', 0x1fcc, 0x1fd4, 0x2406bf52),
    ('.text.clip_read', 0x1fe6, 0x1fea, 0x2406bf38),
    ('.text.clip_read', 0x3618, 0x361e, 0x2406bf52),
    ('.text.clip_read', 0x362a, 0x362e, 0x2406bf38),
    ('.text.clip_read', 0x41d6, 0x41e8, 0x2406bf52),
    ('.text.clip_read', 0x4526, 0x452c, 0x2406bf38),
    ('.text.clip_read', 0x4570, 0x4576, 0x2406bf38),
    ('.text.clip_read', 0x4594, 0x459a, 0x2406bf38),
    ('.text.clip_read', 0x4620, 0x4624, 0x2406bf52),
    ('.text.clip_read', 0x46d0, 0x46d4, 0x2406bf38),
    ('.text.clip_read', 0x471e, 0x4722, 0x2406bf52),
    ('.text.clip_read', 0x474a, 0x4750, 0x2406bf38),
    ('.text.clip_read', 0x4784, 0x478c, 0x2406bf52),
    ('.text.clip_read', 0x4936, 0x493c, 0x2406bf52),
    ('.text.clip_read', 0x495a, 0x495e, 0x2406bf52),
    ('.text.clip_read', 0x4968, 0x496e, 0x2406bf38),
    ('.text.clip_reset', 0x0006, 0x000c, 0x2406bb9c),
    ('.text.clip_reset', 0x0020, 0x0028, 0x2406bb9c),
    ('.text.clip_reset', 0x0024, 0x0034, 0x2406bd08),
    ('.text.clip_reset', 0x005a, 0x0060, 0x2406be39),
    ('.text.clip_reset', 0x0064, 0x0080, 0x2406be39),
    ('.text.clip_reset', 0x0156, 0x015c, 0x2406bf52),
    ('.text.clip_reset', 0x0160, 0x0168, 0x2406bb9c),
    ('.text.clip_reset', 0x0164, 0x016e, 0x2406bd08),
    ('.text.clip_reset', 0x0188, 0x018c, 0x2406bcfd),
    ('.text.clip_reset', 0x01c6, 0x01ce, 0x2406be39),
    ('.text.clip_sread', 0x001e, 0x0024, 0x2406a640),
    ('.text.clip_sum', 0x0000, 0x0004, 0x2406bb00),
    ('.text.clip_tail_of', 0x0000, 0x0004, 0x2406bf38),
    ('.text.cmp_block', 0x000c, 0x0018, 0x2406ab00),
    ('.text.cmp_block', 0x04ee, 0x04f2, 0x080a2065),
    ('.text.cmp_post', 0x0008, 0x0010, 0x2401bc80),
    ('.text.cmp_post', 0x001c, 0x0020, 0x2406a700),
    ('.text.cmp_run_aw', 0x000c, 0x0014, 0x2406a854),
    ('.text.cmp_run_aw', 0x25a8, 0x25ac, 0x2406a854),
    ('.text.cmp_run_aw', 0x2b0e, 0x2b16, 0x2406a854),
    ('.text.cmp_wake', 0x0002, 0x0008, 0x2406a798),
    ('.text.osd_sync', 0x0006, 0x000a, 0x24069418),
    ('.text.osd_sync', 0x0010, 0x0018, 0x2406c0e0),
    ('.text.osd_sync', 0x0074, 0x0080, 0x24069418),
    ('.text.osd_sync', 0x014c, 0x0158, 0x24069418),
    ('.text.slot_reset', 0x0002, 0x0008, 0x2406c254),
    ('.text.thm_job', 0x000a, 0x0012, 0x2406a650),
    ('.text.thm_load', 0x000a, 0x000e, 0x24022970),
    ('.text.thm_load', 0x0042, 0x0046, 0x24009c80),
    ('.text.thm_load', 0x0416, 0x041a, 0x2406a64c),
    ('.text.thm_osd_col', 0x0000, 0x0006, 0x2406c0e0),
    ('.text.thm_post', 0x0012, 0x0018, 0x2406a64c),
    ('.text.thm_post', 0x005a, 0x0068, 0x080e3d98),
)

# Settings: the Tools screen has tabs (Main, Rec, MIDIIn), four rows each --
# one per encoder, no scrolling. The page builder (0x0807974c) copies a tab's
# rows from SETTINGS_VA + 16 * tab and its name from the six-pointer list at
# TABS_VA, and counts tabs up to the first EMPTY name. Slots 4-6 hold the empty
# string and their row pages are zero, so a fourth tab is a name pointer and
# four row ids, with nothing stock moved. (cc5 put the rows on MIDIIn's slots
# 5-8, which the screen never shows.)
SETTINGS_VA = 0x080c7ebc                  # loaded at 0x0807976a (micro 0x08077702)
SETTINGS_STOCK = ((97, 120, 156, 150), (127, 379, 194), (89, 90, 181, 195))
TABS_VA = 0x080c7ea4                      # loaded at 0x08079796
TABS_EMPTY = 0x080cb46c                   # "" -- what slots 4-6 point at
TAB_NAME = "Patch"                        # the builder copies 7 characters

# The stage-3 functions of patch_micro.py that are run here, with every micro
# address in their source replaced through CODE_MAP / RAM_MAP / ram_shift.
STAGE3_FUNCS = (
    "build_program_change_hook", "apply_program_change",
    "build_clock_hold_hook", "apply_clock_hold",
    "build_cpu_meter_hook", "apply_cpu_meter",
    "build_preset_bpm_hook", "apply_preset_bpm",
    "build_character_hook", "apply_character",
    "_osd_pad_rec", "_osd_post", "_keep_skip", "build_osd_hook", "apply_osd",
    "build_keep_hook", "apply_keep_ccs",
    "build_comp_type_hook", "apply_comp_type",          # 2.3.10 (cc13)
    "build_theme_hook", "apply_theme", "_themed_bar",   # 2.3.10 (cc16)
)
# Module constants they read that carry micro code addresses.
STAGE3_GLOBALS = (
    "PC_CALLS", "PC_MIRROR_VA", "CLK_CALLS", "CLK_SITES", "CLK_SET_STORE",
    "CLK_SET_REBUILD", "CLK_REG_LIMIT_VA", "CLK_STORE_CAP_VA", "K_CALLS",
    "L_CALLS", "L_ENTRIES", "CHR_SITE", "CHR_SITE_FN", "CHR_EQ_HEAD_VA",
    "OSD_CALLS", "OSD_FONT_VA", "OSD_FONT_LIT_VA", "OSD_LFO_LABELS",
    "OSD_PAD_SITES", "OSD_SLICER_GUARD", "OSD_GRANULAR_GUARD", "OSD_SETPARAM",
    "KEEP_CALLS", "KEEP_GUARDS", "KEEP_FINAL_SITES", "FINALIZE_FN",
    "KEEP_SETPARAM",
    "CMP_CALLS", "CMP_EXTERNS", "CLIP_EXTERNS", "THEME_EXTERNS", "COMP_SITES",   # 2.3.10 (cc13)
    "CLIP_CC_RET", "THEME_SITES",
)

# Generated by `patch_mk2.py ... --reassemble` with clang 18; see mk2_assemble.
# BEGIN FROZEN_MK2
FROZEN_MK2 = {
    'mk2_font': (
        "45a2002110f8013b2bb152f82330c3f307431944f6e7084670472de9f04f8ab0029203930022049220e02de9f04f8ab0"
        "04460d460293139b0393049206a8dff8d0c0e0470698296888420dd107986968884209d10898a968884205d10998e968"
        "884201d1002004902046294604460d688a682a4401928a880f3200920ff2980a14f8010b00283fd05af82000070ee919"
        "019a914238dcc0f30741059186b20aeb460606f58066ab46002f2ad036f8028bddf800905fea58081ad3049b002b0dd0"
        "1868834514db99680844834510da586881450ddbd9680844814509da03981ffa8bf11ffa89f2029bdbb2dff828c0e047"
        "a9f10109b8f1000fdcd10bf1010b013fd2e705980544bbe70ab0bde8f08f00004d12060869b00508"
        , {'chr': 128, 'col': 168, 'done': 264, 'draw': 108, 'fstr': 26, 'fstrclip': 42, 'ftab': 280, 'fwidth': 0, 'nxt': 258, 'plot': 220, 'row': 180, 'skip': 240}),
    'mk2_gateT': (
        "9df84030072b01d10000000000000000"
        , {'_sT': 0, 'tcc': 8, 'tstock': 12}),
    'mk2_hookC': (
        "30b5169c179d000000006c2c06d06d2c06d06e2c06d06f2c0bd030bd172202e0182200e0ab22b5f5005fb4bf00250125"
        "06e0ac22ed1141f67f7305fb03f5ad0a2b46002482b00094019443f6b840c2f2024040f20001c0f203010000000002b0"
        "30bd"
        , {'_sC': 0, 'cbool': 38, 'cbs': 28, 'cfl': 36, 'cpost': 6, 'cpp': 32, 'csend': 64, 'csetp': 90, 'cwd': 50}),
    'mk2_hookDa': (
        "03b4ddf850c0bcf1000f40f0b080ddf854c0bcf1280f04d0acf12903052b2cd9a5e04df6b840c2f202404ef2b801c2f2"
        "02410268a2f11053b3f5a02f0cd24ff6a073d358b3f1c00f06d14ff6a473d35848f6a04c634503d004308842e9d386e0"
        "ddf858c0bcf5005fb4bf0023012348f65841c0f20201535479e04df60022c2f2064211684cf2de0cc1f2100c61450fd0"
        "c2f800c00ff2b04002f1040102f1180c90ed000a81ed000a043004316145f7d3052b5fd0042b11d1dff880040168d0f8"
        "04c06fea0c0c614508d1dff874c4614503d0dff870c4614500d148e0ddf858c01cf07f0f08bf4ceadc1c00ee10cab8ee"
        "400a03eb43000ff2644101eb8001d1ed000a91ed011a886820ee200a30ee010a002801d0bceec00a02eb830080ed010a"
        "012b11d8dff814040168d0f804c06fea0c0c614508d1dff808c4614503d0dff804c4614500d129e0d2f800c053688cea"
        "030c93688cea030cd3688cea030c13698cea030c53698cea030cc2f818c003bc00000000ddf858c0f048bcf5ac5f09db"
        "ef49bcf52c5fa8bfee4901606fea0101416003e0002101604160d5e76ded031a92ed010ad2ed020ab7ee001ac1ee200a"
        "71ee600af4ee600af1ee10fa55d63aa0d0ec031a30ee210a20ee020a60eea20a71eee11a80fe210ac0fea10af2ee001a"
        "80fe610ac0fee10abdeec02afdeee02a12ee100a12ee901a072888bf0720072988bf072102ee100ab8eec22a30ee420a"
        "02ee901af8eee22a70eee20a00ebc000084424a1c54b1b68dff818c3634508bf01f2441101eb800191ed001ad1ed011a"
        "71eec11a00eea11a91ed092ad1ed0a2a72eec22a00eea22a32ee412a00ee021ab0ee410afdec031a02e0fdec031a15e0"
        "0ca0d0ed000ab4ee600af1ee10fac8bfb0ee600af1ee600ab4ee600af1ee10fab8bfb0ee600a82ed050a55e700205061"
        "52e700bf0000104200002042cdcc4c3ea2bc064100000080ae4731409a99b140ec5104410000304148e15a41a4708341"
        "ec5198416666ac4100000080f6280c40f6288c40d7a3d04066660a41a4702d411f854f4152b86e41e17a884100000080"
        "d7a3d03f7b144e40713d9a400ad7cb40a470fd400ad717410ad72f41000048410000008014ae873fec5108401f854b40"
        "52b88640295ca740295cc7406666e640666602410000008014ae073f6666863f14aec73fe17a04400ad7234033334340"
        "85eb61400000804000000080295c8f3db81e053ecdcc4c3eb81e853e0ad7a33e14aec73e6666e63e5c8f023f00000080"
        "000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080"
        "000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080"
        "000000800000008000000000a4706d40cdccec40e17a304133336b410ad79141c3f5ae41d7a3ca413d0ae94100000000"
        "14ae474014aec740b81e15418fc245411f857741ae4793410000aa41d7a3c241000000005c8f2240713da2405c8ff240"
        "b81e2141e17a48411f856f4100008c41e17a9e4100000000f628fc3f9a9979403333bb40295cf740713d1a41ae473941"
        "5c8f5641cdcc744100000000e17ab43f5c8f3240cdcc8440295caf405c8fda4085eb014148e1164148e12a4100000000"
        "9a99593fec51d83fd7a32040e17a54400ad78340e17a9c40cdccb440ae47d14000000000c3f5a83ec3f5283f48e17a3f"
        "6666a63f7b14ce3f8fc2f53f52b80e4085eb214000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020c00624"
        "4155544f41484f54000040c100000040a005000040380000000000008002203b000020c2000000006002983a0000803f"
        "000000005542953e0000c04101000000e7a239400000f043010000004002903b000010c200000000"
        , {'_sD': 0, 'dauto': 372, 'dauto_off': 404, 'dfound': 96, 'dk36': 676, 'dmakeup': 412, 'dmk_clamp': 624, 'dmk_nan': 618, 'dmk_zero': 668, 'dnext': 368, 'dnextc': 88, 'donoff': 34, 'dout': 366, 'dparam': 122, 'dscale': 1372, 'dscan': 50, 'dseed': 160, 'dseeded': 176, 'dstock': 1352, 'dstore': 280, 'dsum': 328, 'dsum_on': 326, 'dtab': 692, 'dtk': 680, 'dval': 220, 'dval_on': 218}),
    'mk2_hookDg': (
        "ddf848c0bcf1000f0dd1ddf84cc0acf1290cbcf1040f06d8dff814c0dcf800c0044b9c4501d0000000000000000000bf"
        "04c1062452504d43"
        , {'_sDg': 0, 'dg_dr': 38, 'dg_skip': 42}),
    'mk2_hookDr': (
        "03b4ddf850c0bcf1000f40f0a280ddf854c0bcf1280f04d0acf12903052b2cd997e04df6b840c2f202404ef2b801c2f2"
        "02410268a2f11053b3f5a02f0cd24ff6a073d358b3f1c00f06d14ff6a473d35848f6a04c634503d004308842e9d378e0"
        "ddf858c0bcf5005fb4bf0023012348f65841c0f2020153546be04df60022c2f2064211684cf2de0cc1f2100c61450ed0"
        "c2f800c050a002f1040102f1180c90ed000a81ed000a043004316145f7d3052b52d0042b0bd146480168dff818c16145"
        "05d141686fea0c0c614500d141e0ddf858c01cf07f0f08bf4ceadc1c00ee10cab8ee400a03eb430040a101eb8001d1ed"
        "000a91ed011a886820ee200a30ee010a002801d0bceec00a02eb830080ed010a012b0bd82e480168dff8b8c0614505d1"
        "41686fea0c0c614500d125e0d2f800c053688cea030c93688cea030cd3688cea030c13698cea030c53698cea030cc2f8"
        "18c003bc00000000ddf858c01c48bcf5005f05db1b4901606fea0101416003e0002101604160ece792ed010ad2ed020a"
        "b7ee001ac1ee200a70eec10a20ee200ab4ee400af1ee10fa15d60ca0d0ed000ab4ee600af1ee10fac8bfb0ee600af1ee"
        "600ab4ee600af1ee10fab8bfb0ee600a82ed050ab2e700205061afe70000104220c006244155544f000040c100000040"
        "a005000040380000000000008002203b000020c2000000006002983a0000803f000000005542953e0000c04101000000"
        "e7a239400000f043010000004002903b000010c200000000"
        , {'_sD': 0, 'dauto': 344, 'dauto_off': 368, 'dfound': 96, 'dk36': 460, 'dmakeup': 376, 'dmk_zero': 454, 'dnext': 340, 'dnextc': 88, 'donoff': 34, 'dout': 338, 'dparam': 122, 'dscale': 492, 'dscan': 50, 'dseed': 158, 'dseeded': 174, 'dstock': 472, 'dstore': 264, 'dsum': 300, 'dval': 206}),
    'mk2_hookE': (
        "4df60022c2f2064213684cf2de0cc1f2100c634519d0c2f800c040f20003ccf24013536040f20003c4f20003936040f2"
        "a053d36043f64003136140f2000353614ff63e53c9f25013936153688cea030c93688cea030cd3688cea030c13698cea"
        "030c53698cea030c936963450ed15368c0f828349368c0f82c34d368c0f848341369c0f84c345369c0f8303400000000"
        , {'_sE': 0, 'enext': 140, 'eout': 140, 'everify': 74}),
    'mk2_hookF': (
        "03b4ddf850c0bcf1000f40f09580ddf854c0acf13203092b00f28e804df64022c2f2064211684ef20e00c1f210008142"
        "26d0106040f20001516041f6c071916041f6c071d16041f6c071116140f20001516140f20001916140f20001d16140f2"
        "0001116240f20001516240f2010191620021116351634ff6cf71c1f21001d1621699002b05d10a2001fb00f1890b5160"
        "2fe0072b06d1b1f5005fb4bf00210121116226e0092b06d1b1f5005fb4bf0021012151621de0042b06d1b1f5005fb4bf"
        "00210121516114e0052b06d1b1f5005fb4bf0021012191610be0062b06d1b1f5005fb4bf00210121d16102e014a0c05c"
        "1150916a013191621068536880ea0300936880ea0300d36880ea0300136980ea0300536980ea0300936980ea0300d369"
        "80ea0300136a80ea0300536a80ea0300936a80ea0300d06203bc0000000000bf38080c10383838383838"
        , {'_sF': 0, 'fbump': 242, 'fnext': 314, 'fnotba': 200, 'fnotbb': 218, 'fnotbc': 236, 'fnotbyp': 164, 'fnotmode': 146, 'fnotslope': 182, 'fout': 312, 'fplain': 236, 'fseeded': 128, 'fslots': 320}),
    'mk2_hookG': (
        "2de9f0412ded068b04460d464df64026c2f2064633684ef20e00c1f21000834227d03246106040f20001516041f6c071"
        "916041f6c071d16041f6c071116140f20001516140f20001916140f20001d16140f20001116240f20001516240f20101"
        "91620021116351634ff6cf71c1f21001d1623068736880ea0300b36880ea0300f36880ea0300336980ea0300736980ea"
        "0300b36980ea0300f36980ea0300336a80ea0300736a80ea0300b36a80ea0300f36a984240f00480b06a306300f0fcf8"
        "20462946bdec068bbde8f0410000000000b500eb800204eb820282f80c1182ed441a82ed450ac2ed460a0123c2f81c31"
        "0ff6dc1353f8213001462046984700bd002000ee900af8ee600ab4eee00af1ee10fa01d5b0ee600af3ee000ab4eee00a"
        "f1ee10fa01ddb0ee600afceec00a10ee900a0f2888bf0f2000ee900af8ee600a70ee600a0ff6942101eb800191ed001a"
        "d1ed011a71eec11aa1eea01ab0ee410a704741f6c071401a48bf002000ee100ab8ee400a0ff6f011d1ed000a20ee200a"
        "f7ee000ab4eee00af1ee10fa01ddb0ee600a704700ee100ab8ee400a0ff6c011d1ed000a20ee200a704791ed000ad1ed"
        "010a01ee100ab8ee411a0ff6a012d2ed001a21ee211aa1ee200a704741f6c071421a1346002bb8bf5b42802b18d9803b"
        "00ee103ab8ee400a0ff66c11d1ed000a20ee200a002a04dc0ff65011d1ed000a03e00ff64c11d1ed000a20ee200a7047"
        "002300ee103ab8ee400a704741f6c071421a1346002bb8bf5b42802b15d9803b00ee103ab8ee400a0ff61c11d1ed000a"
        "20ee200a0ff60c11d1ed000a20ee200a002a01dcb1ee400a7047002300ee103ab8ee400a704741f6c071421a1346002b"
        "b8bf5b42802b1cd9803b00ee103ab8ee400a0ff6d401d1ed000a20ee200a002a04dc0ff6ec01d1ed000a03e00ff6e401"
        "d1ed000ab7ee001aa0ee201ab0ee410a7047b7ee000a704700b5002000eb800104eb8101002281f80c21c1f81c210130"
        "0428f3d300227263336a002b40f0dd837368002b00f01d80012b00f08981022b00f0fd81032b00f09380042b00f0d280"
        "052b00f0bf82062b00f08f82072b00f0e982082b00f01783092b00f05f8300f0bcbbb26841f6c073d21a10460028b8bf"
        "4042802840f2b183803800ee100ab8ee400a0ff61401d1ed000a20ee200af7ee000ab4eee00af1ee10fa01ddb0ee600a"
        "002a05dc0527f7ee000a30eec00a00e00127f3ee000a20ee200ab0ee409afff7bffeb0ee408af0680ff29471fff70dff"
        "f0ee408a00203946b0ee480af0ee680a002301ee103afff793fe01227263736a002b01d1306903e043f68070c0f20000"
        "fff7e8fef7ee000ab4eee00af1ee10fac0f26383f3ee000a30eec00a0ff28472d2ed000a20ee200a052f02d039ee400a"
        "01e039ee000afff783feb0ee408a01203946b0ee480a0ff23c72d2ed000a002301ee103afff75cfe0322726300f03dbb"
        "00f004f80722726300f037bb00b500270ff2b86000eb870090ed008a1c20a0eb87003058002811d11020a0eb87003058"
        "fff7bcfeb0ee409a0ff29c6000eb8700d0ed008a0ff28060c15d0ee00ff2986000eb8700d0ed008a0ff2986000eb8700"
        "90ed009a0ff27c60c15d3846b0ee480af0ee680ab0ee491afff71afe0137032fc6d300bd0ff2446090ed008ab369002b"
        "0cd1f068fff78afeb0ee409a0ff23860d0ed008a0ff2206001780ae00ff23860d0ed008a0ff23c6090ed009a0ff22460"
        "01780020b0ee480af0ee680ab0ee491afff7eefd0ff2f45090ed028a7369002b0cd1b068fff762feb0ee409a0ff2e850"
        "d0ed028a0ff2d05081780ae00ff2e850d0ed028a0ff2ec5090ed029a0ff2d45081780120b0ee480af0ee680ab0ee491a"
        "fff7c6fd03227263f369002b01d1326903e041f6c072c0f2000241f6c073d21a10460028b8bf4042802840f296828038"
        "00ee100ab8ee400a0ff2dc51d1ed000a20ee200af7ee000ab4eee00af1ee10fa01ddb0ee600a002a05dc0527f7ee000a"
        "30eec00a00e00127f3ee000a20ee200afff7a6fdb0ee408a0ff28852d2ed008a02203946b0ee480af0ee680a002301ee"
        "103afff77dfd07227263736a002b00f05c8203203946b0ee480af0ee680a002301ee103afff76cfd0f22726300f04dba"
        "30690ff21c51fff7d0fdf0ee408a7369002b01d1b06803e041f6c070c0f20000fff79ffdf3ee000a20ee200af3ee000a"
        "30eec00afff764fdb0ee408af0ee409a00200521b0ee480af0ee680a002301ee103afff73dfdb369002b01d1f06803e0"
        "41f6c070c0f20000fff77bfdf3ee000a20ee200afff744fdb0ee409ab0ee408a01200121b0ee480af0ee680a002301ee"
        "103afff71dfd03227263736a002b00f0fc81b0ee698a0ff29c42d2ed008a02200521b0ee480af0ee680a002301ee103a"
        "fff706fdb0ee498a0ff27842d2ed008a03200121b0ee480af0ee680a002301ee103afff7f5fc0f22726300f0d6b9b068"
        "fff750fdb0ee409ab369002b01d1f06803e041f6c070c0f20000fff72afd0ff26041d1ed000a20ee200a0ff25041d1ed"
        "000a70eec09a0ff22042d2ed008a39ee690afff7e5fcb0ee408a00200121b0ee480af0ee680a002301ee103afff7c0fc"
        "0ff2f432d2ed008a39ee290afff7d0fcb0ee408a01200521b0ee480af0ee680a002301ee103afff7abfc032272633069"
        "41f6c073c01a0028b8bf404280281ad9b0ee490afff7b4fcb0ee408a0ff2a832d2ed008a3069fff711fdb0ee401a0220"
        "0321b0ee480af0ee680afff789fc0722726300f06ab9736a002b00f066810ff27432d2ed008a39ee690afff791fcb0ee"
        "408a02200121b0ee480af0ee680a002301ee103afff76cfc0ff24832d2ed008a39ee290afff77cfcb0ee408a03200521"
        "b0ee480af0ee680a002301ee103afff757fc0f22726300f038b9b068fff7b2fcfff766fcb0ee408af0680ff2ec21fff7"
        "b4fcf0ee408af369002b01d1306903e043f68070c0f20000fff783fc0ff21431d1ed000a20ee209a00200321b0ee480a"
        "f0ee680ab0ee491afff72afc0122726300f00bb97369002b01d1b06803e043f68070c0f20000fff7c1fcb0ee409af068"
        "fff778fcfff72cfcb0ee408a0ff29422d2ed008a00200221b0ee480af0ee680ab1ee491afff704fc01200421b0ee480a"
        "f0ee680ab0ee491afff7fafb0322726300f0dbb8b068fff755fcfff709fcb0ee408ab369002b01d1f06803e043f68070"
        "c0f200000ff21821fff74ffcf0ee408af369002b01d1306903e043f68070c0f20000fff753fcb0ee409a00200321b0ee"
        "480af0ee680ab0ee491afff7c9fb0122726300f0aab8b068fff724fcf0ee409af369002b01d1306903e043f68070c0f2"
        "00000ff2cc11fff720fcb0ee40aab369002b01d1f06803e043f68070c0f20000fff7effb0ff2ec11d1ed000a20ee209a"
        "0ff2a411d1ed008a0f227263002700ee107ab8ee400af7ee080a30ee600a20ee0a0a30ee290afff7a3fbb0ee408a3846"
        "0321b0ee480af0ee680ab0ee491afff77ffb0137042fe2d300f05fb83069fff742fcf0ee408ab369002b01d1f06803e0"
        "43f68070c0f20000fff7b3fbb0ee409ab06800ee100ab8ee400a0ff27011d1ed000a20ee200af1ee000ab4eee00af1ee"
        "10fa01ddb0ee600afceec00a10ee900a032888bf032000ee900af8ee600a30ee608a00eb40000ff2581808eb80080722"
        "7263002708eb870393ed000ad3ed030a70eec00aa0ee880a20ee280a0ff2181303eb8703d3ed000a0ff2181303eb8703"
        "93ed001a21ee091a38460321fff720fb0137032fded300f000b8002707eb870104eb8101d1f81c1100290cd138460321"
        "0ff2c40292ed000af7ee000a002301ee103afff705fb0137042fe7d300bd00bf0000000031a90b0875aa0b0835ad0b08"
        "f9b00b08b5af0b08020304000000164300002f4400007a45f4fd343f6666663ff4fd343f01030500f4fd343f6666663f"
        "f4fd343f000000000000c0c100000000f4fd343f4260e9400000803f000098413333b33e9a992940000080400000003f"
        "0000c040f4fd343f6666663f0000c0c100001041000010416f120339040281380402813a0000803e0402013900000041"
        "3333f3400000c0c100007a4404028139000000bf0000803f000080400000e0400000104100004041000010410000c040"
        "0000874300200f4500c03745008004440040e74400001b4500003444004088440080184500800e440000524400001645"
        "00009b4300005c4400000c4500002042418764422934a342b11ae942bf78264396c56d4314cea9436888f24380342d44"
        "a16377445aacb044c057fc44fb353445a1b28045bed1b7455646034600803b46"
        , {'_sG': 0, 'gapply': 696, 'gbpnar': 2928, 'gbpwid': 2924, 'gccinv': 2908, 'gclr': 700, 'gctl0f': 952, 'gctl0j': 960, 'gctl10f': 2424, 'gctl10j': 2432, 'gctl11f': 2544, 'gctl11j': 2552, 'gctl1f': 1362, 'gctl1j': 1370, 'gctl2f': 1560, 'gctl2j': 1568, 'gctl3f': 1632, 'gctl3j': 1640, 'gctl4f': 1794, 'gctl4j': 1802, 'gctl5f': 2128, 'gctl5j': 2136, 'gctl6f': 2190, 'gctl6j': 2198, 'gctl7f': 2300, 'gctl7j': 2308, 'gctl8f': 2330, 'gctl8j': 2338, 'gctl9f': 2394, 'gctl9j': 2402, 'gdjspr': 2916, 'gdtab': 2768, 'gfmtdn': 2944, 'gfmtf': 2976, 'gfmtg': 2964, 'gfmtis': 2940, 'gfmtq': 2952, 'gfmtup': 2948, 'gfsend': 676, 'gfsflat': 690, 'gfshift': 614, 'gfsup': 668, 'gft1': 280, 'gft2': 298, 'gftab': 256, 'ggain': 460, 'ggboo': 2896, 'ggboost': 514, 'ggcut': 2892, 'ggend': 522, 'ggflat': 528, 'ghalf': 354, 'ghdone': 402, 'ghsinv': 2904, 'ghspan': 2920, 'gidxs': 2912, 'gmbpsl': 1990, 'gmdj': 802, 'gmdjc': 864, 'gmdjf': 882, 'gmdjhp': 880, 'gmdjs1': 1010, 'gmdjs2': 1014, 'gmfill': 2716, 'gmfmc': 2600, 'gmfmt': 2524, 'gmfmtl': 2644, 'gmfnext': 2758, 'gmix3': 1068, 'gmix3k': 1132, 'gmix3l': 1072, 'gmix3s': 1162, 'gmixf': 2796, 'gmixk': 2820, 'gmixkg': 2836, 'gmixkq': 2824, 'gmixq': 2808, 'gmixt': 2792, 'gmmix': 1056, 'gmmnl': 2462, 'gmmnot': 2374, 'gmnotch': 2090, 'gmnsp': 2864, 'gmout': 2714, 'gmpeak': 2276, 'gmphone': 1774, 'gmtilt': 2180, 'gmtnc': 1430, 'gmtnf': 1448, 'gmtnhp': 1446, 'gmtnk0': 1228, 'gmtnk1': 1308, 'gmtns0': 1250, 'gmtns1': 1330, 'gmtone': 1188, 'gmtwin': 1536, 'gnext': 204, 'gnotchg': 2932, 'gnullf': 2936, 'gout': 192, 'gqbell': 2888, 'gqfix': 2884, 'gqmap': 426, 'gqmn': 2872, 'gqnot': 2856, 'gqph': 2876, 'gqres': 2848, 'gsetband': 208, 'gtable': 3036, 'gtdend': 600, 'gtdflat': 602, 'gtiltd': 540, 'gtiltg': 2900, 'gu16': 404, 'gvalid': 114}),
    'mk2_hookH': (
        "10b582b01a460ff2141303240094069c01940000000002b010bd0cb495f8b0220a610cbc000000000cb4354a00231360"
        "53600cbc000000000cb4314a0023136053600cbc000000000cb42d4a0023136053600cbc0000000070b50c4605460000"
        "00000fb4002810d026498d420dd1217803290ad12169002901d0234900e000211f4a6fea0103536011600fbc70bd7fb5"
        "c0b0669b022b2cd1194b1c681a4dac4227d15c686fea0505ac4222d1174b1b681b78002b1dd1164b1c682378002b18d0"
        "144800000000002813d0134841996a460000000000280cd06d4640f2001614f8010b15f8011b884203d1002806d0013e"
        "f5d140b0bde87f400000000040b07fbd80da0624b8380224324e4350483c02244c3c0224b83c0224e43b022404110c08"
        "08110c08000000004e4557204f4e4c590000bf00"
        , {'_sH': 0, 'hinit': 40, 'hinit_next': 52, 'hinvalidate': 56, 'hinvalidate_next': 68, 'hload': 142, 'hload_compare': 222, 'hload_idle': 194, 'hload_next': 248, 'hload_resolve': 208, 'hload_same': 252, 'hload_stock': 242, 'hmenu': 284, 'hmenu_new': 296, 'hmenu_new_ptr': 292, 'hpost': 26, 'hpost_next': 36, 'hregister': 0, 'hregister_call': 18, 'hresponse': 88, 'hresponse_call': 94, 'hresponse_invalid': 126, 'hresponse_out': 138, 'hresponse_store': 128, 'hteardown': 72, 'hteardown_next': 84}),
    'mk2_hookJ': (
        "1fb582b040f23a110ff278120ff26c13022400940ff28c1401940000000002b0bde81f400000000007b500000000bde8"
        "074040f23a1100220000000040f23a1c62450bd1dff828c11bb14a4bccf800307047ccf80030ccf80430704700000000"
        "c4f83c31424b4ff0000cc3f800c0c3f804c00000000014f8081021b1dff8f8c03c4bccf800300000000094ed4f0ad4ed"
        "067a00f022f80000000090ed4f0ad0ed067a00f01af80000000094ed4f0ad4ed067a00f012f80000000090ed4f0ad0ed"
        "067a00f00af80000000094ed4f0ad4ed067a00f002f800000000dff894c0dcf80030dff890c0634517d1dff88cc0dcf8"
        "0030dff880c063450fd19fed1b7af4ee477af1ee10fa08dd9fed187af4ee477af1ee10fa01dab0ee670a704787b0fbb9"
        "dff84cc0dcf80030dff848c0634519d1dff844c0dcf80030dff838c0634511d1d4ed067a9fed087af4ee477af1ee10fa"
        "08dd9fed067af4ee477af1ee10fa01da00000000000000000000a04100007a4488da0624444c4f488cda062400000000"
        "00000000436c6b204c6f73733a0000bf494e5445524e414c0000bf00484f4c440000bf00636c6b6c6f73736d6f646500"
        , {'_sJ': 0, 'jctor': 96, 'jctor_next': 114, 'jheld': 118, 'jheld_next': 134, 'jhold': 218, 'jhold_out': 282, 'jholdtxt': 412, 'jinternal': 400, 'jlabel': 388, 'jmax': 364, 'jmin': 360, 'jpost': 60, 'jpost_internal': 82, 'jpost_next': 92, 'jreg': 0, 'jreg_call': 26, 'jreg_next': 36, 'jset': 284, 'jset_rebuild': 356, 'jset_store': 352, 'jstore': 40, 'jstore_call': 42, 'jstore_next': 56, 'jt1': 138, 'jt1_next': 150, 'jt2': 154, 'jt2_next': 166, 'jt3': 170, 'jt3_next': 182, 'jt4': 186, 'jt4_next': 198, 'jt5': 202, 'jt5_next': 214, 'jvalues': 380, 'jxml': 420}),
    'mk2_hookK': (
        "1fb584b040f23b110ff2c0120ff2b413022400940ff2c01401940000000004b0bde81f400000000007b500000000bde8"
        "074040f23b1100220000000040f23b1c624501d000000000dff868c103b15a4bccf8003070472de91750044600000000"
        "20680168426859b38a4288bf0a4640f2e83302fb03f2b2fbf1f240f2e83c624588bf62464d480168614588bf1146531a"
        "01ebe301016041688368614584bf002100238a4203d9114640f2771306e00bb1013b03e002292cbf0239002141608360"
        "bde817902de9ff513a4909683a4a91422cd1804639490c684d6840f2e83c644588bf6446654588bf6546d42604fb06f4"
        "05fb06f540f2e836b4fbf6f4b5fbf6f5002d08bf4ff6ff7508f5907700f012f808f5967700f00ef808f59c7700f00af8"
        "08f5a27700f006f8bff34f8fbde8ff5100000000386800283ad0c10738d1b988b1f5a07f34d1f988f02931d141f2d841"
        "08440022aa4208d0a24209d2be2a0ad2942a0bd248f2e0330ae04ff6ff7307e048f6420304e04ff6004301e04ff68063"
        "00eb42063380a6f88032a6f80035a6f880370132b2f1d40fdcd3dff824c020f01f0600f62812ccf8006020369642fad3"
        "704700bf90da0624444c4f4898da062468ef00e004110c0808110c08435055204d657465723a00006370756d65746572"
        "0000bf00"
        , {'_sK': 0, 'kbar': 308, 'kbar_loop': 340, 'kbar_ret': 432, 'kc_amber': 380, 'kc_bg': 368, 'kc_clean': 422, 'kc_peak': 362, 'kc_put': 384, 'kc_red': 374, 'kdone': 192, 'kdraw': 196, 'kdraw_next': 304, 'kdraw_out': 300, 'klabel_meter': 460, 'kpeak_decay': 180, 'kpeak_old': 174, 'kpeak_save': 188, 'kpost': 60, 'kpost_meter': 72, 'kpost_next': 68, 'kpost_store': 80, 'kreg': 0, 'kreg_call1': 26, 'kreg_next': 36, 'kstart': 86, 'kstart_call': 92, 'kstore': 40, 'kstore_call': 42, 'kstore_next': 56, 'kvalues': 452, 'kxml_meter': 472}),
    'mk2_hookKt': (
        "1fb584b040f23b110ff2f8120ff2ec13022400940ff2f81401940000000004b0bde81f400000000007b500000000bde8"
        "074040f23b1100220000000040f23b1c624501d000000000dff878c103b15e4bccf8003070472de91750044600000000"
        "20680168426859b38a4288bf0a4640f2e83302fb03f2b2fbf1f240f2e83c624588bf624651480168614588bf1146531a"
        "01ebe301016041688368614584bf002100238a4203d9114640f2771306e00bb1013b03e002292cbf0239002141608360"
        "bde817902de9ff533e4909683e4a914235d18046dff8f890d9f800103d4a914201d00ff2f80939490c684d6840f2e83c"
        "644588bf6446654588bf6546d42604fb06f405fb06f540f2e836b4fbf6f4b5fbf6f5002d08bf4ff6ff7508f5907700f0"
        "12f808f5967700f00ef808f59c7700f00af808f5a27700f006f8bff34f8fbde8ff5300000000386800283ad0c10738d1"
        "b988b1f5a07f34d1f988f02931d141f2d84108440022aa4208d0a24209d2be2a0ad2942a0bd2b9f808300ae0b9f80e30"
        "07e0b9f8103004e0b9f80c3001e0b9f80a3000eb42063380a6f88032a6f80035a6f880370132b2f1d40fdcd3dff828c0"
        "20f01f0600f62812ccf8006020369642fad3704790da0624444c4f4898da0624e0da0624314f485468ef00e0314f4854"
        "4288ffffe08380fe00fcffff428810c21f80e0830080ffff00fc00bf04110c0808110c08435055204d657465723a0000"
        "6370756d657465720000bf00"
        , {'_sK': 0, 'kbar': 326, 'kbar_loop': 358, 'kbar_ret': 450, 'kc_amber': 398, 'kc_bg': 386, 'kc_clean': 440, 'kc_peak': 380, 'kc_put': 402, 'kc_red': 392, 'kd_tab': 230, 'kdone': 192, 'kdraw': 196, 'kdraw_next': 322, 'kdraw_out': 318, 'klabel_meter': 516, 'kpeak_decay': 180, 'kpeak_old': 174, 'kpeak_save': 188, 'kpost': 60, 'kpost_meter': 72, 'kpost_next': 68, 'kpost_store': 80, 'kreg': 0, 'kreg_call1': 26, 'kreg_next': 36, 'kstart': 86, 'kstart_call': 92, 'kstore': 40, 'kstore_call': 42, 'kstore_next': 56, 'ktho': 476, 'kvalues': 508, 'kxml_meter': 528}),
    'mk2_hookL': (
        "0ff2901300000000662903d1584b984208bf584870b4458900000000662903d1534b984208bf5348f0b4468900000000"
        "662a1cd130b4504c2460504c24684ff01055ac420dd34e4dac420ad242f66045655d35b14b4c9db2cbf6d015256030bc"
        "7047484c0025256030bc4ff482310000000016b52ded027b424c21680a0c4bf6d0139a4211d13d4a12684ff010539a42"
        "0bd33b4b9a4208d289b207ee901af8ee677ac2ed4f7a00212160bdec027bbde8164000000000dff8c4c0ccf800400000"
        "00002de9ff512ded027b2f4909682f4a914241d12849096891423dd1274c24684ff010518c4237d325498c4234d242f6"
        "6041615c81bbd4ed067a9fed1a7af4ee477af1ee10fa27dd9fed177af4ee477af1ee10fa20da9fed157a77ee877afdee"
        "e77a17ee905a282d38bf2825fa2d88bffa251048662100000000a8420cd00d4866212a46000000000e48a9b2cbf6d011"
        "01600f4801210170bdec027bbde8ff51000000000000a04100007a440000003f40d00124e87301248cda0624a4da0624"
        "00c00724a8da062488da0624444c4f4874d001245072657365742042504d3a00"
        , {'_sL': 0, 'lblock': 114, 'lblock_done': 170, 'lblock_next': 178, 'lctor': 182, 'lctor_next': 190, 'lgetall': 8, 'lgetall_go': 20, 'lgetall_next': 24, 'lhalf': 364, 'llabel': 404, 'lmax': 360, 'lmin': 356, 'lpost': 48, 'lpost_next': 110, 'lpost_now': 98, 'lreg': 0, 'lreg_next': 4, 'lsetall': 28, 'lsetall_go': 40, 'lsetall_next': 44, 'ltick': 194, 'ltick_get': 310, 'ltick_next': 352, 'ltick_out': 344, 'ltick_set': 324}),
    'mk2_hookN': (
        "01b5000000002de90f50eff30080f1ee101a03b42ded100a189800000000bdec100a03bc80f30088e1ee101abde80f50"
        "01b000bd2de90f50eff30080f1ee101a03b42ded100a2a982b992c9a00000000bdec100a03bc80f30088e1ee101abde8"
        "0f500000000000bf"
        , {'_sN': 0, 'nblock': 0, 'nblock_c': 26, 'nblock_orig': 2, 'nmidi': 52, 'nmidi_c': 76, 'nmidi_next': 98}),
    'mk2_hookNc': (
        "01b5000000002de90f50eff30080f1ee101a03b42ded100a189800000000bdec100a03bc80f30088e1ee101abde80f50"
        "01b000bd2de90f50eff30080f1ee101a03b42ded100a2a982b992c9a000000002c90bdec100a03bc80f30088e1ee101a"
        "bde80f5000000000dff88cc1dcf800c0624b9c4508d0dff888c1dcf800c0614b9c4501d0000000002de90f50eff30082"
        "f1ee103a0cb42ded100a00000000bdec100a0cbc82f30088e1ee103abde80f5070472de90f50eff30080f1ee101a03b4"
        "2ded100a284621460000000010ee102abdec100a00ee102a03bc80f30088e1ee101abde80f5094ed068a70474e2b03d0"
        "662b19d3772b17d82de90f50eff30080f1ee101a03b42ded100a204649461a46269b00000000bdec100a03bc80f30088"
        "e1ee101abde80f50000000002de90f50eff30080f1ee101a03b42ded100a86b0ddf878c0cdf800c0ddf87cc0cdf804c0"
        "ddf880c0cdf808c0ddf884c0cdf80cc0ddf888c0cdf810c0ddf88cc0cdf814c0189819991a9a1b9b9ded060a00000000"
        "06b01290bdec100a03bc80f30088e1ee101abde80f5070472de90f50eff30080f1ee101a03b42ded100a504659460000"
        "00001590bdec100a03bc80f30088e1ee101abde80f50704710b5000000002de90f50eff30080f1ee101a03b42ded100a"
        "00000000bdec100a03bc80f30088e1ee101abde80f5010bd04c1062452504d4384c1062442504d43"
        , {'_sN': 0, 'nblock': 0, 'nblock_c': 26, 'nblock_orig': 2, 'nclip_beats': 408, 'nclip_beats_c': 430, 'nclip_cc': 236, 'nclip_cc_c': 274, 'nclip_cc_go': 248, 'nclip_cc_out': 296, 'nclip_rate': 178, 'nclip_rate_c': 200, 'ncomp': 104, 'ncomp_c': 136, 'ncomp_call': 154, 'ncomp_e': 132, 'nfinal': 456, 'nfinal_c': 480, 'nfinal_p': 458, 'njread': 300, 'njread_c': 380, 'nmidi': 52, 'nmidi_c': 76, 'nmidi_next': 100}),
    'mk2_hookOm': (
        "2de91f5083b040f24b110ff29c120ff27413042400940ff2981401940000000003b0bde81f50000000002de90f5040f2"
        "4b11012200000000bde80f500000000040f24b1c62451bd110b5032b05d94448114601220000000001230021414813f0"
        "010f18bf0846dff800c1ccf800003f48022b38bf0846dff8f8c0ccf8000010bd000000002de90f50eff30081f1ee102a"
        "06b42ded100a00000000bdec100a06bc81f30088e1ee102abde80f5000000000dff8c0c0ccf800404ff0000c00000000"
        "2de90710eff3008ca3f14f000e2819d80121814047f2ff72114213d0532b02d894f8751571b1244800682449884209d0"
        "149a234840f200111943416082600168013101608cf30088bde80710000000002de90710eff3008ca3f14f000e2819d8"
        "0121814047f66012114213d05a2b02d194f8541271b1104800681049884209d0129a0f4840f200211943416082600168"
        "013101608cf30088bde807100000000040d001244f44534f00dd0624444c4f4890da062440dd062410be06244c504552"
        "44dd062404110c08000000000000000000000000504f502d5550000043505500424f54480000bf004f53443a0000bf00"
        "6f73646d6f646500"
        , {'_sO': 0, 'oA_out': 260, 'oA_take': 230, 'oB_out': 340, 'oB_take': 310, 'octor': 176, 'octor_next': 188, 'odraw': 132, 'odraw_c': 150, 'odraw_next': 172, 'olabel': 424, 'opadA': 192, 'opadA_next': 268, 'opadB': 272, 'opadB_next': 348, 'opost': 64, 'opost_mode': 90, 'opost_next': 128, 'opost_set': 84, 'oreg': 0, 'oreg_call': 28, 'oreg_next': 38, 'ostore': 42, 'ostore_call': 52, 'ostore_next': 60, 'ostr_both': 416, 'ostr_cpu': 412, 'ostr_popup': 404, 'ovalues': 388, 'oxml': 432}),
    'mk2_hookP': (
        "2de91f5083b040f266110ff250220ff24423022400940ff2502401940000000003b0bde81f50000000002de90f5040f2"
        "6611002200000000bde80f5000000000662a06d1dff8f4c101b401208cf8000001bc40f2661c624510d110b5012b05d9"
        "774811460022000000000023dff8d4c1002003b17448ccf8000010bd0000000010b5000000000fb4eff300836d4c2068"
        "6d49884202d160680130606083f300880fbc10bd0fb4eff300836648002140f22822043a8150fcd1f021c16083f30088"
        "0fbc4ff0000c000000009df84030072b01d0000000002de91f10eff3008c18980f2813d819994f390e290fd81a9a554b"
        "0401241a641803eb4404a4f8402003eb4004208c01228a40104320848cf30088bde81f10000000002de9ff50eff3008c"
        "4df804cd87b0474c0020206120684649884279d16068a168884204d0a0600021e1606161a161e568f02d6dd2a0690130"
        "a0613e4f4af61060385c002831d04af204203e58a6f11050b0f5a02f29d24df6d84030584df6dc417158884221d149f2"
        "3c703858a8b948f2d430385848f2d831795888420dd148f6e010385848f6e4117958884205d160690130606120283bd3"
        "0ae000206061a06940f2ee21884233d302e0002060612fe042f6dc50c0f201003058102828d81027f02d24d20f20b5fb"
        "f0f101fb105204eb41031b8cd340db0717d007200090002001900590029112f14f00039004eb4500b0f8400004901048"
        "206130466946000000000135013fdbd101e00135d8e7e56007b05df804cb8cf30088bde8ff500000000000bf74d00124"
        "40d0012400be06245045454bb83c02244c50455204110c0808110c084b656570204343733a0000bf6b65657063637300"
        , {'_sP': 0, 'pb_busy': 434, 'pb_have': 326, 'pb_loop': 472, 'pb_next': 546, 'pb_out': 552, 'pb_post': 534, 'pb_ready': 456, 'pb_save': 550, 'pb_unsteady': 450, 'pblock': 280, 'pblock_next': 566, 'pctor': 164, 'pctor_clr': 178, 'pctor_next': 198, 'pedit': 64, 'pfinal': 128, 'pfinal_call': 130, 'pfinal_out': 156, 'plabel': 604, 'pmidi': 202, 'pmidi_cc': 214, 'pmidi_next': 276, 'pmidi_out': 268, 'pmidi_stock': 210, 'ppost': 82, 'ppost_mode': 108, 'ppost_next': 124, 'ppost_set': 102, 'ppost_store': 118, 'preg': 0, 'preg_call': 28, 'preg_next': 38, 'pstore': 42, 'pstore_call': 52, 'pstore_next': 60, 'pvalues': 596, 'pxml': 616}),
    'mk2_hookQ': (
        "2de91f5083b040f26b110ff27c020ff26803042400940ff27c0401940000000003b0bde81f50000000002de90f5040f2"
        "6b11002200000000bde80f500000000040f26b1c624514d12de90f50eff30081f1ee102a06b42ded100a184600000000"
        "bdec100a06bc81f30088e1ee102abde80f900000000000bf00000000000000000000000000000000436f6d7020547970"
        "653a0000636f6d70747970650000bf0053544f434b0000bf4c4f474943414c340000bf00564152494d5500005448554e"
        "44455200"
        , {'_sQ': 0, 'qlabel': 136, 'qpost': 64, 'qpost_call': 92, 'qpost_next': 114, 'qreg': 0, 'qreg_call': 28, 'qreg_next': 38, 'qstore': 42, 'qstore_call': 52, 'qstore_next': 60, 'qv0': 160, 'qv1': 168, 'qv2': 180, 'qv3': 188, 'qvalues': 120, 'qxml': 148}),
    'mk2_hookS': (
        "2de91f5083b0039840f28d1101220ff2cc13002400946ff0704401940ff2c814029400000000039840f28e1101220ff2"
        "c413002400946ff0704401940ff2c014029400000000039840f28f1101220ff2b813002400946ff0704401940ff2b414"
        "029400000000039840f2911101220ff2ac13002400946ff0704401940ff2a414029400000000039840f2921101220ff2"
        "a013002400946ff0704401940ff29814029400000000039840f2931101220ff29413002400946ff0704401940ff28c14"
        "029400000000039840f2951101220ff28813002400946ff0704401940ff28014029400000000039840f2961101220ff2"
        "7c13002400946ff0704401940ff2741402940000000003b0bde81f50000000002de90f50009840f28d114ff000020000"
        "0000009840f28e11284a00000000009840f28f114ff0000200000000009840f29111234a00000000009840f29211214a"
        "00000000009840f293111f4a00000000009840f295114ff0400200000000009840f296114ff07f0200000000bde80f50"
        "00000000a2f28d1cbcf1120f01d9000000002de90f50eff30081f1ee10ca2de902102ded100a10461946000000001690"
        "bdec100a06bc81f30088e1ee102abde80f50bcf1000fe2d0704700bf40201008a40ce60f40001000c0ff1f0043687220"
        "416d6f756e743a00636872616d6f756e740000bf43687220546f6e653a0000bf636872746f6e65004368722054797065"
        "3a0000bf6368727479706500436f6d7020313a00636d7076616c73310000bf00436f6d7020323a00636d7076616c7332"
        "0000bf00436f6d7020333a00636d7076616c73330000bf00436f6d7020343a00636d7076616c73340000bf00436f6d70"
        "20353a00636d7076616c73350000bf00"
        , {'_sS': 0, 'schr': 402, 'schr_call': 426, 'sclabel0': 476, 'sclabel1': 500, 'sclabel2': 520, 'sclabel3': 540, 'sclabel4': 560, 'sclabel5': 580, 'sclabel6': 600, 'sclabel7': 620, 'scxml0': 488, 'scxml1': 512, 'scxml2': 532, 'scxml3': 548, 'scxml4': 568, 'scxml5': 588, 'scxml6': 608, 'scxml7': 628, 'spost': 388, 'spost_next': 398, 'sreg': 0, 'sreg_c0': 34, 'sreg_c1': 66, 'sreg_c2': 98, 'sreg_c3': 130, 'sreg_c4': 162, 'sreg_c5': 194, 'sreg_c6': 226, 'sreg_c7': 258, 'sreg_next': 268, 'sstore': 272, 'sstore_c0': 286, 'sstore_c1': 298, 'sstore_c2': 312, 'sstore_c3': 324, 'sstore_c4': 336, 'sstore_c5': 348, 'sstore_c6': 362, 'sstore_c7': 376, 'sstore_next': 384}),
    'mk2_hookT': (
        "2de91f5083b040f283110ff628120ff6f4030c2400940ff62414019400000000039840f28d1101220ff2b42300240094"
        "6ff0704401940ff2b424029400000000039840f28e1101220ff2ac23002400946ff0704401940ff2ac24029400000000"
        "039840f28f1101220ff2a023002400946ff0704401940ff2a024029400000000039840f2911101220ff2942300240094"
        "6ff0704401940ff29024029400000000039840f2921101220ff28823002400946ff0704401940ff28424029400000000"
        "039840f2931101220ff27c23002400946ff0704401940ff27824029400000000039840f2951101220ff2702300240094"
        "6ff0704401940ff26c24029400000000039840f2961101220ff26423002400946ff0704401940ff26024029400000000"
        "03b0bde81f50000000002de90f5040f28311002200000000009840f28d114ff0000200000000009840f28e115e4a0000"
        "0000009840f28f114ff0000200000000009840f29111594a00000000009840f29211574a00000000009840f29311554a"
        "00000000009840f295114ff0400200000000009840f296114ff07f0200000000bde80f500000000040f2831c62450cd0"
        "a2f28d1cbcf1120f3cd90000000040f2831c624501d0000000002de90f50eff30081f1ee102a06b42ded100a18460c28"
        "28bf00200ff29c1151f820103a4a1160a8b10b2812d0411e882201fb02f10ff2b4121144354a222351f804cb42f804cb"
        "013bf9d1bff34f8f012000e0062000000000bdec100a06bc81f30088e1ee102abde80f902de90f50eff30081f1ee10ca"
        "2de902102ded100a10461946000000001690bdec100a06bc81f30088e1ee102abde80f50bcf1000fa7d070472de90f50"
        "eff30082f1ee103a0cb42ded100a002100000000bdec100a0cbc82f30088e1ee103abde80f50000000002de90f50eff3"
        "0082f1ee103a0cb42ded100a012100000000bdec100a0cbc82f30088e1ee103abde80f500000000040201008a40ce60f"
        "40001000c0ff1f002c100050800a072443687220416d6f756e743a00636872616d6f756e740000bf43687220546f6e65"
        "3a0000bf636872746f6e650043687220547970653a0000bf6368727479706500436f6d7020313a00636d7076616c7331"
        "0000bf00436f6d7020323a00636d7076616c73320000bf00436f6d7020333a00636d7076616c73330000bf00436f6d70"
        "20343a00636d7076616c73340000bf00436f6d7020353a00636d7076616c73350000bf00000000000000000000000000"
        "0000000000000000000000000000000000000000aa000000aa00000000ff000000000000000000003b4c5aff0c1216ff"
        "e0f3ffff1c40a8ff00b0ffff1f3bffff00b0ffff0c1216ff475b6bff00b0ffff2bc79cff1c32b8ff0c1216ff000000ff"
        "ecf8ffff2e3b46ff506677ff2bc79cff1c32b8ff66e0ffff1c32b8ff8ca5b8ff7ad2ffff3d8affff1a242cff00527aff"
        "00b0ffff1e6a7aff00b0ffffecf8ffff00b0ffff1c40a8ffecf8ffff000000001e2256ff05060effc4cff0ff1a23c8ff"
        "3d9affff142affff3d9affff05060eff242a6aff3d9affff3fa9d9ff1a24b0ff05060eff000000ffcfdaf8ff191c46ff"
        "2a3076ff3fa9d9ff1a24b0ff5ac1ffff1a24b0ff6c7ad2ff5c7affff7a4ad0ff0d0f24ff18209aff3d9affff204c6bff"
        "3d9affffcfdaf8ff3d9affff1a23c8ffcfdaf8ff000000003a3a3aff0e0e0effffffffffd65f1fff00b0ffff007affff"
        "00b0ffff0e0e0eff707070ff00b0ffffff9b3dff0056b8ff0e0e0eff000000ffffffffff303030ff7e7e7effff9b3dff"
        "0056b8ff4de1ffff0056b8ffc4c4c4ffffd09affd8b0ffff2a2a2aff00567aff00b0ffff256c7aff00b0ffffffffffff"
        "00b0ffffd65f1fffffffffff00000000304827ff0a1107ffe2ffd8ff367a1cff3dc4ffff3a4affff3dc4ffff0a1107ff"
        "39552eff3dc4ffff50ff9aff2e3ab3ff0a1107ff000000ffeeffe8ff25381eff416135ff50ff9aff2e3ab3ff5afff5ff"
        "2e3ab3ff82a872ffc8ff7aff3affc2ff182413ff125a7aff3dc4ffff1e7a6eff3dc4ffffeeffe8ff3dc4ffff367a1cff"
        "eeffe8ff0000000061394dff190d13fffff0ffff6f16b8ffffe62eff3b3bffffffe62eff190d13ff6f4359ffffe62eff"
        "b0ff3dff3a2ab8ff190d13ff000000fffff6ffff4f2d3dff7b4c64ffb0ff3dff3a2ab8ff5ce4ffff3a2ab8ffc298aaff"
        "ff85aeffe08affff351d29ff7a6e0effffe62eff2a6a7affffe62efffff6ffffffe62eff6f16b8fffff6ffff00000000"
        "aa0000ff000000ffffffffff550000ffaaaa00ff000000ffaaaa00ff000000ff55ffffffaaaa00ffaaaa00ff0000aaff"
        "000000ff000000ffffffffffffff55ffffff55ffaaaa00ff0000aaff55ffffff0000aaffaaaaaaffffff55ff55ffffff"
        "aa0000ff555500ffaaaa00ff0055aaffaaaa00ffffffffffaaaa00ff55ffffffffffffff00000000aa0000ff000000ff"
        "ffffffffaaaa00ff55ffffff000000ff55ffffff000000ffffffffff55ffffffaaaa00ff0000aaff000000ff000000ff"
        "ffffffffffff55ffffff55ffaaaa00ff0000aaff55ffffff0000aaffaaaaaaffffff55ff55ffffffaa0000ff555500ff"
        "55ffffff0055aaff55ffffffffffffff55ffffffaa0000ffffffffff00000000550000ff000000ffffffffffaa0000ff"
        "aaaa00ff000000ffaaaa00ff000000ff55ffffff55ffffffaa0000ff0000aaff000000ff000000ffffffffffaa0000ff"
        "ffff55ffaaaa00ff0000aaff55ffffff0000aaffaaaaaaffffff55ff55ffffff550000ff555500ffaaaa00ff0055aaff"
        "aaaa00ffffffffffaaaa00ff55ffffffffffffff00000000550000ff000000ffffffffffaa0000ffaaaa00ff000000ff"
        "aaaa00ff000000ff55ffffffaaaa00ffaa0000ff0000aaff000000ff000000ffffffffffaa0000ffffff55ffaaaa00ff"
        "0000aaff55ffffff0000aaffaaaaaaffffff55ff55ffffff550000ff555500ffaaaa00ff0055aaffaaaa00ffffffffff"
        "aaaa00ff55ffffffffffffff00000000550000ff0000ffffffffffffaa0000ffff80ffff000000ff0080ffff004080ff"
        "ffff00ff00ffffffff8080ff0000aaffff00ffff000000ffffffffffaa0000ffffff55ffaaaa00ff0000aaff00ff00ff"
        "0000aaffaaaaaaffffff55ff808080ff550000ff555500ffaaaa00ff0055aaffaaaa00ffffffffffaaaa00ffff80c0ff"
        "ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000005468656d653a00007468656d650000bf53544f434b0000bf414d4245520000bf53544147450000bf434f4e54"
        "524153540000bf0050484f5350484f520000bf0053594e5448574156450000bf4e4f52544f4e0000564f4c4b4f560000"
        "5041434d414e00004d49444e494748540000bf00444941470000bf00435553544f4d0000"
        , {'_sT': 0, 'tchr': 564, 'tchr_call': 588, 'tclabel0': 736, 'tclabel1': 760, 'tclabel2': 780, 'tclabel3': 800, 'tclabel4': 820, 'tclabel5': 840, 'tclabel6': 860, 'tclabel7': 880, 'tcxml0': 748, 'tcxml1': 772, 'tcxml2': 792, 'tcxml3': 808, 'tcxml4': 828, 'tcxml5': 848, 'tcxml6': 868, 'tcxml7': 888, 'tedit': 446, 'tedit_next': 454, 'tground': 900, 'tlabel': 2356, 'tload': 620, 'tload_call': 640, 'tload_next': 662, 'tm_copy': 520, 'tm_custom': 540, 'tm_go': 542, 'tmine': 458, 'tpal': 948, 'tpost': 424, 'tpost_call': 542, 'tpost_next': 442, 'treg': 0, 'treg_c0': 60, 'treg_c1': 92, 'treg_c2': 124, 'treg_c3': 156, 'treg_c4': 188, 'treg_c5': 220, 'treg_c6': 252, 'treg_c7': 284, 'treg_call': 28, 'treg_next': 294, 'tsave': 666, 'tsave_call': 686, 'tsave_next': 708, 'tstore': 298, 'tstore_c0': 322, 'tstore_c1': 334, 'tstore_c2': 348, 'tstore_c3': 360, 'tstore_c4': 372, 'tstore_c5': 384, 'tstore_c6': 398, 'tstore_c7': 412, 'tstore_call': 308, 'tstore_next': 420, 'tv0': 2372, 'tv1': 2380, 'tv10': 2468, 'tv11': 2476, 'tv2': 2388, 'tv3': 2396, 'tv4': 2408, 'tv5': 2420, 'tv6': 2432, 'tv7': 2440, 'tv8': 2448, 'tv9': 2456, 'tvalues': 2308, 'txml': 2364}),
    'mk2_osdsync': (
        "2de9f04f8a4607465ff00008dff8a8b03c6800f00af87c6800f007f8b8f1000f01d0bff34f8fbde8f08f00b5dff88cc0"
        "002505f1ce064ff4207006fb00f6264405f1020000f01f015fea50195fea8909c646002248f64203b2f10b00b0f5957f"
        "08d20bebc00050f80900c840c00718bf4ff6ff7336f81200baf1000f03d1984207d1002301e0984203d026f8123008f1"
        "01080132b2f5a07fdcd3c64508d026f01f0006f52072ccf8000020309042fad30135222dbdd300bd60b2062468ef00e0"
        , {'os_bit': 116, 'os_clean': 166, 'os_done': 38, 'os_layer': 42, 'os_next': 146, 'os_put': 138, 'os_px': 84, 'os_row': 50, 'os_rowdone': 176, 'os_show': 134, 'osd_sync': 0}),
    'mk2_osdsync10': (
        "2de9f04f8a460468456820b4dff8d0b0344abaf1000f0dd033490b68dff8ccc0634504d18f88cb8847ea034700e0304f"
        "176002e0176807b92d4f5ff0000800f00af810bc00f007f8b8f1000f01d0bff34f8fbde8f08f00b5dff898c0002505f1"
        "ce064ff4207006fb00f6264405f1020000f01f015fea50195fea8909c6460022bbb2b2f10b00b0f5957f07d20bebc000"
        "50f80900c840c00718bf3b0c36f81200baf1000f03d1984207d1002301e0984203d026f8123008f101080132b2f5a07f"
        "ded3c64508d026f01f0006f52072ccf8000020309042fad30135222dbfd300bda8b2062418ae0624e0da0624314f4854"
        "4288ffff68ef00e0"
        , {'os_bit': 156, 'os_clean': 206, 'os_done': 82, 'os_go': 58, 'os_have': 48, 'os_layer': 86, 'os_next': 186, 'os_old': 52, 'os_put': 178, 'os_px': 128, 'os_row': 94, 'os_rowdone': 216, 'os_show': 174, 'os_stock': 46, 'osd_sync': 0}),
}
# END FROZEN_MK2

VERBOSE = False
REASSEMBLE = False
_REGEN = {}


def vprint(msg):
    if VERBOSE:
        print(f"           {msg}")


def m2(va):
    """The MK2 address of a micro address. Unknown means a bug in this file."""
    if va not in MK2:
        raise SystemExit(f"internal error: no MK2 address for micro {va:#x}")
    return MK2[va]


def mk2_hooks():
    """pm.HOOKS with every code address moved to the MK2. Field offsets,
    stack slots and CC numbers are the same on both modules."""
    out = []
    for label, hook, ret, vslot, arms in pm.HOOKS:
        new_arms = []
        for cc, kind, arg in arms:
            if kind in ("jump", "enum", "jbool", "stop"):
                arg = m2(arg)                  # a case address, not an offset
            if cc in DISABLED_CCS:
                # The arm must STAY: the frozen machine code is laid out for
                # exactly this list, and dropping one shifts every branch
                # after it onto the wrong arm. Point it at the stock default
                # instead -- exactly where an unknown CC goes. Only a branching
                # arm can be redirected this way.
                if kind not in ("jump", "enum", "jbool", "stop"):
                    raise SystemExit(f"internal error: CC{cc} cannot be disabled")
                arg = m2(ret)
            new_arms.append((cc, kind, arg))
        out.append((label, m2(hook), m2(ret), vslot, new_arms))
    return out


def check_dispatch(code, arms, label):
    """The frozen code's CC compares must be exactly this hook's arm list, in
    order. If they are not, its branch fix-ups land on the wrong arms."""
    found, o = [], 0
    while o + 6 <= len(code):
        hw, = struct.unpack_from("<H", code, o)
        if hw & 0xff00 != 0x2b00:              # cmp r3, #imm8
            break
        found.append(hw & 0xff)
        o += 6                                 # cmp (2) + beq.w (4)
    want = [cc for cc, _, _ in arms]
    if found != want:
        pm.refuse(f"The {label} hook's frozen code does not match its CC list.",
                  f"code compares {found}", f"list has      {want}")


def word(d, va):
    return struct.unpack_from("<I", d, va - BASE)[0]


def guard_word(d, va, want, what):
    got = word(d, va)
    if got != want:
        pm.refuse(f"The {what} at {va:#x} is not what it should be.",
                  f"found {got:#010x}, expected {want:#010x}")
    vprint(f"{what:24} {va:#x} = {got:#010x}")


def guard_cstr(d, va, want, what):
    o = va - BASE
    got = bytes(d[o:o + len(want) + 1])
    if got != want.encode() + b"\0":
        pm.refuse(f"The {what} at {va:#x} is not what it should be.",
                  f"found {got!r}, expected {want!r}")


def write_string(d, va, end, stock, new):
    guard_cstr(d, va, stock, "splash text")
    room = end - va - 1
    if len(new) > room:
        pm.refuse(f"{new!r} does not fit: {room} characters at most.")
    o = va - BASE
    d[o:end - BASE] = new.encode().ljust(end - va, b"\0")
    vprint(f"splash {va:#x} {stock!r} -> {new!r}")


# --- stage 2 machinery --------------------------------------------------------
def clang_asm(src):
    """Assemble one hook with clang (only under --reassemble)."""
    with tempfile.TemporaryDirectory() as td:
        s, o = os.path.join(td, "h.s"), os.path.join(td, "h.o")
        open(s, "w").write(src)
        cmd = ["clang", "-target", "thumbv7em-none-eabi", "-mcpu=cortex-m7",
               "-mfloat-abi=hard", "-c", "-o", o, s]
        if sys.platform == "darwin":
            cmd.insert(0, "xcrun")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            sys.stderr.write(src + "\n" + r.stderr)
            raise SystemExit("assembly failed")
        elf = open(o, "rb").read()
        code, syms = pm.parse_elf32(elf)
    # No relocations, ever. The hooks are placed by hand and nothing applies
    # an ELF relocation, so one left in the object is a branch or a word that
    # silently keeps its placeholder (see GATE_SRC: that is how cc3 hung).
    shoff, = struct.unpack_from("<I", elf, 0x20)
    shent, shnum = struct.unpack_from("<HH", elf, 0x2e)
    for i in range(shnum):
        typ, = struct.unpack_from("<I", elf, shoff + i * shent + 4)
        size, = struct.unpack_from("<I", elf, shoff + i * shent + 20)
        if typ in (4, 9) and size:            # SHT_RELA, SHT_REL
            sys.stderr.write(src)
            raise SystemExit("assembly left a relocation: branch to a local label")
    return code, {k: v for k, v in syms.items() if not k.startswith("$")}


def mk2_assemble(key, src):
    """Stand-in for pm.assemble while stage 2 builds: the MK2's own frozen
    blobs, keyed apart from the micro's, or clang under --reassemble."""
    k = f"mk2_{key}"
    if REASSEMBLE:
        code, syms = clang_asm(src)
        if FROZEN_MK2.get(k) != (code.hex(), syms):
            _REGEN[k] = (code.hex(), syms)
        else:
            print(f"  reassembled {k:12} matches frozen blob ({len(code)} bytes)")
        return code, syms
    if k not in FROZEN_MK2:
        sys.exit(f"no frozen MK2 blob for {k!r}; rerun with --reassemble")
    blob, syms = FROZEN_MK2[k]
    return bytes.fromhex(blob), dict(syms)


def guard_bytes(d, va, want_hex, what):
    got = bytes(d[va - BASE:va - BASE + len(want_hex) // 2])
    if got.hex() != want_hex:
        pm.refuse(f"The code at {va:#x} is not what it should be ({what}).",
                  f"found {got.hex()}", f"expected {want_hex}")
    vprint(f"{what}")


def check_stage2_ram(d):
    """Every byte stage 2 writes must sit above the main stack and below the
    uncached pool, and the pool must be exactly the twelve requests above."""
    callers = sorted(BASE + o for o in range(0, STOCK_SIZE - 4, 2)
                     if (lambda hw1, hw2: hw1 & 0xf800 == 0xf000
                         and hw2 & 0xd000 in (0xd000, 0x9000))(
                             *struct.unpack_from("<HH", d, o))
                     and pm.branch_target(d, BASE + o) == POOL_ALLOC)
    if callers != sorted(POOL_CALLS):
        pm.refuse("The uncached pool has callers the patcher has not accounted for.",
                  f"found {[hex(c) for c in callers]}")
    # Every range the micro patcher itself declares (2.3.10's included, so the
    # layout is proved for what is still to come), after RAM_DELTA.
    ranges = pm.patch_ram_ranges()
    if HEAP_HI >= STACK_TOP:
        pm.refuse("The heap ends above the stack.")
    for what, lo, hi in ranges:
        if lo < STACK_TOP or hi > POOL_FLOOR:
            pm.refuse(f"Patch RAM ({what}, {lo:#x}-{hi:#x}) is outside "
                      f"{STACK_TOP:#x}-{POOL_FLOOR:#x}.")
    rs = sorted(ranges, key=lambda r: r[1])
    for (w1, _, h1), (w2, l2, _) in zip(rs, rs[1:]):
        if l2 < h1:
            pm.refuse(f"Patch RAM overlaps: {w1} and {w2}.")
    vprint(f"patch RAM {rs[0][1]:#x}-{rs[-1][2]:#x}, stack top {STACK_TOP:#x}, "
           f"pool floor {POOL_FLOOR:#x}")


MICRO_ONLY = {   # values that must never appear in an MK2 hook
    0x24022978: "micro MANAGER", 0x2402c978: "micro SCAN_LO",
    0x2402cd78: "micro SCAN_HI", 0x2406a620: "micro AUTO_RAM",
    0x00028cc0: "micro on/off offset", 0x080bb220: "micro EQ handler",
    0x080ba794: "micro EQ designer", 0x080ba8d8: "micro EQ designer",
    0x080bab98: "micro EQ designer", 0x080baf5c: "micro EQ designer",
    0x080bae18: "micro EQ designer", 0x080937f4: "micro set-parameter",
    0x080950c0: "micro post thunk", 0x080b9b04: "micro compressor DSP",
}


def check_no_micro_values(code, what):
    """Refuse a hook that still carries a micro address: as a literal word,
    a movw/movt pair, or a Thumb pointer."""
    vals = set()
    for o in range(0, len(code) - 3, 2):
        w, = struct.unpack_from("<I", code, o)
        vals.update((w, w & ~1))
    last = {}
    for o in range(0, len(code) - 3, 2):
        hw1, hw2 = struct.unpack_from("<HH", code, o)
        if hw1 & 0xfbf0 in (0xf240, 0xf2c0) and not hw2 & 0x8000:
            imm = ((hw1 & 0xf) << 12) | ((hw1 >> 10 & 1) << 11) \
                | ((hw2 >> 12 & 7) << 8) | (hw2 & 0xff)
            r = (hw2 >> 8) & 0xf
            if hw1 & 0xfbf0 == 0xf240:
                last[r] = imm
            elif r in last:
                vals.add((imm << 16) | last[r])
    bad = sorted(v for v in vals if v in MICRO_ONLY)
    if bad:
        pm.refuse(f"The {what} hook still carries micro values.",
                  *(f"{v:#010x}  {MICRO_ONLY[v]}" for v in bad))


def stage2_guards(d):
    for name, val in STAGE2.items():           # before any check reads them
        setattr(pm, name, val)
    for va, raw, what in STAGE2_GUARDS:
        guard_bytes(d, va, raw, what)
    post = STAGE2["MIDI_POST_CALL"]
    if bytes(d[post - BASE:post - BASE + 4]) != pm.enc_b_bl(post, STAGE2["MIDI_POST_FN"], True):
        pm.refuse(f"The MIDI post call at {post:#x} is not what it should be.")
    dsp = STAGE2["COMP_DSP_CALL"]
    if bytes(d[dsp - BASE:dsp - BASE + 4]) != pm.enc_b_bl(dsp, STAGE2["COMP_DSP_FN"], True):
        pm.refuse(f"The compressor call at {dsp:#x} is not what it should be.")
    if word(d, STAGE2["EQ_VT_HANDLER"]) != STAGE2["EQ_HANDLER"] | 1:
        pm.refuse("The EQ vtable's handler slot is not what it should be.")
    # The EQ ctor's `ldr r5, [pc, #0x1b4]` at 0x080ba756 loads the vtable it
    # stores at 0x080ba776 from the literal at 0x080ba90c.
    guard_bytes(d, 0x080ba756, "6d4d", "the EQ ctor loads its vtable")
    if word(d, 0x080ba90c) != STAGE2["EQ_VTABLE"]:
        pm.refuse("The EQ constructor does not store the expected vtable.")
    check_stage2_ram(d)


def stage2(d, gate=True, comp=False):
    """Hooks C (delay switches), D (compressor CCs), E (compressor DSP),
    F (EQ CCs), G (EQ DSP) and the type gate, chained at the post call
    exactly as the micro chains them: gate -> F -> D -> C -> stock post.
    gate=False when stage 3 follows: Keep CCs' pmidi is the micro's gate.
    comp (2.3.10, cc13): D is the auto-makeup-table variant (Da), and gate
    Dg sits between F and D, as the micro's --comp-types build has them.
    Returns hook E's origin, which the Character's ncomp takes over."""
    for name, val in STAGE2.items():
        if getattr(pm, name) != val:
            raise SystemExit(f"internal error: {name} was not set before stage 2")
    saved, pm.assemble = pm.assemble, mk2_assemble
    try:
        built = []

        def put(code, what):
            check_no_micro_values(code, what)
            org = pm._append(d, bytearray(code))
            built.append((what, org, len(code)))
            vprint(f"{what:18} {len(code):5} bytes at {org:#010x}")
            return org

        hook_c = put(pm.build_midi_hook(BASE + len(d)), "C delay switches")
        hook_d = put(pm.build_comp_hook(BASE + len(d), hook_c, full_range=True, auto_table=comp),
                     "D compressor CCs")
        org_e = put(pm.build_comp_dsp_hook(BASE + len(d)), "E compressor DSP")
        eq_next = hook_d
        if comp:
            eq_next = put(pm.build_comp_gate_hook(BASE + len(d), hook_d, hook_c), "Dg Type gate")
        hook_f = put(pm.build_eq_midi_hook(BASE + len(d), eq_next), "F EQ CCs")
        org_g = put(pm.build_eq_dsp_hook(BASE + len(d)), "G EQ DSP")
        org_t = hook_f
        if gate:
            org_t = BASE + len(d)
            src = GATE_SRC.format(type=pm.MSG_TYPE_SP)
            code, syms = mk2_assemble("gateT", src)
            code = bytearray(code)
            code[syms["tcc"]:syms["tcc"] + 4] = pm.enc_b_bl(org_t + syms["tcc"], hook_f, False)
            code[syms["tstock"]:syms["tstock"] + 4] = pm.enc_b_bl(
                org_t + syms["tstock"], pm.MIDI_POST_FN, False)
            put(bytes(code), "T type gate")
    finally:
        pm.assemble = saved
    # Install: three stock words change, nothing else. (Under --reassemble
    # too: stage 3 builds on top of it, and nothing is written in that case.)
    post, dsp = pm.MIDI_POST_CALL, pm.COMP_DSP_CALL
    d[post - BASE:post - BASE + 4] = pm.enc_b_bl(post, org_t, True)
    d[dsp - BASE:dsp - BASE + 4] = pm.enc_b_bl(dsp, org_e, True)
    struct.pack_into("<I", d, pm.EQ_VT_HANDLER - BASE, org_g | 1)
    return org_e


# --- stage 3 machinery --------------------------------------------------------
def _deep(v, f):
    if isinstance(v, bool) or not isinstance(v, (int, tuple, list, dict)):
        return v
    if isinstance(v, int):
        return f(v)
    if isinstance(v, dict):
        return {_deep(k, f): _deep(x, f) for k, x in v.items()}
    return type(v)(_deep(x, f) for x in v)


_MICRO_KEEP_GUARDS = pm.KEEP_GUARDS       # before any mapping: the micro addresses


def shift_patch_ram():
    """Move every patch-RAM constant in patch_micro.py by RAM_DELTA. Run once,
    before stage 2, so every hook sees the MK2 layout."""
    for name, val in list(vars(pm).items()):
        if name.isupper() and not name.startswith("FROZEN"):
            new = _deep(val, ram_shift)
            if new != val:
                setattr(pm, name, new)


def code_map(v):
    """A micro flash address as the MK2's, or refuse: nothing unmapped passes."""
    if v in CODE_MAP:
        return CODE_MAP[v]
    if BASE <= v < 0x080e3e90:               # inside the micro's stock image
        raise SystemExit(f"internal error: no MK2 address for micro {v:#x}")
    return v


def mk2_value(v):
    if v in CODE_MAP:
        return CODE_MAP[v]
    if v & 1 and v - 1 in CODE_MAP:            # a Thumb function pointer
        return CODE_MAP[v - 1] | 1
    return RAM_MAP.get(v, v)


def transpile(name):
    """Re-define one patch_micro function with every micro address literal in
    its source replaced by the MK2's. Unknown flash literals refuse."""
    import inspect, re, textwrap
    src = textwrap.dedent(inspect.getsource(getattr(pm, name)))

    def sub_flash(m):
        return f"{code_map(int(m.group(0), 16)):#010x}"

    def sub_ram(m):
        v = int(m.group(0), 16)
        if v in RAM_MAP:
            return f"{RAM_MAP[v]:#010x}"
        new = ram_shift(v)
        if new == v and v not in RAM_ALLOWED:
            raise SystemExit(f"internal error: {name} carries RAM address {v:#x}")
        return f"{new:#010x}"
    src = re.sub(r"\b0x0?80[0-9a-fA-F]{5}\b", sub_flash, src)
    src = re.sub(r"\b0x240[0-9a-fA-F]{5}\b", sub_ram, src)
    for old, new in FRAME_LITERALS.get(name, ()):
        if src.count(old) != 1:
            raise SystemExit(f"internal error: {name}: {old!r} is not there exactly once")
        src = src.replace(old, new)
    exec(compile(src, f"<mk2:{name}>", "exec"), vars(pm))


# Dispatcher-frame offsets written as plain numbers in patch_micro.py rather
# than from MSG_*_SP, so no constant override reaches them. Every [sp, #n] in
# the stage-3 sources was read; these are the only ones into the MIDI
# dispatcher's frame (the rest are the hooks' own frames, or the UI dispatcher's
# and the pad handlers', which are identical on the MK2). Missed in cc5's first
# build -- hook N read the channel, CC and value from the wrong words -- and
# caught in emulation, before any hardware saw it.
# Hook K's bar, landscape. The micro's kbar walks a 240x320 bitmap's 320
# rows and paints 4 pixels at the start of each: on the MK2's 320x240 layer
# that is 80 rows past the end of the frame (cc6 reboot). This one checks the
# layer is 320x240 and paints a BAR_W-pixel bar, BAR_H rows high, from
# (BAR_X0, BAR_Y0): in the black band along the top, which on the MK2 holds
# only the bar counter at its left (cc10, asked for on hardware; cc8 and cc9
# had it full width on the bottom rows). Level, peak and the 70% / 90% colour
# steps are scaled to BAR_W. Then the rows are cleaned from the D-cache.
BAR_X0, BAR_W, BAR_Y0, BAR_H = 108, 212, 8, 4
KBAR_MICRO = """kbar:                               /* r7 = bitmap, r4 level, r5 peak */
    ldr     r0, [r7]
    cbz     r0, kbar_ret
    ldrh    r1, [r7, #4]
    lsls    r1, r1, #1              /* stride in bytes */
    movs    r2, #0
kbar_loop:"""
KBAR_MK2 = f"""kbar:                               /* r7 = layer, r4 level, r5 peak */
    ldr     r0, [r7]
    cmp     r0, #0                  /* (cbz: kbar_ret is out of its reach) */
    beq     kbar_ret
    lsls    r1, r0, #31
    bne     kbar_ret                /* odd address: not a frame */
    ldrh    r1, [r7, #4]
    cmp.w   r1, #320
    bne     kbar_ret
    ldrh    r1, [r7, #6]
    cmp     r1, #240
    bne     kbar_ret
    movw    r1, #{BAR_Y0 * 640 + BAR_X0 * 2}
    add     r0, r0, r1              /* the bar's first pixel */
    movs    r2, #0
kbar_loop:"""
KSCALE_MICRO = """    lsls    r4, r4, #5              /* x 320 / 1000 = x 32 / 100 */
    lsls    r5, r5, #5
    movs    r6, #100
    udiv    r4, r4, r6              /* bar length out of 320 px: full width */
    udiv    r5, r5, r6
"""
KSCALE_MK2 = f"""    movs    r6, #{BAR_W}
    mul     r4, r4, r6              /* per mille -> pixels of the bar */
    mul     r5, r5, r6
    movw    r6, #1000
    udiv    r4, r4, r6
    udiv    r5, r5, r6
"""
KSTEPS_MICRO = ("    cmp     r2, #288                /* 90% of 320 */",
                "    cmp     r2, #224                /* 70% of 320 */")
KSTEPS_MK2 = (f"    cmp     r2, #{BAR_W * 9 // 10}                /* 90% of the bar */",
              f"    cmp     r2, #{BAR_W * 7 // 10}                /* 70% of the bar */")

KPUT_MICRO = """kc_put:
    mul     r6, r2, r1
    add     r6, r6, r0
    strh    r3, [r6]
    strh    r3, [r6, #2]
    strh    r3, [r6, #4]
    strh    r3, [r6, #6]
    ldr     r12, =0xe000ef68        /* DCCMVAC: clean the line to RAM */
    str     r6, [r12]
    adds    r2, #1
    cmp     r2, #320
    blo     kbar_loop
kbar_ret:
    bx      lr
"""
KPUT_MK2 = f"""kc_put:
    add.w   r6, r0, r2, lsl #1
    strh    r3, [r6]
    strh.w  r3, [r6, #{640 * 1}]
    strh.w  r3, [r6, #{640 * 2}]
    strh.w  r3, [r6, #{640 * 3}]
    adds    r2, #1
    cmp.w   r2, #{BAR_W}
    blo     kbar_loop
    ldr     r12, =0xe000ef68        /* DCCMVAC: clean the bar's rows to RAM */
    bic     r6, r0, #31
    addw    r2, r0, #{640 * (BAR_H - 1) + 2 * BAR_W}
kc_clean:
    str     r6, [r12]
    adds    r6, #32
    cmp     r6, r2
    blo     kc_clean
kbar_ret:
    bx      lr
"""
assert BAR_H == 4 and BAR_X0 + BAR_W <= 320 and BAR_Y0 + BAR_H <= 240

FRAME_LITERALS = {
    "build_character_hook": (
        ("ldr     r0, [sp, #224]", f"ldr     r0, [sp, #{96 + 0x48}]"),   # channel
        ("ldr     r1, [sp, #228]", f"ldr     r1, [sp, #{96 + 0x4c}]"),   # CC number
        ("ldr     r2, [sp, #232]          /* 96 + 0x88: value",
         f"ldr     r2, [sp, #{96 + 0x50}]          /* 96 + 0x50: value"),
        ("str     r0, [sp, #232]", f"str     r0, [sp, #{96 + 0x50}]"),   # (2.3.10 compressor types)
    ),
    "build_cpu_meter_hook": ((KBAR_MICRO, KBAR_MK2), (KPUT_MICRO, KPUT_MK2), (KSCALE_MICRO, KSCALE_MK2),
                             *zip(KSTEPS_MICRO, KSTEPS_MK2)),
}


def _reloc_pair(data, sec, lo, hi, old, new):
    hw1, hw2 = struct.unpack_from("<HH", data, lo)
    ht1, ht2 = struct.unpack_from("<HH", data, hi)
    if (hw1 & 0xfbf0, ht1 & 0xfbf0) != (0xf240, 0xf2c0) or \
            (pm._thm_imm16(ht1, ht2) << 16 | pm._thm_imm16(hw1, hw2)) != old or \
            (hw2 >> 8) & 0xf != (ht2 >> 8) & 0xf:
        pm.refuse(f"The Character object at {sec}+{lo:#x} is not what it should be.")
    struct.pack_into("<HH", data, lo, *pm._thm_put_imm16(hw1, hw2, new & 0xffff))
    struct.pack_into("<HH", data, hi, *pm._thm_put_imm16(ht1, ht2, new >> 16))


def chr10_value(old):
    """Where a chr10 address lives on the MK2, or refuse."""
    if old in RAM_SAME:
        return old
    if old in CHR_FLASH:                            # the font - 0x100, the LFO labels
        return CHR_FLASH[old]
    if ram_shift(old) != old:
        return ram_shift(old)
    if old in RAM_MAP:
        return RAM_MAP[old]
    new = mk2_value(old)
    if new == old:
        raise SystemExit(f"internal error: chr10 address {old:#x} has no MK2 place")
    return new


def relocated_chr(obj, key="chr"):
    """The Character object with its address pairs and its work-area word
    moved to the MK2 layout, and the pop-up drawn landscape. Every old value
    is checked first."""
    secs, exports = obj
    secs = [list(s) for s in secs]
    by_name = {s[0]: s for s in secs}
    if key == "chr":
        table = [(sec, lo, hi, old, CHR_FLASH[old] if old in CHR_FLASH else ram_shift(old))
                 for sec, lo, hi, old in CHR_RELOC]
        mask = ram_shift(0x24069860)
    elif key == "chr10":
        table = [(sec, lo, hi, old, chr10_value(old)) for sec, lo, hi, old in CHR10_RELOC]
        mask = ram_shift(0x24069418) + 0x490      # chr10's osd_sync: base + 0x490
        theme_table_to_ram(by_name)
    else:
        raise SystemExit(f"internal error: no MK2 relocation for C object {key!r}")
    for sec, lo, hi, old, new in table:
        if new == old and old not in RAM_SAME:
            raise SystemExit(f"internal error: {old:#x} would not move")
        data = bytearray.fromhex(by_name[sec][2])
        _reloc_pair(data, sec, lo, hi, old, new)
        by_name[sec][2] = data.hex()
    landscape_chr(by_name, mask, "osdsync" if key == "chr" else "osdsync10")
    wb = by_name[".rodata.chr_work_base"]
    data = bytearray.fromhex(wb[2])
    old, = struct.unpack_from("<I", data, 0)
    if ram_shift(old) != pm.CHR_WORK_DEFAULT or old == pm.CHR_WORK_DEFAULT:
        pm.refuse("The Character work-area word is not what the patcher expects.")
    struct.pack_into("<I", data, 0, pm.CHR_WORK_DEFAULT)
    wb[2] = data.hex()
    return [tuple(s) for s in secs], exports


# The pop-up, landscape. chr_osd_tick ORs its two text lines into a 1-bit
# mask (298 entries of 64 bits, 38 used: entry = x, bit = y; line 1 in bits
# 0..17, line 2 in 18..37) and hands both layers to osd_sync, which on the
# micro walks them as 240x320 portrait -- and chr_osd_tick only gets that far
# when a layer IS 240x320, so on the MK2 the pop-up never drew at all. Its two
# size checks become 320x240 (the same instructions, registers swapped:
# cmp r2,#320 does not fit 16 bits), and osd_sync is replaced by this:
#   - the box runs edge to edge (x 0..319) along the bottom of the screen
#     (cc12; the CPU bar has the top band since cc10);
#   - mask rows 2..35 only: 2 pixels above line 1's capitals, 2 between
#     the lines (the mask's own), 2 below line 2's descenders -- as asked
#     for on hardware after cc11 (cc9..cc11 had padding, a screen-door
#     background and a black outline; all dropped: the door read badly);
#   - white text on 0x8842; on hide, every pixel still showing the box goes
#     back to 0, as on the micro.
OSD_K0, OSD_H = 2, 34                       # mask rows 2..35
OSD_Y0 = 240 - OSD_H                        # rows 206..239
THEME_OSD_MAGIC = pm.THEME_OSD_MAGIC
OSD_SYNC_MK2 = f"""
    .syntax unified
    .thumb
    .text
    .global osd_sync
    .type   osd_sync, %function
osd_sync:                           /* r0 = the two layer pointers, r1 = show */
    push    {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}
    mov     r10, r1
    ldr     r4, [r0]
    ldr     r5, [r0, #4]
    push    {{r5}}                    /* layer B, for the second pass */
    ldr     r11, =MASK
    ldr     r2, =STATE              /* the colours last drawn: text << 16 | box */
    cmp     r10, #0
    beq     os_old
    ldr     r1, =THO                /* cc16: the theme's box and text, as 2.3.10's */
    ldr     r3, [r1]
    ldr     r12, =0x{THEME_OSD_MAGIC:08x}
    cmp     r3, r12
    bne     os_stock
    ldrh    r7, [r1, #4]            /* box */
    ldrh    r3, [r1, #6]            /* text */
    orr.w   r7, r7, r3, lsl #16
    b       os_have
os_stock:
    ldr     r7, =0xffff8842
os_have:
    str     r7, [r2]
    b       os_go
os_old:                             /* hide: erase in the colours that were drawn */
    ldr     r7, [r2]
    cbnz    r7, os_go
    ldr     r7, =0xffff8842
os_go:
    movs    r8, #0                  /* pixels changed */
    bl      os_layer
    pop     {{r4}}
    bl      os_layer
    cmp     r8, #0
    beq     os_done
    dsb
os_done:
    pop     {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}

os_layer:                           /* r4 = frame, r7 = text << 16 | box */
    push    {{lr}}
    ldr     r12, =0xe000ef68        /* DCCMVAC */
    movs    r5, #0                  /* y in the box */
os_row:
    add.w   r6, r5, #{OSD_Y0}
    mov.w   r0, #640
    mul     r6, r6, r0
    add     r6, r6, r4              /* x = 0 of this row */
    add.w   r0, r5, #{OSD_K0}       /* the mask row */
    and     r1, r0, #31
    lsrs    r9, r0, #5
    lsls    r9, r9, #2              /* which word of the entry */
    mov     lr, r8                  /* changed before this row */
    movs    r2, #0                  /* x */
os_px:
    uxth    r3, r7                  /* the box */
    subs    r0, r2, #11             /* the mask's x 0 is screen x 11 */
    cmp.w   r0, #298
    bhs     os_bit
    add.w   r0, r11, r0, lsl #3
    ldr     r0, [r0, r9]
    lsrs    r0, r0, r1
    lsls    r0, r0, #31
    it      ne
    lsrne   r3, r7, #16             /* the text */
os_bit:
    ldrh.w  r0, [r6, r2, lsl #1]
    cmp     r10, #0
    bne     os_show
    cmp     r0, r3                  /* hide: only what is still the box */
    bne     os_next
    movs    r3, #0
    b       os_put
os_show:
    cmp     r0, r3
    beq     os_next
os_put:
    strh.w  r3, [r6, r2, lsl #1]
    add     r8, r8, #1
os_next:
    adds    r2, #1
    cmp.w   r2, #320
    blo     os_px
    cmp     lr, r8
    beq     os_rowdone
    bic     r0, r6, #31             /* clean the row's 640 bytes */
    add.w   r2, r6, #640
os_clean:
    str     r0, [r12]
    adds    r0, #32
    cmp     r0, r2
    blo     os_clean
os_rowdone:
    adds    r5, #1
    cmp     r5, #{OSD_H}
    blo     os_row
    pop     {{pc}}
    .ltorg
"""
assert OSD_K0 + OSD_H <= 38 and OSD_Y0 + OSD_H == 240
OSD_GUARD_MICRO = "f02a08bfb1f5a07f"    # cmp r2,#0xf0 ; it eq ; cmpeq.w r1,#0x140
OSD_GUARD_MK2 = "f02908bfb2f5a07f"      # cmp r1,#0xf0 ; it eq ; cmpeq.w r2,#0x140


def landscape_chr(by_name, mask, blob):
    """osd_sync replaced, chr_osd_tick's two size checks (layer A, layer B)
    made 320x240: h == 240 and w == 320."""
    tick = by_name[".text.chr_osd_tick"]
    data = bytearray.fromhex(tick[2])
    pat = bytes.fromhex(OSD_GUARD_MICRO)
    hits = [o for o in range(0, len(data) - 7, 2) if data[o:o + 8] == pat]
    if len(hits) != 2:
        pm.refuse("The pop-up's size check is not what the patcher expects.")
    for off in hits:
        data[off:off + 8] = bytes.fromhex(OSD_GUARD_MK2)
    tick[2] = data.hex()
    src = (OSD_SYNC_MK2.replace("=MASK", f"={mask:#010x}")
           .replace("=STATE", f"={ram_shift(0x24069418):#010x}")
           .replace("=THO", f"={pm.THEME_OSD_RAM:#010x}"))
    code, syms = mk2_assemble(blob, src)
    if syms.get("osd_sync") != 0:
        raise SystemExit("internal error: osd_sync must start its blob")
    by_name[".text.osd_sync"][2] = code.hex()


# Built-in themes for the MK2 (cc17), in place of 2.3.10's Amber, Stage,
# Contrast, Phosphor and Synthwave (still there as theme.tml files for
# Custom). A built-in theme is a whole palette, 34 entries, in chr10's
# .rodata.thm_tab (5 x 34 words, B G R A); thm_fam says which theme-file
# colour each entry takes in Custom, so a palette is built from the same 20
# colours a theme.tml names -- and, unlike a file, any single entry can be
# set on its own (THEME_ENTRY_SET). Colours by the MK2 map worked out on
# hardware with two diagnostic themes (2026-10-29): grey1 the lines between
# cells, background the waveform's ground, green the selected Settings row.
THEME_ROLES = ("background", "black", "panel", "grey1", "cell", "grey3", "grey4", "grey5",
               "text", "text-bright", "selection", "accent", "accent-dark", "red",
               "red-dark", "green", "yellow", "yellow-dark", "teal", "purple")
_NORTON = {"background": "000000", "black": "000000", "panel": "0000AA", "grey1": "55FFFF",
           "cell": "0000AA", "grey3": "FFFF55", "grey4": "55FFFF", "grey5": "AAAAAA",
           "text": "FFFFFF", "text-bright": "FFFFFF", "selection": "000055", "accent": "00AAAA",
           "accent-dark": "005555", "red": "000000", "red-dark": "AA0000", "green": "00AAAA",
           "yellow": "FFFF55", "yellow-dark": "AA5500", "teal": "55FFFF", "purple": "FFFF55"}
_VOLKOV = dict(_NORTON, **{"selection": "00AAAA", "accent": "FFFF55"})
_MIDNIGHT = dict(_NORTON, **{"cell": "000055", "panel": "000055", "selection": "0000AA", "grey1": "0000AA"})
_PACMAN = dict(_MIDNIGHT)            # cc21: dividers bright blue too, as asked; the rest to follow a DIAG photo
_DIAG = dict(_PACMAN)
# The diagnostic (cc22): Pacman, with each entry still in question its own
# colour -- the ones a hardware photo of cc18's DIAG could not tell apart
# (cc18's split reused red, orange and yellow across families).
THEME_SPLIT = {2: "FF0000", 5: "FF80FF", 12: "AA0000",          # red, pink, dark red
               7: "FF8000", 8: "804000", 11: "8080FF",          # orange, brown, periwinkle
               10: "FFFF00", 13: "FF00FF", 20: "00FF00",        # yellow, magenta, green
               9: "00FFFF", 24: "808080", 32: "C080FF"}         # cyan, grey, lavender
# Single entries, from DIAG photos (2026-10-30): 32 the loop frame, the
# selected tab and the mixer's level bars; 9 the loop's Str/Len text; 10 the
# waveform and a modulation slot in use; 11 the mixer's unmuted pads (and,
# until cc23, the CPU bar -- moved to 18 so the two can differ).
LOOP_FRAME, LOOP_TEXT, MOD_USED, MIXER_PAD = 32, 9, 10, 11
BUILTIN_THEMES = (("NORTON", _NORTON, {LOOP_FRAME: "FFFF55"}),
                  ("VOLKOV", _VOLKOV, {LOOP_FRAME: "0000AA", LOOP_TEXT: "FFFFFF"}),
                  ("PACMAN", _PACMAN, {LOOP_FRAME: "FFFF55", MOD_USED: "FFFF55", MIXER_PAD: "0000AA"}),
                  ("MIDNIGHT", _MIDNIGHT, {LOOP_FRAME: "FFFF55", MIXER_PAD: "0000AA"}),
                  ("DIAG", _DIAG, THEME_SPLIT))
THM_TAB_HEAD = "000000003b4c5aff0c1216ff"      # Amber's first three entries, as 2.3.10 has them
# cc17b: the new themes come IN ADDITION to 2.3.10's five. The C knows seven
# values (Stock, five table rows, Custom = 6) in a dozen compares; rather than
# touch those, the Theme row has twelve values and hook T maps them: Stock
# -> 0, Custom (11) -> 6, any of the ten tables -> copy that palette (136
# bytes, from T's own copy of all ten) into THEME_PAL_RAM and post 1. The C's
# two references to its table (thm_post, chr_osd_tick) are relinked to
# THEME_PAL_RAM, so row 0 is always the theme just chosen -- including when
# Custom starts its theme.tml from "the theme on screen".
THEME_PAL_RAM = 0x24070a80           # above patch RAM, below the uncached pool (POOL_FLOOR)
assert THEME_PAL_RAM + 136 <= POOL_FLOOR


def theme_palette(fam, colours, entry_set):
    words = []
    for i in range(34):
        if i == 0:
            words.append(0)                  # entry 0 stays clear: the screen's own ground
            continue
        h = entry_set.get(i) or colours[THEME_ROLES[fam[i]]]
        r, g, b = (int(h[j:j + 2], 16) for j in (0, 2, 4))
        words.append(0xff000000 | r << 16 | g << 8 | b)
    return words


def _theme_palettes():
    secs, _ = pm.c_thaw(pm.FROZEN_C["chr10"])
    by = {x[0]: x for x in secs}
    tab = bytes.fromhex(by[".rodata.thm_tab"][2])
    fam = bytes.fromhex(by[".rodata.thm_fam"][2])
    if len(tab) != 5 * 34 * 4 or tab[:12].hex() != THM_TAB_HEAD or len(fam) != 34:
        raise SystemExit("internal error: chr10's theme table is not what cc17 was built on")
    words = list(struct.unpack("<170I", tab))           # Amber, Stage, Contrast, Phosphor, Synthwave
    for _, c, e in BUILTIN_THEMES:
        words += theme_palette(fam, c, e)
    return words


THEME_PALETTES = _theme_palettes()                       # 10 x 34 words
THEME_COUNT = 1 + len(THEME_PALETTES) // 34 + 1          # Stock, the tables, Custom
# cc24: the gaps between cells are no palette entry at all: nothing is drawn
# there and entry 0 is clear, so the LTDC's background colour shows (BCCR,
# 0x5000102c, RGB888; stock initialises it black at 0x08042dc4). Hook T sets
# it with the theme, per Theme row value (Stock, five tables, Norton, Volkov,
# Pacman, Midnight, Diag, Custom).
LTDC_BCCR = 0x5000102c
THEME_GROUND = (0, 0, 0, 0, 0, 0, 0, 0, 0x0000aa, 0x0000aa, 0x00ff00, 0)
assert len(THEME_GROUND) == THEME_COUNT
THEME_MAP_MICRO = """    mov     r0, r3
tpost_call:"""
THEME_MAP_MK2 = f"""    mov     r0, r3                  /* cc17: the row's value -> the C's */
    cmp     r0, #{THEME_COUNT}
    it      hs
    movhs   r0, #0
    adr.w   r1, tground             /* cc24: the screen's ground, LTDC BCCR */
    ldr     r1, [r1, r0, lsl #2]
    ldr     r2, =0x{LTDC_BCCR:08x}
    str     r1, [r2]
    cbz     r0, tm_go               /* Stock */
    cmp     r0, #{THEME_COUNT - 1}
    beq     tm_custom
    subs    r1, r0, #1              /* a table: copy its palette to THEME_PAL_RAM */
    movs    r2, #136
    mul     r1, r1, r2
    adr.w   r2, tpal
    add     r1, r1, r2
    ldr     r2, =0x{THEME_PAL_RAM:08x}
    movs    r3, #34
tm_copy:
    ldr     r12, [r1], #4
    str     r12, [r2], #4
    subs    r3, #1
    bne     tm_copy
    dsb
    movs    r0, #1                  /* the C's table row 0 */
    b       tm_go
tm_custom:
    movs    r0, #6
tm_go:
tpost_call:"""
THEME_TVALUES_MICRO = """    .balign 4
tvalues:"""
THEME_TVALUES_MK2 = ("    .balign 4\ntground:\n"
                     + "    .word   " + ", ".join(f"0x{g:08x}" for g in THEME_GROUND) + "\n"
                     + "    .balign 4\ntpal:\n"
                     + "".join("    .word   " + ", ".join(f"0x{w:08x}" for w in THEME_PALETTES[i:i + 6]) + "\n"
                               for i in range(0, len(THEME_PALETTES), 6))
                     + "    .balign 4\ntvalues:")


FRAME_LITERALS["build_theme_hook"] = ((THEME_MAP_MICRO, THEME_MAP_MK2),
                                      (THEME_TVALUES_MICRO, THEME_TVALUES_MK2))


def theme_table_to_ram(by_name):
    """Point the C's three movw/movt pairs for .rodata.thm_tab at THEME_PAL_RAM."""
    names = [n for n in by_name]
    k = names.index(".rodata.thm_tab")
    n = 0
    for sec in (".text.thm_post", ".text.chr_osd_tick"):
        rel = by_name[sec][3]
        for i, (off, typ, ref) in enumerate(rel):
            if ref[0] == "sec" and ref[1] == k:
                if ref[2] != 0:
                    pm.refuse("The themes' table is reached with an offset; cc17 expects none.")
                rel[i] = (off, typ, ("ext", "thm_tab_ram"))
                n += 1
    if n != 6:     # thm_post's palette, chr_osd_tick's palette and its pop-up colours
        pm.refuse(f"The themes' table is referenced {n} times, not the 6 cc18 expects.")
    # cc21: the CPU bar follows every theme, not only Custom. chr_osd_tick keeps
    # stock's colours for THO roles 2-6 (bar, 70%, 90%, peak, ground) unless
    # the theme is Custom: `cmp r7, #7` decides; #2 hands those roles to the
    # palette for the tables too. And >90% takes red-dark (entry 12), as the
    # built-in themes paint red (entry 6) black.
    tick = by_name[".text.chr_osd_tick"]
    code = bytearray.fromhex(tick[2])
    if code[744:746] != b"\x07\x2f":
        pm.refuse("The pop-up colours' theme check is not what cc21 expects.")
    code[744:746] = b"\x00\x2f"            # cc22: #0, every role (box and text too, below)
    # cc22: the pop-up too -- `cmp r7, #2` kept roles 0-1 (box, text) stock
    # in every theme; #0 hands them over. The box takes the cells' colour
    # (entry 1), the text the text's (3).
    if code[754:756] != b"\x02\x2f":
        pm.refuse("The pop-up's own colour check is not what cc22 expects.")
    code[754:756] = b"\x00\x2f"
    tick[2] = code.hex()
    ent = by_name[".rodata.tho_entry"]
    if ent[2] != "02030b14060f0211050b0e0f06":
        pm.refuse("The pop-up colours' palette entries are not what cc21 expects.")
    ent[2] = "010312140c0f0211050b0e0f06"         # cc23: the bar from 18, not 11 (the mixer's pads)


def prepare_stage3():
    """Point patch_micro's stage-3 constants and functions at the MK2."""
    for name in STAGE3_GLOBALS:
        setattr(pm, name, _deep(getattr(pm, name), mk2_value))
    for name in ("SESSION_MGR", "SONG_STORE", "GLOBAL_STORE", "SESSION_DIRTY",
                 "PC_MANAGER", "PC_LIST", "PC_PENDING", "PC_CURRENT"):
        setattr(pm, name, RAM_MAP[getattr(pm, name)])
    if hasattr(pm, "DISPLAY_OBJ"):
        pm.DISPLAY_OBJ = RAM_MAP[pm.DISPLAY_OBJ]
    pm.SESSION_MGR_GUARDS = SESSION_MGR_GUARDS_MK2
    pm.CHR_SITE_CONTEXT = CHR_SITE_CONTEXT_MK2
    pm.CHR_EQ_HEAD = 0x28c84                       # literal at 0x080983fc
    pm.KEEP_GUARDS = tuple(
        (va, GUARD_BYTES_MK2.get(old, raw), what)
        for (va, raw, what), (old, _, _) in zip(pm.KEEP_GUARDS, _MICRO_KEEP_GUARDS))
    pm.CMP_GUARDS = CMP_GUARDS_MK2
    pm.THEME_GUARDS = THEME_GUARDS_MK2
    pm.THEME_CALLS = THEME_CALLS_MK2
    pm.DISPLAY_OBJ_LIT_VA = DISPLAY_OBJ_LIT_MK2
    pm.THEME_ROW_VA = SETTINGS_VA + 16 * THEME_TAB
    pm.THEME_VALUES = (("STOCK", "AMBER", "STAGE", "CONTRAST", "PHOSPHOR", "SYNTHWAVE")
                       + tuple(n for n, _, _ in BUILTIN_THEMES) + ("CUSTOM",))
    assert len(pm.THEME_VALUES) == THEME_COUNT
    pm.THEME_EXTERNS = dict(pm.THEME_EXTERNS, thm_tab_ram=THEME_PAL_RAM)
    pm.STOCK_SIZE = STOCK_SIZE                     # "is this stock?" checks
    for name in STAGE3_FUNCS:
        transpile(name)
    stock_c_object = pm.c_object
    pm.c_object = lambda key, path, defines=(): relocated_chr(stock_c_object(key, path, defines), key)


def theme_tab(d):
    """Name the fifth Tools tab; apply_theme has put the Theme row in it."""
    if word(d, TABS_VA + 4 * THEME_TAB) != TABS_EMPTY:
        pm.refuse("The fifth Tools tab is not free.")
    org = pm._append(d, bytearray(THEME_TAB_NAME.encode() + b"\0"))
    struct.pack_into("<I", d, TABS_VA + 4 * THEME_TAB - BASE, org)
    vprint(f"Tools tab 5 '{THEME_TAB_NAME}' at {org:#x}: {pm.THEME_ID:#x}")


def apply_settings_mk2(d, rows):
    """A fourth Tools tab, named TAB_NAME, holding the patch's rows."""
    t = SETTINGS_VA - BASE
    pages = [struct.unpack_from("<8H", d, t + 16 * p) for p in range(6)]
    for page, want in zip(pages, SETTINGS_STOCK + ((), (), ())):
        if page != tuple(want) + (0,) * (8 - len(want)):
            pm.refuse("The Settings screen's rows are not what they should be.")
    if word(d, 0x080799b0) != SETTINGS_VA or word(d, 0x080799b8) != TABS_VA:
        pm.refuse("The Settings page builder does not read the expected tables.")
    names = [word(d, TABS_VA + 4 * i) for i in range(6)]
    if names[3:] != [TABS_EMPTY] * 3 or d[TABS_EMPTY - BASE] != 0 or \
            0 in [d[n - BASE] for n in names[:3]]:
        pm.refuse("The Tools tab names are not what they should be.")
    if len(rows) > 4:
        pm.refuse("A Tools tab shows four rows; this build needs more.")
    org = pm._append(d, bytearray(TAB_NAME.encode() + b"\0"))
    struct.pack_into("<I", d, TABS_VA + 12 - BASE, org)
    struct.pack_into("<8H", d, t + 48, *rows, *([0] * (8 - len(rows))))
    vprint(f"Tools tab 4 '{TAB_NAME}' at {org:#x}: {', '.join(f'{r:#x}' for r in rows)}")


def stage3(d, upto="full", hook_e=None):
    """The 2.3.9-mod set, in the micro's own order (its main(), --v239), less
    Flip UI: the MK2 already flips its screen and touch natively.
    upto: "settings" stops after H/J/L/K, "character" after N (diagnostic
    builds for bisecting a hardware fault), "full" is everything."""
    saved, pm.assemble = pm.assemble, mk2_assemble
    try:
        pm.apply_program_change(d)
        rows = (pm.CLK_ID, 0x66) if upto != "full" else (pm.CLK_ID, 0x66, pm.OSD_ID, pm.KEEP_ID)
        apply_settings_mk2(d, rows)
        j_org, j_syms = pm.apply_clock_hold(d)
        l_org, l_syms = pm.apply_preset_bpm(d, j_org, j_syms)
        l_entries = (l_org + l_syms["lpost"], l_org + l_syms["ltick"],
                     l_org + l_syms["lblock"])
        pm.apply_cpu_meter(d, j_org, j_syms, chained=l_entries, row=False,
                           themed=(hook_e is not None))   # cc16: the bar's colours follow the theme
        if upto == "settings":
            return
        n_org, n_syms = pm.apply_character(d, pm.CHR_FEATURE_AUTO, comp=hook_e)
        if upto == "character":
            return
        pm.apply_osd(d, n_org, n_syms, j_org, j_syms, modes=True)
        pm.apply_keep_ccs(d, j_org, j_syms)
        if hook_e is not None:                     # 2.3.10: the micro's order, less T and R
            pm.apply_comp_type(d, n_org, n_syms)
            pm.apply_theme(d, n_org, n_syms)       # the themes and the saved master bus
            theme_tab(d)
            apply_clip_modes(d, n_org, n_syms)
    finally:
        pm.assemble = saved


# The compressor types' guards (pm.CMP_GUARDS) at their MK2 places, every
# byte read off the MK2 image and compared with the micro's by hand: the same
# instructions, except the global store's offset (SESSION_MGR + 0x7ed0, not
# + 0x7fd0), the literal offsets, and the literals themselves.
CMP_GUARDS_MK2 = (
    (0x080ba43c, "0368644a5b6d9342", "the compressor DSP's msg-override test"),
    (0x080ba5d0, "0d340a08", "the override slot's default (0x080a340d)"),
    (0x080ba456, "c18b3846", "the DSP's bus: ldrh r1, [r0, #0x1e]"),
    (0x080ba45c, "eff71cf8", "bl 0x080a9498, the descriptor"),
    (0x080ba462, "eaf791f8", "bl 0x080a4588, the frame count"),
    (0x080ba476, "eaf7dbf8", "bl 0x080a4630, the fetch"),
    (0x080ba4ee, "06f23440", "the compressor's gain ramp at +0x434"),
    (0x080ba514, "06f25440", "the limiter's gain ramp at +0x454"),
    (0x080a2a68, "037f53b943694ff07e510122", "the ramp's state byte at +0x1c"),
    (0x080a2940, "2de9f84fb3f10009", "the ramp's apply"),
    (0x0807f80e, "47f6d068", "handler B's global store: SessionMgr + 0x7ed0"),
    (0x0807f84a, "4246cc49cd48", "handler B's settings.tml arguments"),
    (0x0807fb80, "34710c08", "... the file name"),
    (0x0807fb84, "b8380224", "... the manager (0x240238b8)"),
    (0x080c7134, "73657474696e67732e746d6c00", "\"settings.tml\""),
)


# --- T: the themes (2.3.10's hook T, cc16) -----------------------------------------
# pm.apply_theme at the MK2's places. T also carries the saved master bus (the
# eight hidden rows S had in cc13-cc15), so S is gone. Every guard below was
# read off the MK2 image: the same bytes, but for three literals (the tml
# FIL = MANAGER - 8, the SD card object). The palette (34 ARGB8888 entries at
# 0x24000000, the CLUT DMA2D loads), its flash image and every UI-object
# offset the theme tick touches are identical. The Theme row gets a fifth
# Tools tab of its own.
THEME_GUARDS_MK2 = (
    (0x080e4b58, "000000005a5656ff141414fffcfcfcff", "the palette's flash image (Stock)"),
    (0x08043430, "00000024", "the CLUT load's palette address, 0x24000000"),
    (0x080433c6, "2123", "... its size, 0x21"),
    (0x08040e84, "c80d0024", "the UI task's UI-object pointer, 0x24000dc8"),
    (0x0805b8b8, "04f52076", "the renderer's widget root: UI object + 0x280"),
    (0x0807161e, "94f83820", "the dirty test reads the root's +0x38 ..."),
    (0x08071628, "94f83920", "... and +0x39"),
    (0x08061022, "94f83030", "the children draw skips only a hidden child (+0x30)"),
    (0x0806a2d4, "00b589b0adf804108df806200293", "the integer registrar"),
    (0x0808cc8e, "d4f8b422d4f8b012", "the file thread's buffer and its size: +0x2b4, +0x2b0"),
    (0x0808e598, "b03c0224", "the tml read's FIL pointer, 0x24023cb0 ..."),
    (0x0808e4c0, "b03c0224", "... and the tml write's"),
    (0x0808e4de, "5822", "the FIL cleared: 0x58 bytes"),
    (0x0808e4e8, "0122", "the tml read opens FA_READ"),
    (0x0808e446, "0a22", "the tml write opens FA_WRITE | FA_CREATE_ALWAYS"),
    (0x0808e41e, "d1f8f070", "the tml write's length: the printer's +0xf0 ..."),
    (0x0808e438, "d1f8d4b0", "... and its text, +0xd4"),
    (0x0808c5a4, "84b00024", "the SD card object, 0x2400b084, as the preset jobs pass it"),
    (0x08045128, "10b50446037d33b9", "the card check's entry"),
)
THEME_CALLS_MK2 = (                  # (site, stock target), both MK2
    (0x080433d8, 0x0804a9c4), (0x080433e8, 0x0804a614), (0x080433e0, 0x0804a64a),
    (0x0805b8c0, 0x08071602), (0x0805b8f6, 0x0807163c),
    (0x0808e34c, 0x0808cc9c), (0x0808e33a, 0x0808cc84),
    (0x0808e4ee, 0x08056c78), (0x0808e560, 0x08057442), (0x0808e50e, 0x08043be4),
    (0x0808e55a, 0x08043c48), (0x0805bb8c, 0x0809f89c), (0x0805bb98, 0x0808e4c8),
    (0x0805bbb0, 0x0809e998), (0x0805bc50, 0x0809f038), (0x0805bba2, 0x0809e3fc),
    (0x0805bb28, 0x0808e418), (0x0808c526, 0x08045128), (0x0808ce18, 0x08045128),
)
DISPLAY_OBJ_LIT_MK2 = 0x0805ba14     # micro 0x0805bc78: the present argument
THEME_TAB = 4                        # the fifth Tools tab
THEME_TAB_NAME = "Theme"


# --- R: Clip modes (2.3.10's Clip Tempo, cc15) -------------------------------------
# pm.apply_clip_tempo with the MK2's places: the same sites (the pitch factor,
# hook B's no-match exit, both preset-load finishes through hook P, the
# segment renderer's read, the Beat Count read, the streamer's vtable read)
# and Preset BPM's range widened to 1-255. Hook B is found by the origin main()
# gave it, not by searching for the micro's bytes. Guards read off the MK2.
CLIP_GUARDS_MK2 = (
    (0x080b53d4, "daf8803b", "ldr.w r3, [sl, #0xb80], the clip timing's Beat Count read"),
    (0x080b6a20, "d4e90223fff756fe8146", "ldrd r2, r3, [r4, #8]; bl 0x080b66d4; mov sb, r0: the read"),
    (0x080b66d4, "f0b50446406a1546", "the read's entry"),
    (0x080b53da, "002b40f0f580", "cmp r3, #0; bne.w: Auto or the count"),
    (0x080b55ca, "07ee903a", "vmov s15, r3: the count, used as read"),
    (0x080b5224, "2de9f04f8246006a", "the clip timing's entry"),
    (0x080b5a34, "2de9f04f1d46", "the segment start's entry"),
    (0x080a5954, "016a79b1", "the sample's frame count"),
    (0x08094de4, "2de9f04387b0", "PostSetParam's entry"),
    (0x080b85b2, "012385f82930", "the setter: +0x29 = 1 for a Clip or Slicer pad"),
    (0x0806aca8, "0293fa2301932823", "BPM:'s registration: max 250, min 40"),
    (0x080b691a, "e9f767ff", "bl 0x080a07ec, the pitch factor's exp2"),
    (0x080b691e, "94ed068a", "vldr s16, [r4, #0x18], the segment's base rate"),
    (0x080b6922, "f0ee408a", "vmov.f32 s17, s0, the factor kept for the second path"),
    (0x080b8dec, "9df83430", "ldrb r3, [sp, #0x34], the CC number hook B dispatches on"),
)
CLIP_RATE_SITE_MK2 = 0x080b691e          # micro 0x080b57f6
CLIP_BEATS_SITE_MK2 = 0x080b53d4         # micro 0x080b42ac
CLIP_READ_SITE_MK2 = 0x080b6a24          # micro 0x080b58fc
CLIP_CC_RET_MK2 = 0x080b867c             # micro 0x080b7554
STRM_VT_READ_MK2 = 0x080cb3bc            # micro 0x080ca600: the streamer's vtable read
STRM_READ_MK2 = 0x0809b394               # micro 0x0809a008
CLIP_BPM_REG_MK2 = ((0x0806acae, 0x28), (0x0806acaa, 0xfa))   # micro 0x0806a8b6 / 0x0806a8b2
KEEP_FINAL_SITES_MK2 = (0x0807e2f4, 0x080822ac)               # micro 0x0807c4e0 / 0x0807f98c
HOOK_B_ORG = None                        # set by main() when hook B is appended


def apply_clip_modes(d, n_org, n_syms):
    """Install the Clip modes' sites (after hooks B, N and P)."""
    for va, raw, what in CLIP_GUARDS_MK2:
        guard_bytes(d, va, raw, what)
    if pm.branch_target(d, 0x080b691a) != code_map(0x0809f45c):
        pm.refuse("The pitch factor's exp2 call is not what the Clip modes expect.")
    # 1. the pitch factor
    d[CLIP_RATE_SITE_MK2 - BASE:CLIP_RATE_SITE_MK2 - BASE + 4] = pm.enc_b_bl(
        CLIP_RATE_SITE_MK2, n_org + n_syms["nclip_rate"], True)
    # 2. CC 102-119 and 78: hook B's no-match exit
    b_blob, b_syms = pm.FROZEN["hookB"]
    fb = HOOK_B_ORG + b_syms["fB"] - b_syms["_sB"]
    if bytes(d[fb - BASE:fb - BASE + 4]) != pm.enc_b_bl(fb, CLIP_CC_RET_MK2, False):
        pm.refuse("Hook B's exit is not the branch the Clip modes expect.")
    d[fb - BASE:fb - BASE + 4] = pm.enc_b_bl(fb, n_org + n_syms["nclip_cc"], False)
    # 3. preset loads: both FinalizeBankLoading sites, already wrapped by P
    pfinal = {pm.branch_target(d, site) for site in KEEP_FINAL_SITES_MK2}
    if len(pfinal) != 1 or min(pfinal) < BASE + STOCK_SIZE:
        pm.refuse("The FinalizeBankLoading sites do not lead to Keep CCs' wrapper.")
    pfinal = pfinal.pop()
    if bytes(d[pfinal - BASE:pfinal - BASE + 2]) != bytes.fromhex("10b5"):
        pm.refuse("Keep CCs' wrapper does not begin as the Clip modes expect.")
    p = n_org + n_syms["nfinal_p"]
    if bytes(d[p - BASE:p - BASE + 4]) != b"\0\0\0\0":
        pm.refuse("The Clip modes' load shim is not where the patcher expects it.")
    d[p - BASE:p - BASE + 4] = pm.enc_b_bl(p, pfinal, True)
    for site in KEEP_FINAL_SITES_MK2:
        d[site - BASE:site - BASE + 4] = pm.enc_b_bl(site, n_org + n_syms["nfinal"], True)
    # 4b. the segment renderer's read
    d[CLIP_READ_SITE_MK2 - BASE:CLIP_READ_SITE_MK2 - BASE + 4] = pm.enc_b_bl(
        CLIP_READ_SITE_MK2, n_org + n_syms["njread"], True)
    # 4. the Beat Count read
    d[CLIP_BEATS_SITE_MK2 - BASE:CLIP_BEATS_SITE_MK2 - BASE + 4] = pm.enc_b_bl(
        CLIP_BEATS_SITE_MK2, n_org + n_syms["nclip_beats"], True)
    # 4c. the streamer's read, through its vtable
    if word(d, STRM_VT_READ_MK2) != STRM_READ_MK2 | 1:
        pm.refuse("The streamer's vtable read entry is not what the Clip modes expect.")
    struct.pack_into("<I", d, STRM_VT_READ_MK2 - BASE, (n_org + n_syms["c_clip_sread"]) | 1)
    # 5. Preset BPM 1-255: the registration and hook L's HOLD clamp
    lo, hi = pm.CLIP_BPM_RANGE
    for (va, old), new in zip(CLIP_BPM_REG_MK2, (lo, hi)):
        if bytes(d[va - BASE:va - BASE + 2]) != bytes((old, 0x23)):
            pm.refuse(f"Preset BPM's registration at {va:#x} is not what the Clip modes expect.")
        d[va - BASE] = new
    clamp = bytes.fromhex("282d38bf2825fa2d88bffa25")
    hits = [i for i in range(STOCK_SIZE, len(d) - len(clamp)) if d[i:i + len(clamp)] == clamp]
    if len(hits) != 1:
        pm.refuse("Hook L's HOLD capture clamp is not where the Clip modes expect it.")
    i = hits[0]
    d[i:i + len(clamp)] = bytes((lo, 0x2d, 0x38, 0xbf, lo, 0x25, hi, 0x2d, 0x88, 0xbf, hi, 0x25))
    vprint(f"R Clip modes: rate {CLIP_RATE_SITE_MK2:#x}, B exit {fb:#x}, beats, read, streamer, BPM {lo}-{hi}")


UI_PRESENT_SITE = 0x0805b950            # bl 0x0804368c, every UI tick (micro 0x0805bbb4)
UI_PRESENT_FN = 0x0804368c


def unhook_drawing(d, l_org, l_syms):
    """Take the OSD (hook O's odraw) and the CPU bar (hook K's kdraw) back off
    the UI tick, leaving Preset BPM's ltick, which draws nothing.

    Both draw straight into the LCD layers in the micro's layout: its LTDC is
    240 wide by 320 high (0x080461a2), the UI rotated in software; the MK2's is
    320 by 240 (0x08042dd0). The bar writes 320 rows into a 240-row frame --
    80 rows past its end -- and rebooted the module on cc6 the moment the OSD
    row was set to CPU (hardware, 2026-10-28). The pop-up lands transposed and
    was never seen. Until the MK2 has a renderer of its own, nothing draws."""
    site = UI_PRESENT_SITE
    if pm.branch_target(d, site) < BASE + STOCK_SIZE:
        pm.refuse("The UI tick is not hooked as expected.")
    tick = l_org + l_syms["ltick"]
    nxt = l_org + l_syms["ltick_next"]
    d[site - BASE:site - BASE + 4] = pm.enc_b_bl(site, tick, True)
    d[nxt - BASE:nxt - BASE + 4] = pm.enc_b_bl(nxt, UI_PRESENT_FN, False)
    vprint(f"UI tick: {site:#x} -> ltick {tick:#x} -> stock present {UI_PRESENT_FN:#x}")


# The version string (VER_VA) has four readers: the splash (0x0806ef5c, with
# the attribution), the Home menu's corner label (0x080869b0, beside the
# Pads/Keys/FX/Mix/Presets/Tools/EQ names), the Tools screen's version value
# (0x0807b194: snprintf "%s" into a 0x40 buffer), and 0x08094770. cc14, asked
# for on hardware: Home shows nothing (its label gets ""), and Tools shows
# the patch's own short name -- the full "2.3.4-ccNN" came out as "2.3.4" there.
HOME_VER_LIT = 0x080869b0
TOOLS_VER_LIT = 0x0807b194


def version_labels(d):
    for lit, what in ((HOME_VER_LIT, "Home menu"), (TOOLS_VER_LIT, "Tools screen")):
        if word(d, lit) != VER_VA:
            pm.refuse(f"The {what}'s version label is not where expected.")
    if d[TABS_EMPTY - BASE] != 0:
        pm.refuse("The empty string the Home label would show is not empty.")
    struct.pack_into("<I", d, HOME_VER_LIT - BASE, TABS_EMPTY)
    short = VERSION.split("-")[-1]                   # "cc14"
    org = pm._append(d, bytearray(f"mod {short}".encode() + b"\0"))
    struct.pack_into("<I", d, TOOLS_VER_LIT - BASE, org)
    vprint(f"version: Home label empty, Tools 'mod {short}' at {org:#x}")


# --- UI font: --font=FILE.otf[:SIZE] -----------------------------------------
# Stock text is one 6x8 bitmap font (0x080c0784; descriptor in .data, RAM
# 0x240000cc = {ptr, w 6, h 8}) behind a handful of functions at 0x08061680:
#   0x08061680 width(str)                      strlen * 12 (the 2x size)
#   0x08061698 height()                        16
#   0x080616a4 chr2x / 0x08061824 chr2x, clipped   one glyph, each dot 2x2
#   0x080617ac str2x(str, rect, colour, layer)     rect = {x, y, w, h}
#   0x08061a0c str2xclip(str, rect, clip, colour, [sp] layer): intersects
#              rect with clip (0x0806124c); if that is rect, draws unclipped
#   0x08061ac0 / 0x08061b98 / 0x08061cf8       the same at 1x (the small text)
# Every 2x string goes through width, str2x or str2xclip (19 + 7 + 9 callers),
# so taking those three entries swaps the big UI text and leaves the small 1x
# text alone. putpixel 0x0805b068(layer, x, y, colour) is y-up and clips to the
# layer; a glyph's top row lands at rect.y + 15, as stock's does.
# The font itself is rasterised here from the user's own file (Pillow), never
# shipped: a 256-entry table {u16 column offset, u8 advance, u8 columns} and
# one u16 per column, bit r = row r of a 16-row box, row 0 at the top.
FONT_WIDTH_VA, FONT_STR_VA, FONT_STRCLIP_VA = 0x08061680, 0x080617ac, 0x08061a0c
FONT_GUARDS = {FONT_WIDTH_VA: "10b5044b9c885cf0", FONT_STR_VA: "2de9f04784b00646",
               FONT_STRCLIP_VA: "2de9f04d8ab00746",
               0x0806124c: "2de9f04100230360", 0x0805b068: "70b504460d461646"}
FONT_SRC = r"""
.syntax unified
.thumb
.text
.global fwidth, fstr, fstrclip
.thumb_func
fwidth:                         @ r0 = str -> r0 = width in pixels
    adr r2, ftab
    movs r1, #0
1:  ldrb r3, [r0], #1
    cbz r3, 2f
    ldr r3, [r2, r3, lsl #2]
    ubfx r3, r3, #16, #8
    add r1, r3
    b 1b
2:  mov r0, r1
    bx lr

.thumb_func
fstr:                           @ r0 str, r1 rect, r2 colour, r3 layer
    push {r4-r11, lr}
    sub sp, #40
    str r2, [sp, #8]
    str r3, [sp, #12]
    movs r2, #0
    str r2, [sp, #16]
    b draw

.thumb_func
fstrclip:                       @ r0 str, r1 rect, r2 clip, r3 colour, [sp] layer
    push {r4-r11, lr}
    sub sp, #40
    mov r4, r0
    mov r5, r1
    str r3, [sp, #8]
    ldr r3, [sp, #76]
    str r3, [sp, #12]
    str r2, [sp, #16]
    add r0, sp, #24
    ldr r12, =0x0806124d        @ intersect(out, rect, clip)
    blx r12
    ldr r0, [sp, #24]
    ldr r1, [r5]
    cmp r0, r1
    bne 3f
    ldr r0, [sp, #28]
    ldr r1, [r5, #4]
    cmp r0, r1
    bne 3f
    ldr r0, [sp, #32]
    ldr r1, [r5, #8]
    cmp r0, r1
    bne 3f
    ldr r0, [sp, #36]
    ldr r1, [r5, #12]
    cmp r0, r1
    bne 3f
    movs r0, #0                 @ rect inside clip: no clipping, as stock
    str r0, [sp, #16]
3:  mov r0, r4
    mov r1, r5

draw:                           @ frame: 0 ybase, 4 xmax, 8 colour, 12 layer, 16 clip, 20 advance
    mov r4, r0
    ldr r5, [r1]
    ldr r2, [r1, #8]
    add r2, r5
    str r2, [sp, #4]
    ldrh r2, [r1, #4]
    adds r2, #15
    str r2, [sp, #0]
    adr r10, ftab
chr:
    ldrb r0, [r4], #1
    cmp r0, #0
    beq done
    ldr r0, [r10, r0, lsl #2]
    lsrs r7, r0, #24
    adds r1, r5, r7
    ldr r2, [sp, #4]
    cmp r1, r2
    bgt done
    ubfx r1, r0, #16, #8
    str r1, [sp, #20]
    uxth r6, r0
    add r6, r10, r6, lsl #1
    add r6, r6, #1024
    mov r11, r5
col:
    cmp r7, #0
    beq nxt
    ldrh r8, [r6], #2
    ldr r9, [sp, #0]
row:
    lsrs r8, r8, #1
    bcc skip
    ldr r3, [sp, #16]
    cmp r3, #0
    beq plot
    ldr r0, [r3]
    cmp r11, r0
    blt skip
    ldr r1, [r3, #8]
    add r0, r1
    cmp r11, r0
    bge skip
    ldr r0, [r3, #4]
    cmp r9, r0
    blt skip
    ldr r1, [r3, #12]
    add r0, r1
    cmp r9, r0
    bge skip
plot:
    ldr r0, [sp, #12]
    uxth r1, r11
    uxth r2, r9
    ldr r3, [sp, #8]
    uxtb r3, r3
    ldr r12, =0x0805b069        @ putpixel(layer, x, y, colour)
    blx r12
skip:
    sub r9, r9, #1
    cmp r8, #0
    bne row
    add r11, r11, #1
    subs r7, #1
    b col
nxt:
    ldr r0, [sp, #20]
    add r5, r0
    b chr
done:
    add sp, #40
    pop {r4-r11, pc}
.ltorg
.p2align 2
ftab:
"""


def font_tables(path, size):
    """Rasterise ASCII 0x20-0x7e of the user's font into the 16-row box."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        pm.refuse("--font needs Pillow:  pip install pillow")
    try:
        f = ImageFont.truetype(path, size)
    except OSError as e:
        pm.refuse(f"Could not read the font {path}", str(e))
    # Baseline: capitals centred on stock's (rows 0-13), then nudged up until
    # the deepest descender still fits the 16-row box.
    t = Image.new("1", (64, 64)); ImageDraw.Draw(t).text((0, 40), "H", font=f, fill=1, anchor="ls")
    top, bot = t.getbbox()[1], t.getbbox()[3]
    base = 40 - top + max(0, (14 - (bot - top)) // 2)
    t = Image.new("1", (64, 64)); ImageDraw.Draw(t).text((0, 40), "gjpqy", font=f, fill=1, anchor="ls")
    base -= max(0, t.getbbox()[3] - 40 + base - 16)
    space = max(2, round(f.getlength(" ")))
    entries, cols = [], []
    for c in range(256):
        if not 0x20 <= c <= 0x7e:
            entries.append((0, space, 0)); continue
        g = Image.new("1", (64, 64)); ImageDraw.Draw(g).text((0, base), chr(c), font=f, fill=1, anchor="ls")
        bb = g.getbbox()
        adv = max(1, round(f.getlength(chr(c))))
        n = 0 if bb is None else bb[2]
        start = len(cols)
        for x in range(n):
            m = 0
            for r in range(16):
                if g.getpixel((x, r)):
                    m |= 1 << r
            cols.append(m)
        while cols[start:] and cols[-1] == 0 and len(cols) > start:
            cols.pop()
        entries.append((start, adv, len(cols) - start))
    if len(cols) > 0xffff:
        pm.refuse("The font is too big for the table.")
    tab = b"".join(struct.pack("<HBB", o, a, n) for o, a, n in entries)
    return tab + b"".join(struct.pack("<H", m) for m in cols)


def apply_font(d, spec):
    path, _, size = spec.partition(":")
    size = int(size or 17)
    for va, want in FONT_GUARDS.items():
        guard_bytes(d, va, want, "text drawing code")
    if struct.unpack_from("<I", d, 0x080e4c24 - BASE)[0] != 0x080c0784:
        pm.refuse("The stock font's descriptor is not where expected.")
    code, syms = mk2_assemble("font", FONT_SRC)
    if len(code) != syms["ftab"]:
        pm.refuse("The font code does not end at its table.")
    org = pm._append(d, bytearray(code + font_tables(path, size)))
    for va, sym in ((FONT_WIDTH_VA, "fwidth"), (FONT_STR_VA, "fstr"),
                    (FONT_STRCLIP_VA, "fstrclip")):
        d[va - BASE:va - BASE + 4] = pm.enc_b_bl(va, org + syms[sym], False)
    print(f"     ok   UI font: {os.path.basename(path)} at {size} px")
    vprint(f"font at {org:#x}, {len(d) - (org - BASE)} bytes")


def check_no_micro_anywhere(d):
    """No micro address in anything appended: as a word, at any alignment, or
    as a movw/movt pair. Covers every hook of every stage."""
    bad_vals = {k for k, v in CODE_MAP.items() if k != v} | set(RAM_MAP)
    bad_vals -= set(CODE_MAP.values()) | set(RAM_MAP.values())
    tail = bytes(d[STOCK_SIZE:])
    found = set()
    for o in range(0, len(tail) - 3, 2):
        w, = struct.unpack_from("<I", tail, o)
        for v in (w, w & ~1):
            if v in bad_vals:
                found.add((BASE + STOCK_SIZE + o, v))
    if found:
        pm.refuse("A hook still carries a micro address.",
                  *(f"{a:#010x}: {v:#010x}" for a, v in sorted(found)[:12]))


def write_frozen():
    """--reassemble found new or changed blobs: rewrite FROZEN_MK2 in place."""
    path = os.path.abspath(__file__)
    src = open(path).read()
    merged = dict(FROZEN_MK2, **_REGEN)
    lines = ["FROZEN_MK2 = {"]
    for k in sorted(merged):
        blob, syms = merged[k]
        lines.append(f"    {k!r}: (")
        lines += [f'        "{blob[i:i + 96]}"' for i in range(0, len(blob), 96)]
        lines.append(f"        , {dict(sorted(syms.items()))!r}),")
    lines.append("}")
    a = src.index("# BEGIN FROZEN_MK2\n") + len("# BEGIN FROZEN_MK2\n")
    b = src.index("# END FROZEN_MK2")
    open(path, "w").write(src[:a] + "\n".join(lines) + "\n" + src[b:])
    print(f"  FROZEN_MK2 rewritten: {', '.join(sorted(_REGEN))}")


def main():
    global VERBOSE, REASSEMBLE, HOOK_B_ORG
    flags = sys.argv[1:]
    VERBOSE = "-v" in flags or "--verbose" in flags
    REASSEMBLE = "--reassemble" in flags
    pm.VERBOSE = VERBOSE
    argv = [a for a in flags if not a.startswith("-")]
    if len(argv) != 2:
        sys.exit(__doc__.strip().split("\n")[-1])
    inp, outp = argv
    py = "python" if os.name == "nt" else "python3"

    if os.path.realpath(inp) == os.path.realpath(outp):
        pm.refuse("The input and the output are the same file.",
                  "That would overwrite your stock firmware, your only way back.",
                  "", "    mkdir patched",
                  f"    {py} patch_mk2.py {inp} patched/BITBOXMK2.BIN")

    print("\n  Checking your firmware...")
    try:
        d = bytearray(open(inp, "rb").read())
    except OSError as e:
        pm.refuse(f"Could not open {inp}", str(e))
    sha = hashlib.sha256(d).hexdigest()
    if len(d) != STOCK_SIZE or sha != STOCK_SHA:
        pm.refuse("That is not the stock bitbox mk2 2.3.4 firmware.",
                  f"expected  {STOCK_SIZE:,} bytes   {STOCK_SHA[:24]}...",
                  f"got       {len(d):,} bytes   {sha[:24]}...",
                  "", "Use BITBOXMK2.bin straight out of 1010music's BITBOXMK2234.zip.",
                  "A micro image, an already patched image or another version",
                  "will not do.")
    print("     ok   Genuine bitbox mk2 2.3.4, nothing done to it yet")

    hooks = mk2_hooks()
    # Each hook site must still be the stock bne.w to the stock default.
    for label, hook, ret, _, _ in hooks:
        cur, want = bytes(d[hook - BASE:hook - BASE + 4]), pm.enc_bne_w(hook, ret)
        if cur != want:
            pm.refuse(f"The {label} hook site at {hook:#x} is not what it should be.",
                      f"found {cur.hex()}, expected {want.hex()}")
        vprint(f"hook {label:16} {hook:#x} = bne.w {ret:#x}")
    # Every case we branch into, and every function we call, must open with
    # the instruction it opens with in the micro -- same check, same words.
    for cc, (va, guard) in sorted(pm.CASES.items()):
        guard_word(d, m2(va), guard, f"CC{cc} case")
    guard_word(d, m2(pm.STOP_A), pm.STOP_A_GUARD, "stop, class A")
    guard_word(d, m2(pm.STOP_B), pm.STOP_B_GUARD, "stop, class B")
    guard_word(d, m2(pm.CLASSB_SETPARAM), pm.CLASSB_SETPARAM_GUARD,
               "class B set-parameter")
    # The taper is the one target the micro patcher never guarded; it is
    # called with a float in s0 and returns one, so check its first words.
    guard_word(d, m2(pm.TAPER), 0x0ac0eeb5, "send taper")
    guard_cstr(d, PRODUCT_VA, PRODUCT, "product name")
    if word(d, PTR_TABLE_VA) & 0xfff00001 != 0x08000001:
        pm.refuse("The table after the version string is not where expected.")
    shift_patch_ram()
    stage2_guards(d)
    print("     ok   The code is where the patch expects to find it")

    print("\n  Embellishing your bitbox mk2 with community requests...")
    # The generators read these two at build time.
    pm.TAPER = m2(pm.TAPER)
    pm.CLASSB_SETPARAM = m2(pm.CLASSB_SETPARAM)
    for label, hook, ret, vslot, arms in hooks:
        code = pm.build(BASE + len(d), ret, vslot, arms, label[0])
        check_dispatch(code, arms, label)
        org = pm._append(d, bytearray(code))
        d[hook - BASE:hook - BASE + 4] = pm.enc_bne_w(hook, org)
        if label[0] == "B":
            HOOK_B_ORG = org
        vprint(f"{label:16} at {org:#010x}, "
               + ", ".join(f"CC{c}" for c, _, _ in arms))
    for what, cc in pm.FEATURES:
        if "per pad" in what or "slicer" in what or what.startswith("Stop"):
            if any(cc == f"CC {n}" for n in DISABLED_CCS):
                print(f"     --   {what:<28} {cc}  (left out of this build)")
                continue
            print(f"     ok   {what:<28} {cc}")

    # Diagnostic builds for bisecting a hardware fault (2026-10-28: cc5 stopped
    # taking MIDI after a while). --upto=2 is cc4 with patch RAM moved;
    # settings adds H/J/L/K; character adds N. Each keeps cc4's type gate,
    # which Keep CCs (hook P) otherwise replaces.
    upto = next((f.split("=", 1)[1] for f in flags if f.startswith("--upto=")), "full")
    global VERSION
    VERSION = {"2": "2.3.4-d1", "settings": "2.3.4-d2", "character": "2.3.4-d3"}.get(upto, VERSION)
    comp = upto == "full"                          # 2.3.10's chr10 path (cc13)
    hook_e = stage2(d, gate=(upto != "full"), comp=comp)
    if upto != "2":
        prepare_stage3()
        stage3(d, upto, hook_e if comp else None)
    if _REGEN:
        write_frozen()
        sys.exit("  Rerun without --reassemble to build with the new blobs.")
    check_no_micro_anywhere(d)
    check_stage2_ram(d)
    font = next((f.split("=", 1)[1] for f in flags if f.startswith("--font=")), None)
    if font:
        apply_font(d, font)
        if _REGEN:
            write_frozen()
            sys.exit("  Rerun without --reassemble to build with the new blobs.")
    for what, cc in pm.FEATURES:
        if "ch 1" in what or "global" in what:
            print(f"     ok   {what:<28} {cc}")
    print(f"     ok   {'Compressor auto makeup, ch 1':<28} CC 46")
    for what in ("Character chain, ch 1        CC 14-29",
                 "OSD: pop-ups and CPU bar     TOOLS > Settings",
                 "Keep CCs: OFF/ON             TOOLS > Settings",
                 "ProgChange: OFF/ON/NEW ONLY  TOOLS > Settings",
                 "Clk Loss: INTERNAL/HOLD      TOOLS > Settings",
                 "Preset BPM, HOLD capture     TOOLS > Settings",
                 "Compressor type, ch 1        CC 47 / 48",
                 "Character and compressor     kept across power-off",
                 "Clip modes, per pad          CC 112-116",
                 "Live Flip modes, per pad     CC 117",
                 "Hold buttons, per pad        CC 78, 102, 104, 105, 107, 118, 119",
                 "Theme, and your own          TOOLS > Theme"):
        print(f"     ok   {what}")

    write_string(d, ATTRIB_VA, VER_VA, ATTRIB_STOCK, ATTRIB_NEW)
    if len(VERSION) > pm.VER_DISPLAY_MAX:
        pm.refuse(f"{VERSION!r} is longer than the splash shows.")
    write_string(d, VER_VA, PTR_TABLE_VA, VER_STOCK, VERSION)
    print("     ok   Splash screen, so nobody blames 1010music for my work")
    version_labels(d)

    if len(d) % 4:
        pm.refuse(f"The patched image is {len(d):,} bytes, not a multiple of 4.")
    try:
        open(outp, "wb").write(bytes(d))
    except OSError as e:
        pm.refuse(f"Could not write {outp}", str(e))
    print(f"\n  Done. {outp} is ready -- {len(d):,} bytes.")
    print(f"     Fingerprint  {hashlib.sha256(bytes(d)).hexdigest()}")
    print(f"\n     The splash should read 'bitbox mk2 / {ATTRIB_NEW} / {VERSION}'.\n")


if __name__ == "__main__":
    main()
