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

Not yet: Character, OSD, Keep CCs, Program Change, Clk Loss, Preset BPM,
Flip UI. Two of the micro's RAM areas fall inside the MK2's stack and must
move first.

Usage: patch_mk2.py <BITBOXMK2.bin> <out.bin> [-v] [--reassemble]
"""
import hashlib, os, struct, subprocess, sys, tempfile

sys.dont_write_bytecode = True        # no __pycache__ next to the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import patch_micro as pm                # noqa: E402  the hook generators

BASE = 0x08040000
STOCK_SHA = "35ab7995ad0eca8484f3b28bc76389f10b2037dbb21a4a394e950d9329073e86"
STOCK_SIZE = 674896
VERSION = "2.3.4-cc4"                   # 9 characters: see pm.VER_DISPLAY_MAX

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
    # Auto makeup's flag. The micro keeps it at 0x2406a620, right after Keep
    # CCs -- which on the MK2 is INSIDE the main stack (top 0x2406ad98). It
    # moves into the free words between the store blocks and the Character's.
    "AUTO_RAM": 0x2406c0b0,
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

# Generated by `patch_mk2.py ... --reassemble` with clang 18; see mk2_assemble.
# BEGIN FROZEN_MK2
FROZEN_MK2 = {
    'mk2_gateT': (
        "9df84030072b01d10000000000000000"
        , {'_sT': 0, 'tcc': 8, 'tstock': 12}),
    'mk2_hookC': (
        "30b5169c179d000000006c2c06d06d2c06d06e2c06d06f2c0bd030bd172202e0182200e0ab22b5f5005fb4bf00250125"
        "06e0ac22ed1141f67f7305fb03f5ad0a2b46002482b00094019443f6b840c2f2024040f20001c0f203010000000002b0"
        "30bd"
        , {'_sC': 0, 'cbool': 38, 'cbs': 28, 'cfl': 36, 'cpost': 6, 'cpp': 32, 'csend': 64, 'csetp': 90, 'cwd': 50}),
    'mk2_hookDr': (
        "03b4ddf850c0bcf1000f40f0a280ddf854c0bcf1280f04d0acf12903052b2cd997e04df6b840c2f202404ef2b801c2f2"
        "02410268a2f11053b3f5a02f0cd24ff6a073d358b3f1c00f06d14ff6a473d35848f6a04c634503d004308842e9d378e0"
        "ddf858c0bcf5005fb4bf0023012348f65841c0f2020153546be04cf20002c2f2064211684cf2de0cc1f2100c61450ed0"
        "c2f800c050a002f1040102f1180c90ed000a81ed000a043004316145f7d3052b52d0042b0bd146480168dff818c16145"
        "05d141686fea0c0c614500d141e0ddf858c01cf07f0f08bf4ceadc1c00ee10cab8ee400a03eb430040a101eb8001d1ed"
        "000a91ed011a886820ee200a30ee010a002801d0bceec00a02eb830080ed010a012b0bd82e480168dff8b8c0614505d1"
        "41686fea0c0c614500d125e0d2f800c053688cea030c93688cea030cd3688cea030c13698cea030c53698cea030cc2f8"
        "18c003bc00000000ddf858c01c48bcf5005f05db1b4901606fea0101416003e0002101604160ece792ed010ad2ed020a"
        "b7ee001ac1ee200a70eec10a20ee200ab4ee400af1ee10fa15d60ca0d0ed000ab4ee600af1ee10fac8bfb0ee600af1ee"
        "600ab4ee600af1ee10fab8bfb0ee600a82ed050ab2e700205061afe700001042b0c006244155544f000040c100000040"
        "a005000040380000000000008002203b000020c2000000006002983a0000803f000000005542953e0000c04101000000"
        "e7a239400000f043010000004002903b000010c200000000"
        , {'_sD': 0, 'dauto': 344, 'dauto_off': 368, 'dfound': 96, 'dk36': 460, 'dmakeup': 376, 'dmk_zero': 454, 'dnext': 340, 'dnextc': 88, 'donoff': 34, 'dout': 338, 'dparam': 122, 'dscale': 492, 'dscan': 50, 'dseed': 158, 'dseeded': 174, 'dstock': 472, 'dstore': 264, 'dsum': 300, 'dval': 206}),
    'mk2_hookE': (
        "4cf20002c2f2064213684cf2de0cc1f2100c634519d0c2f800c040f20003ccf24013536040f20003c4f20003936040f2"
        "a053d36043f64003136140f2000353614ff63e53c9f25013936153688cea030c93688cea030cd3688cea030c13698cea"
        "030c53698cea030c936963450ed15368c0f828349368c0f82c34d368c0f848341369c0f84c345369c0f8303400000000"
        , {'_sE': 0, 'enext': 140, 'eout': 140, 'everify': 74}),
    'mk2_hookF': (
        "03b4ddf850c0bcf1000f40f09580ddf854c0acf13203092b00f28e804cf24002c2f2064211684ef20e00c1f210008142"
        "26d0106040f20001516041f6c071916041f6c071d16041f6c071116140f20001516140f20001916140f20001d16140f2"
        "0001116240f20001516240f2010191620021116351634ff6cf71c1f21001d1621699002b05d10a2001fb00f1890b5160"
        "2fe0072b06d1b1f5005fb4bf00210121116226e0092b06d1b1f5005fb4bf0021012151621de0042b06d1b1f5005fb4bf"
        "00210121516114e0052b06d1b1f5005fb4bf0021012191610be0062b06d1b1f5005fb4bf00210121d16102e014a0c05c"
        "1150916a013191621068536880ea0300936880ea0300d36880ea0300136980ea0300536980ea0300936980ea0300d369"
        "80ea0300136a80ea0300536a80ea0300936a80ea0300d06203bc0000000000bf38080c10383838383838"
        , {'_sF': 0, 'fbump': 242, 'fnext': 314, 'fnotba': 200, 'fnotbb': 218, 'fnotbc': 236, 'fnotbyp': 164, 'fnotmode': 146, 'fnotslope': 182, 'fout': 312, 'fplain': 236, 'fseeded': 128, 'fslots': 320}),
    'mk2_hookG': (
        "2de9f0412ded068b04460d464cf24006c2f2064633684ef20e00c1f21000834227d03246106040f20001516041f6c071"
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
    ranges = [("compressor store", pm.PATCH_RAM, pm.PATCH_RAM + pm.PATCH_SUM + 4),
              ("EQ store", pm.EQ_STORE, pm.EQ_STORE_END),
              ("auto makeup flag", pm.AUTO_RAM, pm.AUTO_RAM + 8)]
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


def stage2(d):
    """Hooks C (delay switches), D (compressor CCs), E (compressor DSP),
    F (EQ CCs), G (EQ DSP) and the type gate, chained at the post call
    exactly as the micro chains them: gate -> F -> D -> C -> stock post."""
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
        hook_d = put(pm.build_comp_hook(BASE + len(d), hook_c, full_range=True),
                     "D compressor CCs")
        org_e = put(pm.build_comp_dsp_hook(BASE + len(d)), "E compressor DSP")
        hook_f = put(pm.build_eq_midi_hook(BASE + len(d), hook_d), "F EQ CCs")
        org_g = put(pm.build_eq_dsp_hook(BASE + len(d)), "G EQ DSP")
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
    if _REGEN:
        return built
    # Install: three stock words change, nothing else.
    post, dsp = pm.MIDI_POST_CALL, pm.COMP_DSP_CALL
    d[post - BASE:post - BASE + 4] = pm.enc_b_bl(post, org_t, True)
    d[dsp - BASE:dsp - BASE + 4] = pm.enc_b_bl(dsp, org_e, True)
    struct.pack_into("<I", d, pm.EQ_VT_HANDLER - BASE, org_g | 1)
    return built


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
    global VERBOSE, REASSEMBLE
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
        vprint(f"{label:16} at {org:#010x}, "
               + ", ".join(f"CC{c}" for c, _, _ in arms))
    for what, cc in pm.FEATURES:
        if "per pad" in what or "slicer" in what or what.startswith("Stop"):
            if any(cc == f"CC {n}" for n in DISABLED_CCS):
                print(f"     --   {what:<28} {cc}  (left out of this build)")
                continue
            print(f"     ok   {what:<28} {cc}")

    stage2(d)
    if _REGEN:
        write_frozen()
        sys.exit("  Rerun without --reassemble to build with the new blobs.")
    for what, cc in pm.FEATURES:
        if "ch 1" in what or "global" in what:
            print(f"     ok   {what:<28} {cc}")
    print(f"     ok   {'Compressor auto makeup, ch 1':<28} CC 46")

    write_string(d, ATTRIB_VA, VER_VA, ATTRIB_STOCK, ATTRIB_NEW)
    if len(VERSION) > pm.VER_DISPLAY_MAX:
        pm.refuse(f"{VERSION!r} is longer than the splash shows.")
    write_string(d, VER_VA, PTR_TABLE_VA, VER_STOCK, VERSION)
    print("     ok   Splash screen, so nobody blames 1010music for my work")

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
