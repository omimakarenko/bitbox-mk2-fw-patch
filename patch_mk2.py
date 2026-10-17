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

Everything that goes through the MIDI dispatcher (compressor, EQ, delay
switches, Character, Keep CCs) is NOT here yet: the MK2 dispatcher is built
with a different stack frame and the micro hooks for it cannot be reused as
they are.

Usage: patch_mk2.py <BITBOXMK2.bin> <out.bin> [-v]
"""
import hashlib, os, struct, sys

sys.dont_write_bytecode = True        # no __pycache__ next to the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import patch_micro as pm                # noqa: E402  the hook generators

BASE = 0x08040000
STOCK_SHA = "35ab7995ad0eca8484f3b28bc76389f10b2037dbb21a4a394e950d9329073e86"
STOCK_SIZE = 674896
VERSION = "2.3.4-cc1"                   # 9 characters: see pm.VER_DISPLAY_MAX

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

VERBOSE = False


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
            new_arms.append((cc, kind, arg))
        out.append((label, m2(hook), m2(ret), vslot, new_arms))
    return out


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


def main():
    global VERBOSE
    flags = sys.argv[1:]
    VERBOSE = "-v" in flags or "--verbose" in flags
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
    print("     ok   The code is where the patch expects to find it")

    print("\n  Embellishing your bitbox mk2 with community requests...")
    # The generators read these two at build time.
    pm.TAPER = m2(pm.TAPER)
    pm.CLASSB_SETPARAM = m2(pm.CLASSB_SETPARAM)
    for label, hook, ret, vslot, arms in hooks:
        org = pm._append(d, bytearray(pm.build(BASE + len(d), ret, vslot, arms,
                                               label[0])))
        d[hook - BASE:hook - BASE + 4] = pm.enc_bne_w(hook, org)
        vprint(f"{label:16} at {org:#010x}, "
               + ", ".join(f"CC{c}" for c, _, _ in arms))
    for what, cc in pm.FEATURES:
        if "per pad" in what or "slicer" in what or what.startswith("Stop"):
            print(f"     ok   {what:<28} {cc}")

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
