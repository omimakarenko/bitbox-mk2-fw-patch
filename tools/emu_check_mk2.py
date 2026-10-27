"""Emulate the MK2 stage-2 hooks of a patched image (needs: pip install unicorn).
Usage: python3 tools/emu_check_mk2.py patched/BITBOXMK2.BIN
Every MIDI message type through the type gate and the CC chain must return to
the dispatcher with sp, r0/r1 and callee-saved registers intact and exactly one
stock post; hooks E and G must reach the stock compressor DSP / EQ handler.
Written after 2.3.4-cc3, whose gate spun forever on any non-CC message."""
import sys, struct, random
from unicorn import *
from unicorn.arm_const import *
BASE=0x08040000
img=open(sys.argv[1],"rb").read()
T=0x080e5fc8; POST=0x0809656c; SETP=0x08094de4; RET=0x0809542e
COMPDSP=0x080ba43c; EQH=0x080bb3b8
def mk():
    mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB|UC_MODE_MCLASS)
    mu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M7)
    mu.mem_map(0x08000000,0x200000); mu.mem_write(BASE,img)
    mu.mem_map(0x24000000,0x80000); mu.mem_map(0x20000000,0x20000); mu.mem_map(0xE0000000,0x100000)
    mu.mem_write(0xE000ED88,struct.pack("<I",0xF<<20))   # CPACR: FPU on
    return mu
CS=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
def midi(mu,typ,chan,cc,val):
    sp=0x24050000
    fr=bytearray(0x18); fr[0]=typ; struct.pack_into("<III",fr,8,chan,cc,val); mu.mem_write(sp+0x40,bytes(fr))
    init={r:0x1000+i for i,r in enumerate(CS)}; init[UC_ARM_REG_R6]=sp+0x40
    for r,v in init.items(): mu.reg_write(r,v)
    mu.reg_write(UC_ARM_REG_R0,0x24011110); mu.reg_write(UC_ARM_REG_R1,sp+0x40)
    mu.reg_write(UC_ARM_REG_SP,sp); mu.reg_write(UC_ARM_REG_LR,RET|1)
    log=[]
    def hk(mu,a,s,u):
        if a in (POST,SETP):
            log.append((a,mu.reg_read(UC_ARM_REG_R0),mu.reg_read(UC_ARM_REG_R1),mu.reg_read(UC_ARM_REG_R2),mu.reg_read(UC_ARM_REG_R3)))
            mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
        elif a==RET: mu.emu_stop()
    h=mu.hook_add(UC_HOOK_CODE,hk)
    mu.emu_start(T|1,0,count=5000)
    mu.hook_del(h)
    ok = mu.reg_read(UC_ARM_REG_PC)==RET and mu.reg_read(UC_ARM_REG_SP)==sp and all(mu.reg_read(r)==v for r,v in init.items())
    posts=[l for l in log if l[0]==POST]
    ok = ok and len(posts)==1 and posts[0][1]==0x24011110 and posts[0][2]==sp+0x40
    return ok,log
mu=mk(); bad=0; n=0; setp=[]
random.seed(1)
for typ in range(0,16):
    for chan in (0,14):
        ccs=range(128) if typ==7 else (60,)
        for cc in ccs:
            for val in (0,64<<7,127<<7, random.randrange(128)<<7):
                ok,log=midi(mu,typ,chan,cc,val); n+=1
                if not ok: bad+=1; print("FAIL",typ,chan,cc,val,log) if bad<10 else None
                setp+= [(cc,hex(l[2]),hex(l[3]),l[4]) for l in log if l[0]==SETP]
print(f"MIDI chain: {n} messages, {bad} failures")
print("set-parameter calls by CC:",sorted(set((c,k,p) for c,k,p,_ in setp)))
st=mu.mem_read(0x2406c000,0x80)
print("comp store magic",hex(struct.unpack_from("<I",st,0)[0]),"EQ store magic",hex(struct.unpack_from("<I",st,0x40)[0]))
# E: compressor DSP hook, 3 blocks, fake object
obj=0x24060000
for blk in range(3):
    mu.reg_write(UC_ARM_REG_R0,obj); mu.reg_write(UC_ARM_REG_R1,0x1234); mu.reg_write(UC_ARM_REG_SP,0x24050000); mu.reg_write(UC_ARM_REG_LR,RET|1)
    done=[]
    def he(mu,a,s,u):
        if a==COMPDSP: done.append(mu.reg_read(UC_ARM_REG_R0)==obj and mu.reg_read(UC_ARM_REG_R1)==0x1234); mu.emu_stop()
    h=mu.hook_add(UC_HOOK_CODE,he); mu.emu_start(0x080e51cc|1,0,count=2000); mu.hook_del(h)
    f=struct.unpack("<5I",mu.mem_read(obj+0x428,12)+mu.mem_read(obj+0x448,8))
    print(f"E block {blk}: reached comp DSP with args intact={done}, thresh/ratio/makeup/atk/rel words={[hex(x) for x in f]}")
# G: EQ DSP hook via a fake EQ object built by the stock ctor? call ctor 0x080ba75c area start
# G: EQ hook. Zeroed object; G applies the stored mode via the stock designers, then tails to the handler.
eq=0x24062000
mu.mem_write(eq,b"\0"*0x200)
for blk in range(3):
    mu.reg_write(UC_ARM_REG_R0,eq); mu.reg_write(UC_ARM_REG_R1,0x5678); mu.reg_write(UC_ARM_REG_SP,0x24050000); mu.reg_write(UC_ARM_REG_LR,RET|1)
    for r in CS: mu.reg_write(r,0x2000+r)
    res=[]; wild=[]
    def hg(mu,a,s,u):
        if a==EQH: res.append((mu.reg_read(UC_ARM_REG_R0)==eq, mu.reg_read(UC_ARM_REG_R1)==0x5678, mu.reg_read(UC_ARM_REG_SP)==0x24050000, all(mu.reg_read(r)==0x2000+r for r in CS))); mu.emu_stop()
        elif not (0x08040000<=a<0x080e6000): wild.append(hex(a)); mu.emu_stop()
    h=mu.hook_add(UC_HOOK_CODE,hg)
    try: mu.emu_start(0x080e53a8|1,0,count=200000)
    except UcError as e: print("G fault",e,hex(mu.reg_read(UC_ARM_REG_PC)))
    mu.hook_del(h)
    types=[mu.mem_read(eq+0x10c+i*0x14,1)[0] for i in range(4)]
    en=[mu.mem_read(eq+0x11c+i*0x14,1)[0] for i in range(4)]
    print(f"G block {blk}: reached EQ handler (r0,r1,sp,callee-saved ok)={res}, wild={wild}, band types={types}, enables={en}")
