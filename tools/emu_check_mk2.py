"""Emulation checks for a patched MK2 image (needs: pip install unicorn).
Usage: python3 tools/emu_check_mk2.py patched/BITBOXMK2.BIN
Runs the hooks in a Cortex-M7 emulator with every stock function stubbed, and
fails on any write outside the patch RAM block, the stack or the buffers it
hands out:
  1. every MIDI message type, 128 CCs, 3 channels through the CC chain
  2. the Character DSP on a master-bus buffer, all four effect sets
  3. boot: the clock constructor chain    4. Settings registrations
  5. Settings posts                       6. the engine block start
  7. the UI tick (pop-up and CPU bar)     8. pad CCs through hooks A and B
  9. the saved master bus: boot posts to the C, then SetParam and the
     settings.tml write from the UI tick   10. compressor types (CC 47) on the DSP call
Known limit: Unicorn's M7 has no double-precision FPU, so one Character
effect set stops at a vmov.f64 (the MK2 hardware has one: stock uses it 533x)."""
import struct, sys, random
from unicorn import *
from unicorn.arm_const import *
BASE=0x08040000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
      UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
CS=REGS[4:12]
class H:
    def __init__(s,img,stock_end,win):
        s.img=img; s.end=stock_end; s.win=win
        mu=s.mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB|UC_MODE_MCLASS)
        mu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M7)
        mu.mem_map(0x08000000,0x200000); mu.mem_write(BASE,img)
        mu.mem_map(0x24000000,0x80000); mu.mem_map(0x20000000,0x20000); mu.mem_map(0xE0000000,0x100000)
        mu.mem_write(0xE000ED88,struct.pack("<I",0xF<<20))
        s.allowed=[(0x20000000,0x20020000),win,(0xE0000000,0xE0100000)]
        s.badw=[]; s.calls=[]; s.stop_at=set(); s.terminal=set()
        mu.hook_add(UC_HOOK_MEM_WRITE,s._w); mu.hook_add(UC_HOOK_CODE,s._c)
    def allow(s,lo,hi): s.allowed.append((lo,hi))
    def _w(s,mu,acc,addr,size,val,ud):
        if not any(lo<=addr<hi for lo,hi in s.allowed): s.badw.append((hex(mu.reg_read(UC_ARM_REG_PC)),hex(addr),size))
    def _c(s,mu,addr,size,ud):
        if addr in s.stop_at: s.ended=addr; mu.emu_stop(); return
        if addr in s.terminal: s.ended=addr; s.calls.append(("TERM",hex(addr))); mu.emu_stop(); return
        if BASE<=addr<s.end:          # stock code: stub it -- return to lr
            s.calls.append((hex(addr),[hex(mu.reg_read(r)) for r in REGS[:4]]))
            mu.reg_write(UC_ARM_REG_R0,s.ret0.get(addr,0) if hasattr(s,"ret0") else 0)
            mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR)); return
        if not (0x08000000<=addr<0x08200000): s.ended=("WILD",hex(addr)); mu.emu_stop()
    def run(s,entry,regs,sp=0x2001f000,lr=0x08040401,count=2_000_000):
        mu=s.mu; s.calls=[]; s.badw=[]; s.ended=None
        for r,v in regs.items(): mu.reg_write(r,v)
        mu.reg_write(UC_ARM_REG_SP,sp); mu.reg_write(UC_ARM_REG_LR,lr)
        s.stop_at={lr&~1}
        try: mu.emu_start(entry|1,0,count=count)
        except UcError as e: s.ended=("FAULT",str(e),hex(mu.reg_read(UC_ARM_REG_PC)))
        return s.ended



img=open(sys.argv[1],"rb").read(); stock=b"\0"*674896
END=BASE+len(stock); WIN=(0x2406ae00,0x24070a80)
POST_SITE=0x0809542a; POST=0x0809656c; RET=0x0809542e
def bl_target(at):
    hw1,hw2=struct.unpack_from("<HH",img,at-BASE)
    S=(hw1>>10)&1; J1=(hw2>>13)&1; J2=(hw2>>11)&1; I1=1-(J1^S); I2=1-(J2^S)
    off=(S<<24)|(I1<<23)|(I2<<22)|((hw1&0x3ff)<<12)|((hw2&0x7ff)<<1)
    if S: off-=1<<25
    return at+4+off
h=H(img,END,WIN)
# ---- 1. MIDI chain at the post call
head=bl_target(POST_SITE); print("post call ->",hex(head))
sp=0x2001f000
fails=0; n=0; charcc=0
random.seed(7)
for typ in range(16):
  for chan in (0,1,14):
    for cc in (range(128) if typ==7 else (60,)):
      for val in (0,64<<7,127<<7,random.randrange(128)<<7):
        fr=bytearray(0x18); fr[0]=typ; struct.pack_into("<III",fr,8,chan,cc,val)
        h.mu.mem_write(sp+0x40,bytes(fr))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40; regs[UC_ARM_REG_R6]=sp+0x40
        end=h.run(head,regs,sp=sp,lr=RET|1)
        posts=[c for c in h.calls if c[0]==hex(POST)]
        ok = end==RET and h.mu.reg_read(UC_ARM_REG_SP)==sp and all(h.mu.reg_read(r)==regs[r] for r in CS) and len(posts)==1 and posts[0][1][:2]==['0x24011110',hex(sp+0x40)] and not h.badw
        n+=1
        if not ok:
            fails+=1
            if fails<6: print("FAIL",typ,chan,cc,val,end,posts,h.badw[:3],[c for c in h.calls][:6])
print(f"MIDI chain: {n} messages, {fails} failures")
# what else did CCs call in stock?
# C code really ran? the Character store and the OSD state
st=h.mu.mem_read(0x2406dc00,0x40); print("CHR store head:",st[:16].hex(), " OSD ACC:",h.mu.mem_read(0x2406dd40,12).hex())
# ---- 2. Character DSP on the master bus: the site bl at 0x0809817a, r0 = bus buffer
CHR_SITE=0x0809817a; head=bl_target(CHR_SITE); print("master bus call ->",hex(head))
buf=0x24040000; h.allow(buf,buf+0x4000)
FR=48
def mkbus():
    import math
    L=buf+0x100; R=buf+0x100+FR*4
    h.mu.mem_write(buf,struct.pack("<IIII",FR,0,L,R)+bytes([0,1,0,0]))
    sig=[0.5*math.sin(i*0.3)+0.2*random.uniform(-1,1) for i in range(FR)]
    h.mu.mem_write(L,struct.pack(f"<{FR}f",*sig)); h.mu.mem_write(R,struct.pack(f"<{FR}f",*sig))
    return L,R,sig
for amt in (0,64,127):
    # set all four slot amounts via CC 14-17 on ch1, and pick effects 22-25
    for cc,v in ((14,amt),(15,amt),(16,amt),(17,amt),(18,100),(19,30),(20,90),(21,64)):
        fr=bytearray(0x18); fr[0]=7; struct.pack_into("<III",fr,8,0,cc,v<<7); h.mu.mem_write(sp+0x40,bytes(fr))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40
        h.run(bl_target(POST_SITE),regs,sp=sp,lr=RET|1)
    for blk in range(4):
        L,R,sig=mkbus()
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=buf; regs[UC_ARM_REG_R1]=buf+0x2000
        end=h.run(head,regs,sp=sp,lr=0x0809817f)
        ok= end==0x0809817e and h.mu.reg_read(UC_ARM_REG_SP)==sp and all(h.mu.reg_read(r)==regs[r] for r in CS) and not h.badw
        import math
        out=struct.unpack(f"<{FR}f",h.mu.mem_read(L,FR*4))
        fin=all(math.isfinite(x) for x in out); mx=max(abs(x) for x in out); diff=max(abs(a-b) for a,b in zip(out,sig))
        print(f"  amount {amt:3} block {blk}: ok={ok} finite={fin} peak={mx:.3f} changed-by={diff:.3f} insns? badw={h.badw[:3]}")

# all 16 effects: pick each in each slot (CC 22-25 four bands), amount 127
import math
worst=0
for eff in range(4):
    for cc,v in ((14,127),(15,127),(16,127),(17,127),(22,eff*32+16),(23,eff*32+16),(24,eff*32+16),(25,eff*32+16)):
        fr=bytearray(0x18); fr[0]=7; struct.pack_into("<III",fr,8,0,cc,v<<7); h.mu.mem_write(sp+0x40,bytes(fr))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40
        h.run(bl_target(POST_SITE),regs,sp=sp,lr=RET|1)
    for blk in range(6):
        L,R,sig=mkbus()
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=buf
        end=h.run(head,regs,sp=sp,lr=0x0809817f)
        out=struct.unpack(f"<{FR}f",h.mu.mem_read(L,FR*4))
        ok= end==0x0809817e and not h.badw and all(math.isfinite(x) for x in out)
        worst=max(worst,max(abs(x) for x in out))
        if not ok: print("  FAIL effect",eff,"block",blk,end,h.badw[:3])
    print(f"  effect set {eff}: store {h.mu.mem_read(0x2406dc00,16).hex()} peak so far {worst:.2f}")

# ---- 3. boot: the clock constructor chain (J jctor -> L -> O -> P ctor), r4 = clock
CLK_SITE=0x080a7438; CLK_RET=0x080a743c
clk=0x24044000; h.allow(clk,clk+0x4000); h.mu.mem_write(clk,b"\0"*0x4000)
regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R4]=clk; regs[UC_ARM_REG_R3]=0x42f00000
h.mu.mem_write(0x2406be00,b"\xa5"*0x228)          # stale Keep CCs RAM: the ctor must clear it
def bw_target(at):
    hw1,hw2=struct.unpack_from("<HH",img,at-BASE)
    S=(hw1>>10)&1; J1=(hw2>>13)&1; J2=(hw2>>11)&1; I1=1-(J1^S); I2=1-(J2^S)
    off=(S<<24)|(I1<<23)|(I2<<22)|((hw1&0x3ff)<<12)|((hw2&0x7ff)<<1)
    if S: off-=1<<25
    return at+4+off
h.terminal={CLK_RET}
end=h.run(bw_target(CLK_SITE),regs,sp=sp,lr=0x0800fff1)
keep=h.mu.mem_read(0x2406be00,0x228)
print("3. clock ctor chain: end",hex(end) if isinstance(end,int) else end,"| clock+0x13c =",h.mu.mem_read(clk+0x13c,4).hex(),
      "| L_CLOCK/OSD_CLK =",h.mu.mem_read(0x2406daa4,4).hex(),h.mu.mem_read(0x2406dd40,4).hex(),
      "| Keep RAM cleared:",all(b==0 for b in keep[:0x220]) or keep[:16].hex(),"| badw",h.badw[:3])
h.terminal=set()

# ---- 4. registration chain at the uiflip registration (0x0806afb2)
REG_SITE=0x0806afb2
regd=[]
regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24046000; regs[UC_ARM_REG_R1]=0x78; regs[UC_ARM_REG_R2]=0x080c1000; regs[UC_ARM_REG_R3]=0x080c1104
h.mu.mem_write(sp,struct.pack("<III",5,0x080c1200,0))
end=h.run(bl_target(REG_SITE),regs,sp=sp,lr=0x0806afb7)
def cstr(a):
    try: return bytes(h.mu.mem_read(a,24)).split(b"\0")[0].decode()
    except Exception: return "?"
print("4. registration chain: end",hex(end) if isinstance(end,int) else end,"badw",h.badw[:3])
for c in h.calls:
    a,args=c[0],c[1]
    print("     stock",a,"id",args[1],"label",repr(cstr(int(args[2],16))))

# ---- 5. Settings posts: apply-all (0x0807e456) for our ids and a stock one
POST_A=0x0807e456; POST_RET=0x0807e45a
for pid in (0x13a,0x66,0x14b,0x166,0xb5,0x78):
    for v in (0,1,2,3):
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24023cb8; regs[UC_ARM_REG_R1]=0x400; regs[UC_ARM_REG_R2]=pid; regs[UC_ARM_REG_R3]=v
        h.mu.mem_write(sp,struct.pack("<II",0,0))
        end=h.run(bl_target(POST_A),regs,sp=sp,lr=POST_RET|1)
        ok= end==POST_RET and h.mu.reg_read(UC_ARM_REG_SP)==sp and all(h.mu.reg_read(r)==regs[r] for r in CS) and not h.badw
        if not ok: print("   POST FAIL",hex(pid),v,end,h.badw[:2])
    print(f"5. post id {pid:#x}: stock post called on last value: {[c[0] for c in h.calls]}  modes clk/osd/keep:",
          h.mu.mem_read(0x2406da88,4).hex(),h.mu.mem_read(0x2406dd00,4).hex(),h.mu.mem_read(0x2406be00,4).hex())

# ---- 6. engine block start (0x08095388), r0 = profiler
BLK=0x08095388; BLK_RET=0x0809538c
prof=0x24047000; h.allow(prof,prof+0x100); h.mu.mem_write(prof,struct.pack("<I",prof+0x40)+b"\0"*0x3c+struct.pack("<II",1000000,300000))
for i in range(5):
    regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=prof
    end=h.run(bl_target(BLK),regs,sp=sp,lr=BLK_RET|1)
    ok= end==BLK_RET and all(h.mu.reg_read(r)==regs[r] for r in CS) and not h.badw
print("6. block start chain: ok",ok,"end",hex(end) if isinstance(end,int) else end,"CPU avg/peak per-mille:",struct.unpack("<II",h.mu.mem_read(0x2406da98,8)),"stock:",[c[0] for c in h.calls])

# ---- 7. UI tick: the present call (0x0805b950), r0 = display object
DRAW=0x0805b950; DRAW_RET=0x0805b954
h.mu.mem_map(0x30000000,0x100000)
FRAME=320*240*2                       # writes past a frame are bad writes
for k in range(4): h.allow(0x30000000+k*0x26000,0x30000000+k*0x26000+FRAME)
disp=0x24048000; h.allow(disp,disp+0x400); h.mu.mem_write(disp,b"\0"*0x400)
for k,off in enumerate((0x120,0x12c,0x138,0x144)):
    h.mu.mem_write(disp+off,struct.pack("<IHH",0x30000000+k*0x26000,320,240))
h.mu.mem_write(0x2406da90,struct.pack("<I",0x484f4c44))   # K_MODE: bar on
# fresh CC so the pop-up has something to show
fr=bytearray(0x18); fr[0]=7; struct.pack_into("<III",fr,8,0,51,90<<7); h.mu.mem_write(sp+0x40,bytes(fr))
regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40
h.run(bl_target(POST_SITE),regs,sp=sp,lr=RET|1)
for t in range(4):
    regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=disp
    end=h.run(bl_target(DRAW),regs,sp=sp,lr=DRAW_RET|1)
    ok= end==DRAW_RET and all(h.mu.reg_read(r)==regs[r] for r in CS) and not h.badw
    lit=[sum(1 for i in range(0,0x26000,2) if h.mu.mem_read(0x30000000+k*0x26000+i,2)!=b"\0\0") for k in range(4)]
    print(f"7. UI tick {t}: ok={ok} end={hex(end) if isinstance(end,int) else end} pixels drawn per layer={lit} stock={[c[0] for c in h.calls]} badw={h.badw[:2]}")
    if t==0 and len(sys.argv)>2:      # picture of layer 0 for a look
        from PIL import Image
        raw=bytes(h.mu.mem_read(0x30000000,FRAME)); im=Image.new("RGB",(320,240))
        for i in range(320*240):
            v=raw[2*i]|raw[2*i+1]<<8      # ARGB1555
            im.putpixel((i%320,i//320),((v>>10&31)*8,(v>>5&31)*8,(v&31)*8))
        im.resize((640,480),Image.NEAREST).save(sys.argv[2])
    h.mu.mem_write(0x30000000,b"\0"*0x98000)
print("   OSD text:",bytes(h.mu.mem_read(0x2406dd58,56)).replace(b"\0",b"|"))
# a portrait layer (the micro's 240x320) must get nothing at all
for k,off in enumerate((0x120,0x12c,0x138,0x144)):
    h.mu.mem_write(disp+off,struct.pack("<IHH",0x30000000+k*0x26000,240,320))
regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=disp
end=h.run(bl_target(DRAW),regs,sp=sp,lr=DRAW_RET|1)
lit=[sum(1 for i in range(0,FRAME,2) if h.mu.mem_read(0x30000000+k*0x26000+i,2)!=b"\0\0") for k in range(4)]
print(f"7. UI tick, 240x320 layers: end={hex(end) if isinstance(end,int) else end} pixels drawn per layer={lit} (want all 0) badw={h.badw[:2]}")

# ---- 8. pad CCs through the OSD's pad recorders into hooks A and B
def bne_target(at):
    hw1,hw2=struct.unpack_from("<HH",img,at-BASE)
    S=(hw1>>10)&1; J1=(hw2>>13)&1; J2=(hw2>>11)&1
    off=(S<<20)|(J2<<19)|(J1<<18)|((hw1&0x3f)<<12)|((hw2&0x7ff)<<1)
    if S: off-=1<<21
    return at+4+off
CASES={84:"send",85:"send",86:"reverse",79:0x80b40fa,80:0x80b4160,81:0x80b3b10,82:0x80b413e,83:0x80b41a2,87:0x80b3c46,88:0x80b41f8,89:0x80b2168,91:0x80b3f86,92:0x80b3990,93:0x80b3f2e,120:0x80b30f4,123:0x80b30f4}
voice=0x24049000; h.allow(voice,voice+0x1000)
for site,vslot,ret,tag in ((0x080b336e,0x40,0x080b2168,"A"),(0x080b8dfe,0x38,0x080b867c,"B")):
    entry=bne_target(site); bad=0
    for cc in range(64,128):
        h.mu.mem_write(voice,b"\0"*0x1000)
        h.mu.mem_write(voice+0x575,b"\1"); h.mu.mem_write(voice+0x254,b"\1")
        h.mu.mem_write(sp+vslot,struct.pack("<I",100<<7))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R3]=cc; regs[UC_ARM_REG_R4]=voice; regs[UC_ARM_REG_R9]=0x24049800
        h.terminal=set(v for v in CASES.values() if isinstance(v,int))|{ret,0x80b8916,0x80a1868,0x80b7e10}
        end=h.run(entry,regs,sp=sp,lr=0x0800fff1,count=20000)
        if h.badw or end is None or isinstance(end,tuple): bad+=1; print("   PAD FAIL",tag,cc,end,h.badw[:2])
    print(f"8. pad hook {tag}: CC 64-127 through the recorder, {bad} failures; OSD ACC now {h.mu.mem_read(0x2406dd44,12).hex()}")
h.terminal=set()

# ---- 9. 2.3.10: the saved master bus (hook S + chr10's chr_post / UI-tick save)
GSTORE=0x2401d040; SAVE_FN=0x0808bdd8; SETP=0x080893b2
SAVE_IDS=(0x18d,0x18e,0x18f,0x191,0x192,0x193,0x195,0x196)
# a) boot: apply-all posts of the saved rows go to the C, not the engine
seed=(0, 64|64<<7|64<<14|64<<21, 0)
vals={0x18d:20|40<<7|60<<14|80<<21, 0x18e:10|20<<7|30<<14|40<<21, 0x18f:1|2<<7|3<<14|0<<21}
consumed=0
for pid in SAVE_IDS+(0x16b,):
    v=vals.get(pid,0) if pid!=0x16b else 2
    regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24023cb8; regs[UC_ARM_REG_R1]=0x400; regs[UC_ARM_REG_R2]=pid; regs[UC_ARM_REG_R3]=v
    h.mu.mem_write(sp,struct.pack("<II",0,0))
    end=h.run(bl_target(POST_A),regs,sp=sp,lr=POST_RET|1)
    ok= end==POST_RET and h.mu.reg_read(UC_ARM_REG_SP)==sp and all(h.mu.reg_read(r)==regs[r] for r in CS) and not h.badw
    stock_post=[c for c in h.calls if c[0] in ("0x8094de4",)]
    if ok and not stock_post: consumed+=1
    else: print("   SAVE POST",hex(pid),ok,end,[c[0] for c in h.calls],h.badw[:2])
print(f"9a. boot posts of the 8 saved rows + Comp Type: {consumed}/9 taken by the C, none to the engine")
print("    CHR store after restore:",h.mu.mem_read(0x2406dc00,24).hex())
# b) a live change, then UI ticks across ~2 s of DWT time: SetParam on the global store, then the settings.tml write
fr=bytearray(0x18); fr[0]=7; struct.pack_into("<III",fr,8,0,15,77<<7); h.mu.mem_write(sp+0x40,bytes(fr))
regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40
h.run(bl_target(POST_SITE),regs,sp=sp,lr=RET|1)
for k,off in enumerate((0x120,0x12c,0x138,0x144)):
    h.mu.mem_write(disp+off,struct.pack("<IHH",0x30000000+k*0x26000,320,240))
sets=[]; saves=[]
for t in range(10):
    h.mu.mem_write(0xE0001004,struct.pack("<I",(t*240_000_000)&0xffffffff))   # 0.5 s a tick at 480 MHz
    regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=disp
    end=h.run(bl_target(DRAW),regs,sp=sp,lr=DRAW_RET|1)
    if end!=DRAW_RET or h.badw: print("   UI TICK FAIL",t,end,h.badw[:2])
    sets+=[(t,c[1][1],c[1][2]) for c in h.calls if c[0]==hex(SETP) and c[1][0]==hex(GSTORE)]
    saves+=[(t,c[1][:3]) for c in h.calls if c[0]==hex(SAVE_FN)]
print("9b. SetParam(global store, id, value):",[(t,i) for t,i,v in sets][:12])
print("    settings.tml writes:",saves)
want=['0x240238b8','0x80c7134',hex(GSTORE)]
print("    write args as the Settings screen's:", bool(saves) and all(s[1]==want for s in saves))

# ---- 10. 2.3.10: compressor types -- CC 47 picks a type, the DSP call runs cmp_block
CMP_CALL=0x080983a8
for v in (40, 72, 104, 0):                 # Logical4, VariMu, Thunder, Stock
    for cc,val in ((47,v),(40,127),(41,127),(42,127),(43,64),(44,64),(45,64)):
        fr=bytearray(0x18); fr[0]=7; struct.pack_into("<III",fr,8,0,cc,val<<7); h.mu.mem_write(sp+0x40,bytes(fr))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=0x24011110; regs[UC_ARM_REG_R1]=sp+0x40
        end=h.run(bl_target(POST_SITE),regs,sp=sp,lr=RET|1)
    run=struct.unpack("<I",h.mu.mem_read(0x2406c104,4))[0]
    obj=0x2404a000; h.allow(obj,obj+0x2000); msg=0x2404c000; h.allow(msg,msg+0x400)
    bL=0x2404d000; bR=0x2404d400; h.allow(bL,bL+0x800)
    h.mu.mem_write(obj,b"\0"*0x2000); h.mu.mem_write(msg,b"\0"*0x400)
    h.mu.mem_write(obj,struct.pack("<I",obj+0x1f00))                    # its vtable ...
    h.mu.mem_write(obj+0x1f00+0x54,struct.pack("<I",0x080a340d))        # ... with the stock msg-override default
    def fetch(mu,addr,size,ud):
        if addr==0x080a4630:
            mu.mem_write(mu.reg_read(UC_ARM_REG_R1),struct.pack("<I",bL)); mu.mem_write(mu.reg_read(UC_ARM_REG_R2),struct.pack("<I",bR))
    hk=h.mu.hook_add(UC_HOOK_CODE,fetch,begin=0x080a4630,end=0x080a4630)
    h.ret0={0x080a9498:msg+0x100, 0x080a4588:48}
    import math
    bad=0
    for blk in range(12):
        h.mu.mem_write(bL,struct.pack("<96f",*[0.6*math.sin(i*0.2) for i in range(96)]))
        h.mu.mem_write(bR,struct.pack("<96f",*[0.6*math.sin(i*0.2) for i in range(96)]))
        regs={r:0x1000+i for i,r in enumerate(REGS)}; regs[UC_ARM_REG_R0]=obj; regs[UC_ARM_REG_R1]=msg
        end=h.run(bl_target(CMP_CALL),regs,sp=sp,lr=(CMP_CALL+4)|1)
        out=struct.unpack("<48f",h.mu.mem_read(bL,192))
        chg=max(abs(o-0.6*math.sin(i*0.2)) for i,o in enumerate(out))
        if end!=CMP_CALL+4 or h.badw or not all(math.isfinite(x) for x in out) or any(h.mu.reg_read(r)!=regs[r] for r in CS): bad+=1; print("   CMP FAIL",v,blk,end,h.badw[:2])
    h.mu.hook_del(hk); del h.ret0
    print(f"10. CC 47 = {v:3}: store run word {run:#010x}, 12 DSP blocks, {bad} failures, last block changed by {chg:.3f}, stock calls {sorted(set(c[0] for c in h.calls))}")
