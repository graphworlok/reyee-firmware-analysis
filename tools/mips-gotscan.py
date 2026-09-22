#!/usr/bin/env python3
"""
mips-gotscan.py - resolve call sites in the section-stripped MIPS32 LE
ReyeeOS easyson builds (2.380 / 2.388).

Why this exists
---------------
These binaries have their SECTION headers stripped but an intact .dynsym
reachable through PT_DYNAMIC, so readelf -s and any section-based tool
reports nothing while the names are in fact all present.

They are also compiled WITHOUT optimisation, so the PIC call idiom is:

    lw    v0, off(gp)        # GOT slot for the callee -> $v0, NOT $t9
    nop
    addu  t9, v0, zero
    jalr  ra, t9

Scanning for "lw $t9, off($gp)" therefore misses ~97% of all calls
(easyson_2380.elf: 7,567 "jalr $t9" vs 218 "lw $t9,off($gp)") and returns
a confident false negative. This scans for "lw <any reg>, off($gp)".

Always sanity-check against a symbol whose call count you can predict:
snprintf must resolve to 385 sites in 75 functions on easyson_2380.elf,
13 of them in esw_disc_handle_hello_msg, matching its decompilation.
A scan that returns 0 for snprintf is broken.

Usage
-----
    python mips-gotscan.py <elf> <symbol> [symbol ...]
    python mips-gotscan.py <elf> --slots 0x4b3984-0x4b39b0   # local GOT table

Written 2026-09-20; used to close open items 2 and 4 in HANDOFF.md.
"""
import struct
import sys
import bisect

DT_PLTGOT, DT_STRTAB, DT_SYMTAB, DT_SYMENT, DT_HASH = 3, 5, 6, 11, 4
DT_MIPS_LOCAL_GOTNO = 0x7000000a
DT_MIPS_SYMTABNO = 0x70000011
DT_MIPS_GOTSYM = 0x70000013


class ELF:
    def __init__(self, path):
        self.path = path
        d = self.d = open(path, 'rb').read()
        if d[:4] != b'\x7fELF' or d[4] != 1:
            raise SystemExit(path + ": not a 32-bit ELF")
        self.e = '<' if d[5] == 1 else '>'
        hdr = struct.unpack_from(self.e + 'HHIIIIIHHHHHH', d, 16)
        phoff, phentsize, phnum = hdr[4], hdr[8], hdr[9]
        self.ph = []
        for i in range(phnum):
            typ, off, vaddr, _pa, filesz, _ms, flags, _al = struct.unpack_from(
                self.e + '8I', d, phoff + i * phentsize)
            self.ph.append(dict(type=typ, off=off, vaddr=vaddr,
                                filesz=filesz, flags=flags))
        self.load = [p for p in self.ph if p['type'] == 1]

    def v2o(self, va):
        for p in self.load:
            if p['vaddr'] <= va < p['vaddr'] + p['filesz']:
                return p['off'] + (va - p['vaddr'])
        return None

    def cstr(self, va):
        o = self.v2o(va)
        return self.d[o:self.d.index(b'\0', o)].decode('utf-8', 'replace')

    def dyn(self):
        p = [x for x in self.ph if x['type'] == 2][0]
        tags = {}
        for o in range(p['off'], p['off'] + p['filesz'], 8):
            t, v = struct.unpack_from(self.e + 'II', self.d, o)
            if t == 0:
                break
            tags.setdefault(t, v)
        return tags

    def dynsyms(self):
        t = self.dyn()
        n = t.get(DT_MIPS_SYMTABNO)
        if n is None:
            ho = self.v2o(t[DT_HASH])
            n = struct.unpack_from(self.e + 'II', self.d, ho)[1]
        base = self.v2o(t[DT_SYMTAB])
        strtab = t[DT_STRTAB]
        ent = t.get(DT_SYMENT, 16)
        out = []
        for i in range(n):
            nm, value, size, info, _o, _sh = struct.unpack_from(
                self.e + 'IIIBBH', self.d, base + i * ent)
            out.append(dict(idx=i, name=self.cstr(strtab + nm), value=value,
                            size=size, type=info & 0xf))
        return out


class Image:
    def __init__(self, path):
        self.elf = ELF(path)
        t = self.elf.dyn()
        self.pltgot = t[DT_PLTGOT]
        self.local_gotno = t[DT_MIPS_LOCAL_GOTNO]
        self.gotsym = t[DT_MIPS_GOTSYM]
        self.gp = self.pltgot + 0x7ff0
        self.extbase = self.pltgot + self.local_gotno * 4
        self.syms = self.elf.dynsyms()
        self.slot_of = {}
        self.name_of = {}
        for s in self.syms:
            if s['idx'] >= self.gotsym:
                a = self.pltgot + (self.local_gotno + (s['idx'] - self.gotsym)) * 4
                self.slot_of.setdefault(s['name'], a)
                self.name_of.setdefault(a, s['name'])
        self.funcs = sorted([s for s in self.syms if s['type'] == 2 and s['value']],
                            key=lambda s: s['value'])
        self._fa = [f['value'] for f in self.funcs]
        self._byaddr = {f['value']: f['name'] for f in self.funcs}
        self.text = [p for p in self.elf.load if p['flags'] & 1][0]

    def by_addr(self, a):
        return self._byaddr.get(a)

    def owner(self, va):
        """Enclosing named function, or None when va is inside a static one."""
        i = bisect.bisect_right(self._fa, va) - 1
        if i < 0:
            return None
        f = self.funcs[i]
        if f['size'] and va >= f['value'] + f['size']:
            return None
        return f['name']

    def func_start(self, va):
        """Walk back to the 'lui gp, imm' that opens every PIC function."""
        a = va
        while a > self.text['vaddr']:
            if struct.unpack_from('<I', self.elf.d, self.elf.v2o(a))[0] >> 16 == 0x3c1c:
                return a
            a -= 4
        return None

    def gp_loads(self):
        """Yield (vaddr, target_got_addr) for every 'lw <reg>, off($gp)'."""
        t = self.text
        d = self.elf.d
        for off in range(t['off'], t['off'] + t['filesz'] - 4, 4):
            w = struct.unpack_from('<I', d, off)[0]
            if (w >> 26) != 0x23 or ((w >> 21) & 31) != 28:
                continue
            imm = w & 0xffff
            if imm & 0x8000:
                imm -= 0x10000
            yield t['vaddr'] + (off - t['off']), self.gp + imm

    def ptr_at(self, va):
        return struct.unpack_from('<I', self.elf.d, self.elf.v2o(va))[0]


def report(path, names):
    im = Image(path)
    print("=== " + path)
    print("  DT_PLTGOT 0x%x  LOCAL_GOTNO 0x%x  GOTSYM 0x%x"
          % (im.pltgot, im.local_gotno, im.gotsym))
    print("  $gp = 0x%x   external GOT from 0x%x   %d named functions"
          % (im.gp, im.extbase, len(im.funcs)))
    sites = {}
    for va, tgt in im.gp_loads():
        sites.setdefault(tgt, []).append(va)
    for n in names:
        if n not in im.slot_of:
            print("\n  !! %s: no GOT slot (not an imported dynsym)" % n)
            continue
        a = im.slot_of[n]
        ss = sites.get(a, [])
        byf = {}
        for va in ss:
            byf.setdefault(im.owner(va) or '<static>', []).append(va)
        print("\n  %s  slot 0x%x  lw <reg>,%d(gp)  ->  %d site(s) in %d function(s)"
              % (n, a, a - im.gp, len(ss), len(byf)))
        for fn in sorted(byf, key=lambda k: byf[k][0]):
            addrs = " ".join("0x%x" % v for v in byf[fn][:8])
            print("      %-44s x%-3d %s" % (fn, len(byf[fn]), addrs))


def dump_slots(path, lo, hi):
    """Resolve a local-GOT handler table, e.g. the eap dispatcher's."""
    im = Image(path)
    print("=== %s  local GOT 0x%x..0x%x" % (path, lo, hi))
    for a in range(lo, hi + 4, 4):
        p = im.ptr_at(a)
        print("   0x%08x -> 0x%08x  %s" % (a, p, im.by_addr(p) or '<static>'))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    if sys.argv[2] == '--slots':
        lo, _, hi = sys.argv[3].partition('-')
        dump_slots(sys.argv[1], int(lo, 16), int(hi, 16))
    else:
        report(sys.argv[1], sys.argv[2:])
