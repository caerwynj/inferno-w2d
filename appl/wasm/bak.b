implement Wasm;

#
# Derived by Vita Nuova Limited 1998 from /appl/wm/rt.b, which is
# Copyright © 1996-1999 Lucent Technologies Inc.  All rights reserved.
# Defined from /appl/lib/dis.b

include "sys.m";
	sys: Sys;
	sprint: import sys;

include "math.m";
	math: Math;

include "dis.m";

disptr: int;
disobj: array of byte;

I32: con -1;
I64: con -2;
F32: con -3;
F64: con -4;
FUNCREF: con -16r10;
FUNC: con -16r20;
VOID: cond -16r40;

optab := array[] of {
	"unreachable",	#0x00
	"nop",		#0x01
	"block",	#0x02
	"loop",		#0x03
	"if",		#0x04
	"else",		#0x05
	"",
	"",
	"",
	"",
	"",
	"end",		#0x0b
	"br",		#0x0c
	"br_if",	#0x0d
	"br_table",	#0x0e
	"return",	#0x0f
	"call",		#0x10
	"call_indirect", #0x11
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"drop",		#0x1a
	"select",	#0x1b
	"",
	"",
	"",
	"",
	"local.get",	#0x20
	"local.set",	#0x21
	"local.tee",	#0x22
	"global.get",	#0x23
	"global.set",	#0x24
	"",
	"",
	"",
	"i32.load",	#0x28
	"i64.load",	#0x29
	"f32.load",	#0x2a
	"f64.load",	#0x2b
	"i32.load8_s",	#0x2c
	"i32.load16_s",	#0x2e
	"i64.load8_s",	#0x30
	"i64.load16_s",	#0x32
	"i64.load32_s",	#0x34
	"i32.load8_u",	#0x2d
	"i32.load16_u",	#0x2f
	"i64.load8_u",	#0x31
	"i64.load16_u",	#0x33
	"i64.load32_u",	#0x35
	"i32.store",	#0x36
	"i64.store",	#0x37
	"f32.store",	#0x38
	"f64.store",	#0x39
	"i32.store8",	#0x3a
	"i32.store16",	#0x3b
	"i64.store8",	#0x3c
	"i64.store16",	#0x3d
	"i64.store32",	#0x3e
	"memory.size",	#0x3f
	"memory.grow",	#0x40
	"i32.const",	#0x41
	"i64.const",	#0x42
	"f32.const",	#0x43
	"f64.const",	#0x44
	"i32.eqz",	#0x45
	"i32.eq",	#0x46
	"i32.ne",	#0x47
	"i32.lt_s",	#0x48
	"i32.lt_u",	#0x49
	"i32.gt_s",	#0x4a
	"i32.gt_u",	#0x4b
	"i32.le_s",	#0x4c
	"i32.le_u",	#0x4d
	"i32.ge_s",	#0x4e
	"i32.ge_u",	#0x4f
	"i64.eqz",	#0x50
	"i64.eq",	#0x51
	"i64.ne",	#0x52
	"i64.lt_s",	#0x53
	"i64.lt_u",	#0x54
	"i64.gt_s",	#0x55
	"i64.gt_u",	#0x56
	"i64.le_s",	#0x57
	"i64.le_u",	#0x58
	"i64.ge_s",	#0x59
	"i64.ge_u",	#0x5a
	"f32.eq",	#0x5b
	"f32.ne",	#0x5c
	"f32.lt",	#0x5d
	"f32.gt",	#0x5e
	"f32.le",	#0x5f
	"f32.ge",	#0x60
	"f64.eq",	#0x61
	"f64.ne",	#0x62
	"f64.lt",	#0x63
	"f64.gt",	#0x64
	"f64.le",	#0x65
	"f64.ge",	#x066
	"i32.clz",	#0x67
	"i32.ctz",	#0x68
	"i32.popcnt",	#0x69
	"i32.add",	#0x6a
	"i32.sub",	#0x6b
	"i32.mul",	#0x6c
	"i32.div_s",	#0x6d
	"i32.div_u",	#0x6e
	"i32.rem_s",	#0x6f
	"i32.rem_u",	#0x70
	"i32.and",	#0x71
	"i32.or",	#0x72
	"i32.xor",	#0x73
	"i32.shl",	#0x74
	"i32.shr_s",	#0x75
	"i32.shr_u",	#0x76
	"i32.rotl",	#0x77
	"i32.rotr",	#0x78
	"i64.clz",	#0x79
	"i64.ctz",	#0x7a
	"i64.popcnt",	#0x7b
	"i64.add",	#0x7c
	"i64.sub",	#0x7d
	"i64.mul",	#0x7e
	"i64.div_s",	#0x7f
	"i64.div_u",	#0x80
	"i64.rem_s",	#0x81
	"i64.rem_u",	#0x82
	"i64.and",	#0x83
	"i64.or",	#0x84
	"i64.xor",	#0x85
	"i64.shl",	#0x86
	"i64.shr_s",	#0x87
	"i64.shr_u",	#0x88
	"i64.rotl",	#0x89
	"i64.rotr",	#0x8a
	"f32.abs",	#0x8b
	"f32.neg",	#0x8c
	"f32.ceil",	#0x8d
	"f32.floor",	#0x8e
	"f32.trunc",	#0x8f
	"f32.nearest",	#0x90
	"f32.sqrt",	#0x91
	"f32.add",	#0x92
	"f32.sub",	#0x93
	"f32.mul",	#0x94
	"f32.div",	#0x95
	"f32.min",	#0x96
	"f32.max",	#0x97
	"f32.copysign",	#0x98
	"f64.abs",	#0x99
	"f64.neg",	#0x9a
	"f64.ceil",	#0x9b
	"f64.floor",	#0x9c
	"f64.trunc",	#0x9d
	"f64.nearest",	#0x9e
	"f64.sqrt",	#0x9f
	"f64.add",	#0xa0
	"f64.sub",	#0xa1
	"f64.mul",	#0xa2
	"f64.div",	#0xa3
	"f64.min",	#0xa4
	"f64.max",	#0xa5
	"f64.copysign", #0xa6
	"i32.wrap_i64",		#0xa7
	"i32.trunc_f32_s",	#0xa8
	"i32.trunc_f32_u",	#0xa9
	"i32.trunc_f64_s",	#0xaa
	"i32.trunc_f64_u",	#0xab
	"i64.extend_i32_s",	#0xac
	"i64.extend_i32_u",	#0xad
	"i64.trunc_f32_s",	#0xae
	"i64.trunc_f32_u",	#0xaf
	"i64.trunc_f64_s",	#0xb0
	"i64.trunc_f64_u",	#0xb1
	"f32.convert_i32_s",	#0xb2
	"f32.convert_i32_u",	#0xb3
	"f32.convert_i64_s",	#0xb4
	"f32.convert_i64_u",	#0xb5
	"f32.demote_f64",	#0xb6
	"f64.convert_i32_s",	#0xb7
	"f64.convert_i32_u",	#0xb8
	"f64.convert_i64_s",	#0xb9
	"f64.convert_i64_u",	#0xba
	"f64.promote_f32",	#0xbb
	"i32.reinterpret_f32",	#0xbc
	"i64.reinterpret_f64",	#0xbd
	"f32.reinterpret_i32",	#0xbe
	"f64.reinterpret_i64",	#0xbf
	"i32.extend8_s",	#0xc0
	"i32.extend16_s",	#0xc1
	"i64.extend8_s",	#0xc2
	"i64.extend16_s",	#0xc3
	"i64.extend32_s",	#0xc4
};

init()
{
	sys = load Sys  Sys->PATH;
	math = load Math Math->PATH;	# optional
}

loadobj(disfile: string): (ref Mod, string)
{
	fd := sys->open(disfile, sys->OREAD);
	if(fd == nil)
		return (nil, "open failed: "+sprint("%r"));

	(ok, d) := sys->fstat(fd);
	if(ok < 0)
		return (nil, "stat failed: "+sprint("%r"));

	objlen := int d.length;
	disobj = array[objlen] of byte;

	if(sys->read(fd, disobj, objlen) != objlen){
		disobj = nil;
		return (nil, "read failed: "+sprint("%r"));
	}

	disptr = 0;
	m := ref Mod;
	m.magic = operand();
	if(m.magic == SMAGIC) {
		n := operand();
		m.sign = disobj[disptr:disptr+n];
		disptr += n;
		m.magic = operand();
	}
	if(m.magic != XMAGIC){
		disobj = nil;
		return (nil, "bad magic number");
	}

	m.rt = operand();
	m.ssize = operand();
	m.isize = operand();
	m.dsize = operand();
	m.tsize = operand();
	m.lsize = operand();
	m.entry = operand();
	m.entryt = operand();

	m.inst = array[m.isize] of ref Inst;
	for(i := 0; i < m.isize; i++) {
		o := ref Inst;
		o.op = int disobj[disptr++];
		o.addr = int disobj[disptr++];
		case o.addr & ARM {
		AXIMM or
		AXINF or
		AXINM =>
			o.mid = operand();
		}

		case (o.addr>>3) & 7 {
		AFP or
		AMP or
		AIMM =>
			o.src = operand();
		AIND|AFP or
		AIND|AMP =>
			o.src = operand()<<16;
			o.src |= operand();
		}

		case o.addr & 7	 {
		AFP or
		AMP or
		AIMM =>
			o.dst = operand();
		AIND|AFP or
		AIND|AMP =>
			o.dst = operand()<<16;
			o.dst |= operand();
		}
		m.inst[i] = o;
	}

	m.types = array[m.tsize] of ref Type;
	for(i = 0; i < m.tsize; i++) {
		h := ref Type;
		id := operand();
		h.size = operand();
		h.np = operand();
		h.map = disobj[disptr:disptr+h.np];
		disptr += h.np;
		m.types[i] = h;
	}

	for(;;) {
		op := int disobj[disptr++];
		if(op == 0)
			break;

		n := op & (DMAX-1);
		if(n == 0)
			n = operand();

		offset := operand();

		dat: ref Data;
		case op>>4 {
		DEFB =>
			dat = ref Data.Bytes(op, n, offset, disobj[disptr:disptr+n]);
			disptr += n;
		DEFW =>
			words := array[n] of int;
			for(i = 0; i < n; i++)
				words[i] = getw();
			dat = ref Data.Words(op, n, offset, words);
		DEFS =>
			dat = ref Data.String(op, n, offset, string disobj[disptr:disptr+n]);
			disptr += n;
		DEFF =>
			if(math != nil){
				reals := array[n] of real;
				for(i = 0; i < n; i++)
					reals[i] = math->bits64real(getl());
				dat = ref Data.Reals(op, n, offset, reals);
			} else {
				disptr += 8*n;	# skip it
				dat = ref Data.Reals(op, n, offset, nil);
			}
			break;
		DEFA =>
			typex := getw();
			length := getw();
			dat = ref Data.Array(op, n, offset, typex, length);
		DIND =>
			dat = ref Data.Aindex(op, n, offset, getw());
		DAPOP =>
			dat = ref Data.Arestore(op, n, offset);
		DEFL =>
			bigs := array[n] of big;
			for(i = 0; i < n; i++)
				bigs[i] = getl();
			dat = ref Data.Bigs(op, n, offset, bigs);
		* =>
			dat = ref Data.Zero(op, n, offset);
		}
		m.data = dat :: m.data;
	}

	m.data = revdat(m.data);

	m.name = gets();

	m.links = array[m.lsize] of ref Link;
	for(i = 0; i < m.lsize; i++) {
		l := ref Link;
		l.pc = operand();
		l.desc = operand();
		l.sig = getw();
		l.name = gets();

		m.links[i] = l;
	}

	if(m.rt & Dis->HASLDT0)
		raise "obsolete dis";

	if(m.rt & Dis->HASLDT){
		nl := operand();
		imps := array[nl] of array of ref Import;
		for(i = 0; i < nl; i++){
			n := operand();
			imps[i] = array[n] of ref Import;
			for(j := 0; j < n; j++){
				imps[i][j] = im := ref Import;
				im.sig = getw();
				im.name = gets();
			}
		}
		disptr++;
		m.imports = imps;
	}

	if(m.rt & Dis->HASEXCEPT){
		nh := operand();	# number of handlers
		hs := array[nh] of ref Handler;
		for(i = 0; i < nh; i++){
			h := hs[i] = ref Handler;
			h.eoff = operand();
			h.pc1 = operand();
			h.pc2 = operand();
			t := operand();
			if(t >= 0)
				h.t = m.types[t];
			n := operand();	
			h.ne = n>>16;
			n &= 16rffff;	# number of cases
			h.etab = array[n+1] of ref Except;
			for(j := 0; j < n; j++){
				e := h.etab[j] = ref Except;
				k := disptr;
				while(int disobj[disptr++])	# pattern
					;
				e.s = string disobj[k: disptr-1];
				e.pc = operand();
			}
			e := h.etab[j] = ref Except;
			e.pc = operand();	# * pc
		}
		disptr++;	# 0 byte
		m.handlers = hs;
	}

	m.srcpath = gets();

	disobj = nil;
	return (m, nil);
}

operand(): int
{
	if(disptr >= len disobj)
		return -1;

	b := int disobj[disptr++];

	case b & 16rC0 {
	16r00 =>
		return b;
	16r40 =>
		return b | ~16r7F;
	16r80 =>
		if(disptr >= len disobj)
			return -1;
		if(b & 16r20)
			b |= ~16r3F;
		else
			b &= 16r3F;
		return (b<<8) | int disobj[disptr++];
	16rC0 =>
		if(disptr+2 >= len disobj)
			return -1;
		if(b & 16r20)
			b |= ~16r3F;
		else
			b &= 16r3F;
		b = b<<24 |
			(int disobj[disptr]<<16) |
		    	(int disobj[disptr+1]<<8)|
		    	int disobj[disptr+2];
		disptr += 3;
		return b;
	}
	return 0;
}

get4(a: array of byte, i: int): int
{
	return (int a[i+0] << 24) | (int a[i+1] << 16) | (int a[i+2] << 8) | int a[i+3];
}

getw(): int
{
	if(disptr+3 >= len disobj)
		return -1;
	i := (int disobj[disptr+0]<<24) |
	     (int disobj[disptr+1]<<16) |
	     (int disobj[disptr+2]<<8) |
	      int disobj[disptr+3];

	disptr += 4;
	return i;
}

getl(): big
{
	if(disptr+7 >= len disobj)
		return big -1;
	i := (big disobj[disptr+0]<<56) |
	     (big disobj[disptr+1]<<48) |
	     (big disobj[disptr+2]<<40) |
	     (big disobj[disptr+3]<<32) |
	     (big disobj[disptr+4]<<24) |
	     (big disobj[disptr+5]<<16) |
	     (big disobj[disptr+6]<<8) |
	      big disobj[disptr+7];

	disptr += 8;
	return i;
}

gets(): string
{
	s := disptr;
	while(disptr < len disobj && disobj[disptr] != byte 0)
		disptr++;

	v := string disobj[s:disptr];
	disptr++;
	return v;
}

revdat(d: list of ref Data): list of ref Data
{
	t: list of ref Data;

	while(d != nil) {
		t = hd d :: t;
		d = tl d;
	}
	return t;
}

op2s(op: int): string
{
	if(op < 0 || op >= len optab)
		return sys->sprint("OP%d", op);
	return optab[op];
}

inst2s(o: ref Inst): string
{
	fi := 0;
	si := 0;
	s := sprint("%-10s", optab[o.op]);
	src := "";
	dst := "";
	mid := "";
	case (o.addr>>3) & 7 {
	AFP =>
		src = sprint("%x(fp)", o.src);
	AMP =>
		src = sprint("%x(mp)", o.src);
	AIMM =>
		src = sprint("$%d", o.src);
	AIND|AFP =>
		fi = (o.src>>16) & 16rFFFF;
		si = o.src & 16rFFFF;
		src = sprint("%x(%x(fp))", si, fi);
	AIND|AMP =>
		fi = (o.src>>16) & 16rFFFF;
		si = o.src & 16rFFFF;
		src = sprint("%x(%x(mp))", si, fi);
	}

	case o.addr & ARM {
	AXIMM =>
		mid = sprint("$%d", o.mid);
	AXINF =>
		mid = sprint("%x(fp)", o.mid);
	AXINM =>
		mid = sprint("%x(mp)", o.mid);
	}

	case o.addr & 7 {
	AFP =>
		dst = sprint("%x(fp)", o.dst);
	AMP =>
		dst = sprint("%x(mp)", o.dst);
	AIMM =>
		dst = sprint("$%d", o.dst);
	AIND|AFP =>
		fi = (o.dst>>16) & 16rFFFF;
		si = o.dst & 16rFFFF;
		dst = sprint("%x(%x(fp))", si, fi);
	AIND|AMP =>
		fi = (o.dst>>16) & 16rFFFF;
		si = o.dst & 16rFFFF;
		dst = sprint("%x(%x(mp))", si, fi);
	}
	if(mid == "") {
		if(src == "")
			s += sprint("%s", dst);
		else if(dst == "")
			s += sprint("%s", src);
		else
			s += sprint("%s, %s", src, dst);
	}
	else
		s += sprint("%s, %s, %s", src, mid, dst);

	return s;
}

getsb(fd: ref Sys->FD, o: int): (string, int)
{
	b := array[1] of byte;
	buf := array[8192] of byte;
	p := len buf;
	for( ; ; o++){
		sys->seek(fd, big -o, Sys->SEEKEND);
		if(sys->read(fd, b, 1) != 1)
			return (nil, 0);
		if(b[0] == byte 0){
			if(p < len buf)
				break;
		}
		else if(p > 0)
			buf[--p] = b[0];
	}
	return (string buf[p: ], o);
}

src(disf: string): string
{
	fd := sys->open(disf, sys->OREAD);
	if(fd == nil)
		return nil;
	(s, nil) := getsb(fd, 1);
	if(s != nil && s[0] == '/')
		return s;
	return nil;
}
