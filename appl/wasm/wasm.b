implement Wasm;
include "sys.m";
	sys: Sys;
	sprint: import sys;

include "math.m";
	math: Math;

include "wasm.m";
include "optab.m";

wasmptr: int;
wasmobj: array of byte;

FUNCREF: con -16r10;
FUNC: con -16r20;
VOID: con -16r40;
BLOCK: con 16r40;


init()
{
	sys = load Sys  Sys->PATH;
	math = load Math Math->PATH;	# optional
}

loadobj(wasmfile: string): (ref Mod, string)
{
	fd := sys->open(wasmfile, sys->OREAD);
	if(fd == nil)
		return (nil, "open failed: "+sprint("%r"));

	(ok, d) := sys->fstat(fd);
	if(ok < 0)
		return (nil, "stat failed: "+sprint("%r"));

	objlen := int d.length;
	wasmobj = array[objlen] of byte;

	if(sys->read(fd, wasmobj, objlen) != objlen){
		wasmobj = nil;
		return (nil, "read failed: "+sprint("%r"));
	}

	wasmptr = 0;
	m := ref Mod;
	m.magic = getw();
	if(m.magic != Wasm->MAGIC){
		wasmobj = nil;
		return (nil, sys->sprint("bad magic number %x", m.magic));
	}
	m.version = getw();

	while(wasmptr < len wasmobj) {
		section := operand();
		slen := operand();
		sys->print("%s len %d\n", sectab[section], slen);

		case section {
		STYPE =>
			m.typesection = ref TypeSection;
			m.typesection.size = slen;
			vlen := operand();
			sys->print("TYPE vlen %d\n", vlen);
			m.typesection.types = array[vlen] of {* => ref FuncType(nil, nil)};
			t := 0;
			while (vlen > 0) {
				b := getb();
				sys->print("functype %x\n", b);
				vallen := operand();
				ba := array[vallen] of int;
				i := 0;
				while(vallen > 0) {
					vb := getb();
					ba[i++] = vb;
					sys->print("arg typ %x\n", vb);
					vallen--;
				}
				m.typesection.types[t].args = ba;
				vallen = operand();
				ba = array[vallen] of int;
				i = 0;
				while(vallen > 0) {
					vb := getb();
					ba[i++] = vb;	
					sys->print("res typ %x\n", vb);
					vallen--;
				}
				m.typesection.types[t].rets = ba;	
				vlen--;
				t++;
			}
		SIMPORT =>
			m.importsection = ref ImportSection;
			m.importsection.size = slen;
			vlen := operand();
			m.importsection.imports = array[vlen] of ref Import;
			i := 0;
			while (vlen > 0) {
				modname := gets();
				name := gets();
				desc := getb();
				sys->print("IMPORT: %s %s %d\n", modname, name, desc);
				case desc {
				16r0 =>
					typeidx := operand();
					m.importsection.imports[i++] = ref Import.Func(modname, name, desc, typeidx);
				16r1 =>
					elemtype := getb();
					lb := getb();
					min, max: int;
					min = operand();
					if (lb == 0) max = -1;
					else max = operand();
					m.importsection.imports[i++] = ref Import.Table(modname, name, desc, min, max);
				16r2 =>
					lb := getb();
					min, max: int;
					min = operand();
					if (lb == 0) max = -1;
					else max = operand();
					m.importsection.imports[i++] = ref Import.Mem(modname, name, desc, min, max);
				16r3 =>
					valtyp := getb();
					mut := getb();
					m.importsection.imports[i++] = ref Import.Global(modname, name, desc, valtyp, mut);
				* =>
					sys->print("import error\n");
				}
				vlen--;
			}	
			#wasmptr += slen;
		SFUNC =>
			m.funcsection = ref FuncSection;
			m.funcsection.size = slen;
			vlen := operand();
			m.funcsection.funcs = array[vlen] of int;
			i := 0;
			while (vlen > 0) {
				typeidx := getb();
				sys->print("SFUNC %d\n", typeidx);
				m.funcsection.funcs[i++] = typeidx;
				vlen--;
			}
			#wasmptr += slen;
		SCODE =>
			m.codesection = ref CodeSection;
			m.codesection.size = slen;
			vlen := operand();
			m.codesection.codes = array[vlen] of ref Code;
			i := 0;
			while (vlen > 0) {
				codesize := operand();
				localsize := operand();
				sys->print("vlen %d code len %d bytes; codesize %d, localsize %d\n", vlen, slen, codesize, localsize);
				locs := array[localsize] of ref Local;
				j := 0;
				while(localsize > 0){
					localcnt := operand();
					localtyp := getb();
					sys->print("local %d 0x%x\n", localcnt, localtyp);
					locs[j++] = ref Local(localcnt, localtyp);
					localsize--;
				}
				opcode := getb();
				l : list of ref Winst;
				while(opcode != 16r0b){
					#sys->print("opcode 0x%x %s\n", opcode, optab[opcode]);
					case opcode {
					II32_LOAD or II64_LOAD or IF32_LOAD or IF64_LOAD or
					II32_LOAD8_S or II32_LOAD8_U or II32_LOAD16_S or II32_LOAD16_U or
					II64_LOAD8_S or II64_LOAD8_U or II64_LOAD16_S or II64_LOAD16_U or
					II64_LOAD32_S or II64_LOAD32_U or
					II32_STORE or II64_STORE or IF32_STORE or IF64_STORE or
					II32_STORE8 or II32_STORE16 or II64_STORE8 or II64_STORE16 or II64_STORE32
					=>
						align := operand();
						offset := operand();
						sys->print("%s %d %d\n", optab[opcode], align, offset);
						l = ref Winst(opcode, align, offset) :: l;
					ILOCAL_GET or ILOCAL_SET or ILOCAL_TEE or IGLOBAL_GET or IGLOBAL_SET =>
						n := operand();
						sys->print("%s %d\n", optab[opcode], n);
						l = ref Winst(opcode, n, -1) :: l;
					IBR or IBR_IF or ICALL or ICALL_INDIRECT =>
						idx := operand();
						sys->print("%s %d\n", optab[opcode], idx);
						l = ref Winst(opcode, idx, -1) :: l;
					II32_CONST or II64_CONST =>
						n := operand();
						sys->print("%s %d\n", optab[opcode], n);
						l = ref Winst(opcode, n, -1) :: l;
					IF32_CONST or IF64_CONST =>
						n := operand();
						sys->print("%s %d\n", optab[opcode], n);
						l = ref Winst(opcode, n, -1) :: l;
					* =>
						sys->print("%s\n", optab[opcode]);
						l = ref Winst(opcode, -1, -1) :: l;
						;
					}
					opcode = getb();
				}
				vlen--;
				rl := array[len l] of ref Winst;
				for(k := len l - 1; l != nil; l = tl l) 
					rl[k--] = hd l;
				m.codesection.codes[i++] = ref Code(codesize, locs, rl);
			}
		* =>
			wasmptr += slen;
		}
	}

	wasmobj = nil;
	return (m, nil);
}

operand(): int
{
	if(wasmptr >= len wasmobj)
		return -1;

	d := 0;
	shift := 0;	

	for(;;) {
		b := int wasmobj[wasmptr++];
		#sys->print("%d: %x\n", wasmptr-1, b);
		case b & 16r80 {
		16r00 =>
			d |= (b << shift);
			return d;
		16r80 =>
			d |= ((b & 16r7F) << shift);
			shift += 7;
		}
		if(wasmptr >= len wasmobj)
			return -1;
	}
	return 0;
}

get4(a: array of byte, i: int): int
{
	return (int a[i+0] << 24) | (int a[i+1] << 16) | (int a[i+2] << 8) | int a[i+3];
}

getb(): int
{
	return int wasmobj[wasmptr++];
}

getw(): int
{
	if(wasmptr+3 >= len wasmobj)
		return -1;
	i := (int wasmobj[wasmptr+0]) |
	     (int wasmobj[wasmptr+1]<<8) |
	     (int wasmobj[wasmptr+2]<<16) |
	      int wasmobj[wasmptr+3]<<24;

	wasmptr += 4;
	return i;
}

gets(): string
{
	n := getb();
	s := wasmptr;

	v := string wasmobj[s:wasmptr+n];
	wasmptr += n;
	return v;
}

op2s(op: int): string
{
	if(op < 0 || op >= len optab)
		return sys->sprint("OP%d", op);
	return optab[op];
}
