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

		case section {
		STYPE =>
			m.typesection = ref TypeSection;
			m.typesection.size = slen;
			vlen := operand();
			m.typesection.types = array[vlen] of {* => ref FuncType(nil, nil)};
			t := 0;
			while (vlen > 0) {
				getb();  # functype marker
				vallen := operand();
				ba := array[vallen] of int;
				i := 0;
				while(vallen > 0) {
					vb := getb();
					ba[i++] = vb;
					vallen--;
				}
				m.typesection.types[t].args = ba;
				vallen = operand();
				ba = array[vallen] of int;
				i = 0;
				while(vallen > 0) {
					vb := getb();
					ba[i++] = vb;
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
				m.funcsection.funcs[i++] = typeidx;
				vlen--;
			}
		SCODE =>
			# Skip code section parsing - just skip past it
			wasmptr += slen;
		SEXPORT =>
			m.exportsection = ref ExportSection;
			m.exportsection.size = slen;
			vlen := operand();
			m.exportsection.exports = array[vlen] of ref Export;
			i := 0;
			while (vlen > 0) {
				name := gets();
				kind := getb();
				idx := operand();
				m.exportsection.exports[i++] = ref Export(name, kind, idx);
				vlen--;
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
