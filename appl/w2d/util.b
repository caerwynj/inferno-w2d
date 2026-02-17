#
# Utility functions.
#

#
# Align 'off' on an 'align'-byte boundary ('align' is a power of 2).
#

align(off: int, align: int): int
{
	align--;
	return (off + align) & ~align;
}

#
# Set 'offset' bit in type descriptor 'map'.
#

setbit(map: array of byte, offset: int)
{
	map[offset / (8*IBY2WD)] |= byte(1 << (7 - (offset / IBY2WD % 8)));
}

#
# Trivial hash function from asm.
#

hashval(s: string): int
{
	h, i: int;

	h = 0;
	for(i = 0; i < len s; i++)
		h = h*3 + s[i];
	if(h < 0)
		h = -h;
	return h % Hashsize;
}

#
# $i operands
#

addrimm(a: ref Addr, ival: int)
{
	a.mode = byte Aimm;
	a.ival = ival;
}

#
# Is an int too big to be an immediate operand?
#

notimmable(val: int): int
{
	return val < 0 && ((val >> 29) & 7) != 7 || val > 0 && (val >> 29) != 0;
}

#
# i(fp) and i(mp) operands
#

addrsind(a: ref Addr, mode: byte, off: int)
{
	a.mode = mode;
	a.offset = off;
}

#
# i(j(fp)) and i(j(mp)) operands
#

addrdind(a: ref Addr, mode: byte, fi: int, si: int)
{
	a.mode = mode;
	a.ival = fi;
	a.offset = si;
}

#
# Assign a register to a destination operand if not already done so.
#

dstreg(a: ref Addr, dtype: byte)
{
	if(a.mode == Afp && a.offset == -1)
		a.offset = getreg(dtype);
}

#
# Print a string.
#

pstring(s: string)
{
	slen, c: int;

	slen = len s;
	for(i := 0; i < slen; i++) {
		c = s[i];
		if(c == '\n')
			bout.puts("\\n");
		else if(c == '\t')
			bout.puts("\\t");
		else if(c == '"')
			bout.puts("\\\"");
		else if(c == '\\')
			bout.puts("\\\\");
		else
			bout.putc(c);
	}
}

#
# Die.
#

fatal(msg: string)
{
	print("fatal w2d error: %s\n", msg);
	if(bout != nil)
		sys->remove(ofile);
	reset();
	if(fabort) {
		p: ref Addr;
		if(p.mode == Anone);	# abort
	}
	exit;
}

verifyerrormess(mess: string)
{
	fatal("VerifyError: " + mess);
}

badpick(s: string)
{
	fatal("bad pick in " + s);
}

hex(v, n: int): string
{
	return sprint("%.*ux", n, v);
}

#
# Sanitize a function name to be a valid Limbo identifier.
# Replace hyphens and dots with underscores, and escape reserved keywords.
#

sanitizename(name: string): string
{
	s := "";
	for(i := 0; i < len name; i++) {
		c := name[i];
		if(c == '-' || c == '.')
			s += "_";
		else
			s[len s] = c;
	}
	# Escape Limbo reserved keywords by adding underscore suffix
	if(iskeyword(s))
		s += "_";
	return s;
}

iskeyword(s: string): int
{
	# Limbo reserved keywords that might conflict with WASM function names
	case s {
	"adt" or "alt" or "array" or "big" or "break" or "byte" or "case" or "chan" or
	"con" or "continue" or "cyclic" or "do" or "else" or "exception" or "exit" or
	"fn" or "for" or "hd" or "if" or "implement" or "import" or "include" or "int" or
	"len" or "list" or "load" or "module" or "nil" or "of" or "or" or "pick" or
	"raise" or "real" or "ref" or "return" or "self" or "spawn" or "string" or
	"tagof" or "tl" or "to" or "type" or "while" or "and" or "xor" =>
		return 1;
	}
	return 0;
}

#
# Size of frame cell of given type.
#

cellsize := array [int DIS_P + 1] of {
	0,		# DIS_X
	IBY2WD,		# DIS_W
	IBY2LG,		# DIS_L
	IBY2WD,		# DIS_P
};

#
# Enable consecutive runs of W2d->init() without having to reload.
#

reset()
{
	# desc.b
	dlist = nil;
	dtail = nil;
	id = 0;

	# dis.b
	ihead = nil;
	itail = nil;
	cache = nil;
	ncached = 0;
	ndatum = 0;
	startoff = 0;
	lastoff = 0;
	lastkind = -1;
	lencache = 0;
	ibuf = nil;
	nibuf = 0;

	# emit.b
	pcdis = 0;
	THISCLASS = nil;

	# entry.b
	pc = -1;
	tid = -1;

	# frame.b
	frameoff = 0;
	maxframe = 0;
	tmpslwm = 0;
	tmpssz = 0;
	tmps = nil;

	# links.b
	links = nil;
	nlinks = 0;

	# main.b
	gendis = 1;
	fabort = 0;
	genmod = 0;
	bout = nil;

	# wxlate.b imports
	nimportfuncs = 0;
	wimporttypes = nil;
	wimportmodidx = nil;
	wimportfuncidx = nil;
	wimportuniqmods = nil;
	nimportuniqmods = 0;
	wimpmodpathoff = nil;
	wimpmodptroff = nil;
}

#
# Convert WASM type to Limbo type name.
#

wtype2limbo(wtype: int): string
{
	case wtype {
	I32 =>
		return "int";
	I64 =>
		return "big";
	F32 or F64 =>
		return "real";
	}
	return "int";
}

#
# Generate a function declaration from a FuncType.
#

wfuncdecl(name: string, ft: ref FuncType): string
{
	s := "\t" + name + ": fn(";
	for(i := 0; i < len ft.args; i++) {
		if(i > 0)
			s += ", ";
		s += sprint("arg%d: %s", i, wtype2limbo(ft.args[i]));
	}
	s += ")";
	if(len ft.rets > 0)
		s += ": " + wtype2limbo(ft.rets[0]);
	s += ";\n";
	return s;
}

#
# Generate a .m module file from WASM exports.
#

genmodfile(m: ref Mod, basename: string)
{
	# Derive module name: capitalize first letter
	modname := basename;
	if(len modname > 0 && modname[0] >= 'a' && modname[0] <= 'z')
		modname[0] = modname[0] - 'a' + 'A';

	# Create .m file
	modfile := basename + ".m";
	fd := sys->create(modfile, Sys->OWRITE, 8r644);
	if(fd == nil) {
		print("w2d: can't create %s: %r\n", modfile);
		return;
	}

	# Write module header
	sys->fprint(fd, "%s: module\n{\n", modname);

	# Write init function declaration if module needs initialization
	# (has memory or imports)
	hasinit := 0;
	if(m.memorysection != nil && len m.memorysection.memories > 0)
		hasinit = 1;
	if(m.importsection != nil) {
		for(j := 0; j < len m.importsection.imports; j++) {
			pick imp := m.importsection.imports[j] {
			Func =>
				hasinit = 1;
			}
		}
	}
	if(hasinit)
		sys->fprint(fd, "\tinit: fn();\n");

	# Write function exports
	if(m.exportsection != nil) {
		for(i := 0; i < len m.exportsection.exports; i++) {
			exp := m.exportsection.exports[i];
			if(exp.kind != 0)	# only functions (kind=0)
				continue;

			# Get function type
			funcidx := exp.idx;
			# Account for imports - they come before module functions
			nimports := 0;
			if(m.importsection != nil) {
				for(j := 0; j < len m.importsection.imports; j++) {
					pick imp := m.importsection.imports[j] {
					Func =>
						nimports++;
					}
				}
			}

			typeidx: int;
			if(funcidx < nimports) {
				# It's an imported function - get type from import
				impidx := 0;
				for(j := 0; j < len m.importsection.imports; j++) {
					pick imp := m.importsection.imports[j] {
					Func =>
						if(impidx == funcidx) {
							typeidx = imp.typeidx;
							break;
						}
						impidx++;
					}
				}
			} else {
				# It's a module function
				localidx := funcidx - nimports;
				if(m.funcsection == nil || localidx >= len m.funcsection.funcs)
					continue;
				typeidx = m.funcsection.funcs[localidx];
			}

			if(m.typesection == nil || typeidx >= len m.typesection.types)
				continue;

			ft := m.typesection.types[typeidx];
			fname := sanitizename(exp.name);
			sys->fprint(fd, "%s", wfuncdecl(fname, ft));
		}
	}

	# Write module footer
	sys->fprint(fd, "};\n");
}
