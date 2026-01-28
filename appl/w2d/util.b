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
	bout = nil;
}
