#
# Manage method frame.
#

#
# Local variables.
#

Local: adt {				# local variable
	dtype:	byte;			# type of local (DIS_[BWLP])
	offset:	int;			# fp offset of this local
	next:	cyclic ref Local;	# for locals that are reused
};

frameoff:	int;			# tracks growth of frame
maxframe:	int;			# size of largest frame

#
# fp temporaries.
#

Fp: adt {
	dtype:	byte;
	refcnt:	int;
};

tmpslwm:	int;		# lowest temporary fp offset
tmpssz:		int;		# size of tmps array
tmps:		array of Fp;	# temporary arena

# fp temporary management starts here

incref(off: int)
{
	if(off >= tmpslwm)		# if <, then local variable
		tmps[off-tmpslwm].refcnt++;
}

acqreg(a: ref Addr)
{
	case int a.mode {
	int Anone or
	int Aimm or
	int Amp or
	int Ampind =>
		;
	int Afp =>
		incref(a.offset);
	int Afpind =>
		incref(a.ival);
	}
}

#
# Get fp offset of the next available register of the given type.
#

getoff(dtype: byte): int
{
	off: int;
	stride: int;

	if(dtype == DIS_L) {
		stride = IBY2LG;
		off = tmpslwm % IBY2LG;
	} else {
		stride = IBY2WD;
		off = 0;
	}
	while(off < tmpssz) {
		if(tmps[off].refcnt == 0
		&& (tmps[off].dtype == dtype || tmps[off].dtype == DIS_X)) {
			return off;
		}
		off += stride;
	}
	return off;
}

#
# Get a register (fp offset thereof) of the appropriate type.
#

getreg(dtype: byte): int
{
	off: int;
	oldsz: int;

	off = getoff(dtype);
	if(off >= tmpssz) {	# increase size of temporary arena
		oldsz = tmpssz;
		tmpssz += ALLOCINCR*IBY2LG;
		newtmps := array [tmpssz] of Fp;
		for(i := 0; i < oldsz; i++)
			newtmps[i] = tmps[i];
		for(i = oldsz; i < tmpssz; i++)
			newtmps[i] = Fp(byte 0, 0);
		tmps = newtmps;
	}
	tmps[off].dtype = dtype;
	if(dtype == DIS_L)	# also reserve next word
		tmps[off+IBY2WD].dtype = dtype;
	tmps[off].refcnt = 1;
	if(tmpslwm+off+cellsize[int dtype] > frameoff)
		frameoff = tmpslwm+off+cellsize[int dtype];
	return tmpslwm+off;
}

decref(off: int)
{
	if(off >= tmpslwm) {		# if <, then local variable
		if(--tmps[off-tmpslwm].refcnt < 0)
			fatal("decref: refcnt < 0");
	}
}

#
# "Free" register used by a.
#

relreg(a: ref Addr)
{
	case int a.mode {
	int Anone or
	int Aimm or
	int Amp or
	int Ampind =>
		;
	int Afp =>
		decref(a.offset);
	int Afpind =>
		decref(a.ival);
	}
}

#
# Mark all temporary fp registers as available.  Leave typing as is.
#

clearreg()
{
	i: int;

	i = 0;
	while(i < frameoff-tmpslwm) {
		tmps[i].refcnt = 0;
		i += IBY2WD;
	}
}

#
# Minimum stack extent size.
#

disstackext()
{
	discon(10*maxframe);
}

#
# WASM-specific frame management
#

wlocals:	array of ref Local;	# WASM local variables (params + locals)
nwlocals:	int;			# number of WASM locals

#
# Map WASM type to Dis type.
#

w2dtype(wtype: int): byte
{
	case wtype {
	I32 =>
		return DIS_W;
	I64 or F32 or F64 =>
		return DIS_L;
	}
	return DIS_W;  # default
}

#
# Reserve a frame cell for a WASM local variable.
#

reservewlocal(dtype: byte, ix: int)
{
	if(ix >= nwlocals) {
		oldsz := nwlocals;
		while(ix >= nwlocals)
			nwlocals += ALLOCINCR;
		newlocals := array [nwlocals] of ref Local;
		for(i := 0; i < oldsz; i++)
			newlocals[i] = wlocals[i];
		for(i = oldsz; i < nwlocals; i++)
			newlocals[i] = ref Local(byte 0, 0, nil);
		wlocals = newlocals;
	}
	if(wlocals[ix].dtype != byte 0)
		return;  # already reserved
	wlocals[ix].dtype = dtype;
	frameoff = align(frameoff, cellsize[int dtype]);
	wlocals[ix].offset = frameoff;
	frameoff += cellsize[int dtype];
}

#
# Return fp offset of a WASM local variable.
#

wlocaloffset(ix: int): int
{
	if(ix >= nwlocals)
		fatal("wlocaloffset: bad index " + string ix);
	return wlocals[ix].offset;
}

#
# Return type of a WASM local variable.
#

wlocaltype(ix: int): byte
{
	if(ix >= nwlocals)
		fatal("wlocaltype: bad index " + string ix);
	return wlocals[ix].dtype;
}

#
# Initialize local variables to 0 (WASM requires locals to be zero-initialized).
# Parameters are already initialized by the caller, so we only initialize
# the actual local variables (indices >= len functype.args).
#

winitlocals(functype: ref FuncType, wlocaltypes: array of ref Wlocal)
{
	if(wlocaltypes == nil)
		return;

	localidx := len functype.args;
	for(i := 0; i < len wlocaltypes; i++) {
		dtype := w2dtype(wlocaltypes[i].localtyp);
		for(j := 0; j < wlocaltypes[i].count; j++) {
			offset := wlocaloffset(localidx);
			# Generate mov $0, offset(fp) instruction
			case int dtype {
			int DIS_W =>
				inst := newi(IMOVW);
				addrimm(inst.s, 0);
				addrsind(inst.d, Afp, offset);
			int DIS_L =>
				inst := newi(IMOVL);
				addrimm(inst.s, 0);
				addrsind(inst.d, Afp, offset);
			}
			localidx++;
		}
	}
}

#
# Prepare frame for a WASM function.
#

wopenframe(functype: ref FuncType, wlocaltypes: array of ref Wlocal)
{
	frameoff = NREG * IBY2WD + 3 * IBY2WD;	# MaxTemp: skip fixed regs + temp slots
	nwlocals = 0;

	# reserve space for parameters
	for(i := 0; i < len functype.args; i++)
		reservewlocal(w2dtype(functype.args[i]), i);

	# reserve space for local variables
	localidx := len functype.args;
	if(wlocaltypes != nil) {
		for(i = 0; i < len wlocaltypes; i++) {
			dtype := w2dtype(wlocaltypes[i].localtyp);
			for(j := 0; j < wlocaltypes[i].count; j++)
				reservewlocal(dtype, localidx++);
		}
	}

	# align frame and initialize temp pool
	frameoff = align(frameoff, IBY2WD);
	tmpslwm = frameoff;
	tmpssz = frameoff;
	tmps = array [tmpssz] of { * => Fp(byte 0, 0) };
}

#
# Close a WASM function frame.
#

wcloseframe(): int
{
	tid: int;

	# frame size is always a multiple of 8
	frameoff = align(frameoff, IBY2LG);
	if(frameoff > maxframe)
		maxframe = frameoff;
	tid = wframedesc();
	wlocals = nil;
	nwlocals = 0;
	frameoff = 0;
	tmpslwm = 0;
	tmpssz = 0;
	tmps = nil;
	return tid;
}

#
# Calculate the type descriptor for a WASM frame (no pointers).
#

wframedesc(): int
{
	ln := frameoff / (8*IBY2WD) + (frameoff % (8*IBY2WD) != 0);
	map := array [ln] of { * => byte 0 };
	# WASM doesn't have pointer types, so no bits to set
	return descid(frameoff, ln, map);
}
