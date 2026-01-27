#
# Compute DIS link signature from WASM function type.
# Builds a type signature string (e.g., f(i,i)i) and
# MD5 hashes it, then XOR-folds to 4 bytes.
#

wsigchar(wtype: int): string
{
	case wtype {
	I32 =>
		return "i";
	I64 =>
		return "B";
	F32 or F64 =>
		return "r";
	}
	return "i";
}

wfuncsig(ft: ref FuncType): int
{
	i: int;

	# Build signature string like f(i,i)i
	s := "f(";
	for(i = 0; i < len ft.args; i++) {
		if(i > 0)
			s += ",";
		s += wsigchar(ft.args[i]);
	}
	s += ")";
	for(i = 0; i < len ft.rets; i++)
		s += wsigchar(ft.rets[i]);

	# MD5 hash
	buf := array of byte s;
	kr := load Keyring Keyring->PATH;
	md5sig := array[Keyring->MD5dlen] of { * => byte 0 };
	kr->md5(buf, len buf, md5sig, nil);

	# XOR-fold 16 bytes into 4 bytes (little-endian)
	sig := 0;
	for(i = 0; i < Keyring->MD5dlen; i += 4)
		sig ^= int md5sig[i+0] | (int md5sig[i+1]<<8) | (int md5sig[i+2]<<16) | (int md5sig[i+3]<<24);

	return sig;
}

#
# Translate WASM instructions to Dis instructions.
#

Wi: ref Winst;
wpc: int;			# current WASM instruction index
wcodes: array of ref Winst;	# current function's code
wftype: ref FuncType;		# current function's type

#
# Labels for branch targets - maps WASM pc to Dis pc
#
wlabels: array of int;

#
# Get Dis move instruction for WASM type.
#

wmovinst(wtype: int): int
{
	case wtype {
	I32 =>
		return IMOVW;
	I64 =>
		return IMOVL;
	F32 or F64 =>
		return IMOVF;
	}
	return IMOVW;
}

#
# Get Dis move instruction for Dis type.
#

dmoveinst(dtype: byte): int
{
	case int dtype {
	int DIS_W =>
		return IMOVW;
	int DIS_L =>
		return IMOVL;
	}
	return IMOVW;
}

#
# Get source operand from stack position (relative to current instruction).
# n=0 is the top of stack, n=1 is second from top, etc.
#

wsrc(n: int): ref Addr
{
	# Find the producer instruction for the nth stack value
	# This is determined during simulation - the value's dst address
	# was allocated at that time
	depth := 0;
	for(pc := wpc - 1; pc >= 0 && depth <= n; pc--) {
		w := wcodes[pc];
		if(w.dst != nil) {
			if(depth == n)
				return w.dst;
			depth++;
		}
	}
	fatal("wsrc: could not find stack operand " + string n);
	return nil;
}

#
# Translate i32 binary arithmetic operation.
#

xi32binop(disop: int)
{
	i := newi(disop);
	*i.s = *wsrc(1);	# first operand (deeper in stack)
	*i.m = *wsrc(0);	# second operand (top of stack)
	*i.d = *Wi.dst;
}

#
# Translate i64 binary arithmetic operation.
#

xi64binop(disop: int)
{
	i := newi(disop);
	*i.s = *wsrc(1);
	*i.m = *wsrc(0);
	*i.d = *Wi.dst;
}

#
# Translate f32/f64 binary operation.
#

xfbinop(disop: int)
{
	i := newi(disop);
	*i.s = *wsrc(1);
	*i.m = *wsrc(0);
	*i.d = *Wi.dst;
}

#
# Translate i32 comparison to a conditional set.
# WASM comparisons push 1 or 0; Dis uses branches.
# We implement this by: set dst=1, then conditionally set dst=0.
#

xi32cmp(disbranchop: int)
{
	# Set destination to 1 (true)
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	# Branch over the "set to 0" if condition is true
	ibr := newi(disbranchop);
	*ibr.s = *wsrc(1);
	*ibr.m = *wsrc(0);
	addrimm(ibr.d, pcdis + 1);  # skip next instruction

	# Set destination to 0 (false)
	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate i64 comparison.
#

xi64cmp(disbranchop: int)
{
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	ibr := newi(disbranchop);
	*ibr.s = *wsrc(1);
	*ibr.m = *wsrc(0);
	addrimm(ibr.d, pcdis + 1);

	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate f32/f64 comparison.
#

xfcmp(disbranchop: int)
{
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	ibr := newi(disbranchop);
	*ibr.s = *wsrc(1);
	*ibr.m = *wsrc(0);
	addrimm(ibr.d, pcdis + 1);

	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate eqz (compare with zero).
#

xi32eqz()
{
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	ibr := newi(IBEQW);
	*ibr.s = *wsrc(0);
	addrimm(ibr.m, 0);
	addrimm(ibr.d, pcdis + 1);

	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate i64 eqz.
#

xi64eqz()
{
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	ibr := newi(IBEQL);
	*ibr.s = *wsrc(0);
	addrimm(ibr.m, 0);
	addrimm(ibr.d, pcdis + 1);

	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate a single WASM instruction to Dis.
#

xlatwinst()
{
	i: ref Inst;

	# Record label for this instruction
	wlabels[wpc] = pcdis;

	case Wi.opcode {
	# unreachable and nop
	Wunreachable =>
		# Generate a trap/exit
		i = newi(IEXIT);

	Wnop =>
		i = newi(INOP);

	# control flow - handled specially
	Wblock or Wloop or Wif or Welse or Wend =>
		;  # control flow structure, no direct instruction

	Wbr =>
		i = newi(IJMP);
		# target will be patched later
		addrimm(i.d, Wi.arg1);  # temporarily store label index

	Wbr_if =>
		# Branch if top of stack is non-zero
		i = newi(IBNEW);
		*i.s = *wsrc(0);
		addrimm(i.m, 0);
		addrimm(i.d, Wi.arg1);  # temporarily store label index

	Wreturn =>
		# Copy return value if any
		if(len wftype.rets > 0) {
			imov := newi(wmovinst(wftype.rets[0]));
			*imov.s = *wsrc(0);
			addrdind(imov.d, Afpind, WREGRET, 0);
		}
		i = newi(IRET);

	Wcall =>
		# For now, generate a placeholder
		# Real implementation needs to handle function table
		i = newi(INOP);

	# parametric instructions
	Wdrop =>
		# No Dis instruction needed, register already released in sim
		;

	Wselect =>
		# select(c, v1, v2) = c ? v1 : v2
		# Implement as: dst = v1; if(c==0) dst = v2
		imov1 := newi(IMOVW);
		*imov1.s = *wsrc(2);  # v1
		*imov1.d = *Wi.dst;

		ibr := newi(IBNEW);
		*ibr.s = *wsrc(0);  # c (condition)
		addrimm(ibr.m, 0);
		addrimm(ibr.d, pcdis + 1);

		imov2 := newi(IMOVW);
		*imov2.s = *wsrc(1);  # v2
		*imov2.d = *Wi.dst;

	# variable instructions
	Wlocal_get =>
		i = newi(dmoveinst(wlocaltype(Wi.arg1)));
		addrsind(i.s, Afp, wlocaloffset(Wi.arg1));
		*i.d = *Wi.dst;

	Wlocal_set =>
		i = newi(dmoveinst(wlocaltype(Wi.arg1)));
		*i.s = *wsrc(0);
		addrsind(i.d, Afp, wlocaloffset(Wi.arg1));

	Wlocal_tee =>
		# Copy top of stack to local, leave value on stack
		i = newi(dmoveinst(wlocaltype(Wi.arg1)));
		*i.s = *wsrc(0);
		addrsind(i.d, Afp, wlocaloffset(Wi.arg1));

	Wglobal_get =>
		# Globals would need module data support
		# For now, generate placeholder
		i = newi(IMOVW);
		addrimm(i.s, 0);
		*i.d = *Wi.dst;

	Wglobal_set =>
		# Placeholder for global set
		;

	# memory instructions - loads
	Wi32_load =>
		# Load 32-bit value from memory
		# address = base (from stack) + offset (from instruction)
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);		# base address from stack
		addrimm(iadd.m, Wi.arg2);	# offset from instruction
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVW);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	Wi32_load8_s =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(ICVTBW);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	Wi32_load8_u =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		# Load byte
		i = newi(IMOVB);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	Wi32_load16_s or Wi32_load16_u =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		# Load 16-bit (would need sign extension for _s)
		i = newi(IMOVW);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	Wi64_load =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVL);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	Wf32_load or Wf64_load =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(0);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVF);
		addrdind(i.s, Afpind, iadd.d.offset, 0);
		*i.d = *Wi.dst;
		relreg(iadd.d);

	# memory instructions - stores
	Wi32_store =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(1);		# address from stack
		addrimm(iadd.m, Wi.arg2);	# offset
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVW);
		*i.s = *wsrc(0);		# value from stack
		addrdind(i.d, Afpind, iadd.d.offset, 0);
		relreg(iadd.d);

	Wi32_store8 =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(1);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(ICVTWB);
		*i.s = *wsrc(0);
		addrdind(i.d, Afpind, iadd.d.offset, 0);
		relreg(iadd.d);

	Wi32_store16 =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(1);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVW);
		*i.s = *wsrc(0);
		addrdind(i.d, Afpind, iadd.d.offset, 0);
		relreg(iadd.d);

	Wi64_store =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(1);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVL);
		*i.s = *wsrc(0);
		addrdind(i.d, Afpind, iadd.d.offset, 0);
		relreg(iadd.d);

	Wf32_store or Wf64_store =>
		iadd := newi(IADDW);
		*iadd.s = *wsrc(1);
		addrimm(iadd.m, Wi.arg2);
		addrsind(iadd.d, Afp, getreg(DIS_W));

		i = newi(IMOVF);
		*i.s = *wsrc(0);
		addrdind(i.d, Afpind, iadd.d.offset, 0);
		relreg(iadd.d);

	# numeric instructions - constants
	Wi32_const =>
		i = newi(IMOVW);
		addrimm(i.s, Wi.arg1);
		*i.d = *Wi.dst;

	Wi64_const =>
		i = newi(IMOVL);
		# For 64-bit, we might need module data for large values
		addrimm(i.s, Wi.arg1);
		*i.d = *Wi.dst;

	Wf32_const or Wf64_const =>
		# Floating point constants need module data
		# For now, use immediate (will only work for small values)
		i = newi(IMOVF);
		addrimm(i.s, Wi.arg1);
		*i.d = *Wi.dst;

	# i32 comparison operations
	Wi32_eqz =>
		xi32eqz();

	Wi32_eq =>
		xi32cmp(IBEQW);

	Wi32_ne =>
		xi32cmp(IBNEW);

	Wi32_lt_s =>
		xi32cmp(IBLTW);

	Wi32_lt_u =>
		# Unsigned comparison - use signed after adjustment
		xi32cmp(IBLTW);  # simplified

	Wi32_gt_s =>
		xi32cmp(IBGTW);

	Wi32_gt_u =>
		xi32cmp(IBGTW);  # simplified

	Wi32_le_s =>
		xi32cmp(IBLEW);

	Wi32_le_u =>
		xi32cmp(IBLEW);  # simplified

	Wi32_ge_s =>
		xi32cmp(IBGEW);

	Wi32_ge_u =>
		xi32cmp(IBGEW);  # simplified

	# i64 comparison operations
	Wi64_eqz =>
		xi64eqz();

	Wi64_eq =>
		xi64cmp(IBEQL);

	Wi64_ne =>
		xi64cmp(IBNEL);

	Wi64_lt_s =>
		xi64cmp(IBLTL);

	Wi64_lt_u =>
		xi64cmp(IBLTL);  # simplified

	Wi64_gt_s =>
		xi64cmp(IBGTL);

	Wi64_gt_u =>
		xi64cmp(IBGTL);  # simplified

	Wi64_le_s =>
		xi64cmp(IBLEL);

	Wi64_le_u =>
		xi64cmp(IBLEL);  # simplified

	Wi64_ge_s =>
		xi64cmp(IBGEL);

	Wi64_ge_u =>
		xi64cmp(IBGEL);  # simplified

	# f32 comparison operations
	Wf32_eq =>
		xfcmp(IBEQF);

	Wf32_ne =>
		xfcmp(IBNEF);

	Wf32_lt =>
		xfcmp(IBLTF);

	Wf32_gt =>
		xfcmp(IBGTF);

	Wf32_le =>
		xfcmp(IBLEF);

	Wf32_ge =>
		xfcmp(IBGEF);

	# f64 comparison operations
	Wf64_eq =>
		xfcmp(IBEQF);

	Wf64_ne =>
		xfcmp(IBNEF);

	Wf64_lt =>
		xfcmp(IBLTF);

	Wf64_gt =>
		xfcmp(IBGTF);

	Wf64_le =>
		xfcmp(IBLEF);

	Wf64_ge =>
		xfcmp(IBGEF);

	# i32 unary operations
	Wi32_clz or Wi32_ctz or Wi32_popcnt =>
		# These need runtime support, generate placeholder
		i = newi(IMOVW);
		addrimm(i.s, 0);
		*i.d = *Wi.dst;

	# i32 binary operations
	Wi32_add =>
		xi32binop(IADDW);

	Wi32_sub =>
		xi32binop(ISUBW);

	Wi32_mul =>
		xi32binop(IMULW);

	Wi32_div_s =>
		xi32binop(IDIVW);

	Wi32_div_u =>
		xi32binop(IDIVW);  # simplified, should use unsigned div

	Wi32_rem_s =>
		xi32binop(IMODW);

	Wi32_rem_u =>
		xi32binop(IMODW);  # simplified

	Wi32_and =>
		xi32binop(IANDW);

	Wi32_or =>
		xi32binop(IORW);

	Wi32_xor =>
		xi32binop(IXORW);

	Wi32_shl =>
		xi32binop(ISHLW);

	Wi32_shr_s =>
		xi32binop(ISHRW);

	Wi32_shr_u =>
		xi32binop(ILSRW);

	Wi32_rotl or Wi32_rotr =>
		# Rotate operations - need special handling
		xi32binop(ISHLW);  # placeholder

	# i64 unary operations
	Wi64_clz or Wi64_ctz or Wi64_popcnt =>
		i = newi(IMOVL);
		addrimm(i.s, 0);
		*i.d = *Wi.dst;

	# i64 binary operations
	Wi64_add =>
		xi64binop(IADDL);

	Wi64_sub =>
		xi64binop(ISUBL);

	Wi64_mul =>
		xi64binop(IMULL);

	Wi64_div_s =>
		xi64binop(IDIVL);

	Wi64_div_u =>
		xi64binop(IDIVL);  # simplified

	Wi64_rem_s =>
		xi64binop(IMODL);

	Wi64_rem_u =>
		xi64binop(IMODL);  # simplified

	Wi64_and =>
		xi64binop(IANDL);

	Wi64_or =>
		xi64binop(IORL);

	Wi64_xor =>
		xi64binop(IXORL);

	Wi64_shl =>
		xi64binop(ISHLL);

	Wi64_shr_s =>
		xi64binop(ISHRL);

	Wi64_shr_u =>
		xi64binop(ILSRL);

	Wi64_rotl or Wi64_rotr =>
		xi64binop(ISHLL);  # placeholder

	# f32 unary operations
	Wf32_abs or Wf32_neg or Wf32_ceil or Wf32_floor or Wf32_trunc or
	Wf32_nearest or Wf32_sqrt =>
		# Need runtime support
		i = newi(IMOVF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	# f32 binary operations
	Wf32_add =>
		xfbinop(IADDF);

	Wf32_sub =>
		xfbinop(ISUBF);

	Wf32_mul =>
		xfbinop(IMULF);

	Wf32_div =>
		xfbinop(IDIVF);

	Wf32_min or Wf32_max or Wf32_copysign =>
		# Need runtime support
		xfbinop(IADDF);  # placeholder

	# f64 unary operations
	Wf64_abs or Wf64_neg or Wf64_ceil or Wf64_floor or Wf64_trunc or
	Wf64_nearest or Wf64_sqrt =>
		i = newi(IMOVF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	# f64 binary operations
	Wf64_add =>
		xfbinop(IADDF);

	Wf64_sub =>
		xfbinop(ISUBF);

	Wf64_mul =>
		xfbinop(IMULF);

	Wf64_div =>
		xfbinop(IDIVF);

	Wf64_min or Wf64_max or Wf64_copysign =>
		xfbinop(IADDF);  # placeholder

	# conversions
	Wi32_wrap_i64 =>
		i = newi(ICVTLW);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wi32_trunc_f32_s or Wi32_trunc_f32_u or Wi32_trunc_f64_s or Wi32_trunc_f64_u =>
		i = newi(ICVTFW);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wi64_extend_i32_s or Wi64_extend_i32_u =>
		i = newi(ICVTWL);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wi64_trunc_f32_s or Wi64_trunc_f32_u or Wi64_trunc_f64_s or Wi64_trunc_f64_u =>
		i = newi(ICVTFL);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf32_convert_i32_s or Wf32_convert_i32_u =>
		i = newi(ICVTWF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf32_convert_i64_s or Wf32_convert_i64_u =>
		i = newi(ICVTLF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf32_demote_f64 =>
		i = newi(IMOVF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf64_convert_i32_s or Wf64_convert_i32_u =>
		i = newi(ICVTWF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf64_convert_i64_s or Wf64_convert_i64_u =>
		i = newi(ICVTLF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wf64_promote_f32 =>
		i = newi(IMOVF);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	# reinterpret - just move the bits
	Wi32_reinterpret_f32 or Wf32_reinterpret_i32 =>
		i = newi(IMOVW);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wi64_reinterpret_f64 or Wf64_reinterpret_i64 =>
		i = newi(IMOVL);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	# sign extension
	Wi32_extend8_s =>
		i = newi(ISHLW);
		addrimm(i.s, 24);
		*i.m = *wsrc(0);
		*i.d = *Wi.dst;
		i = newi(ISHRW);
		addrimm(i.s, 24);
		*i.d = *Wi.dst;

	Wi32_extend16_s =>
		i = newi(ISHLW);
		addrimm(i.s, 16);
		*i.m = *wsrc(0);
		*i.d = *Wi.dst;
		i = newi(ISHRW);
		addrimm(i.s, 16);
		*i.d = *Wi.dst;

	Wi64_extend8_s or Wi64_extend16_s or Wi64_extend32_s =>
		# Placeholder
		i = newi(IMOVL);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wmemory_size or Wmemory_grow =>
		# Placeholder - need runtime support
		i = newi(IMOVW);
		addrimm(i.s, 0);
		*i.d = *Wi.dst;

	* =>
		# Unknown opcode - generate nop
		i = newi(INOP);
	}
}

#
# Translate all WASM instructions for a function to Dis.
#

wasm2dis(codes: array of ref Winst)
{
	wcodes = codes;
	wlabels = array [len codes + 1] of { * => -1 };

	for(wpc = 0; wpc < len codes; wpc++) {
		Wi = codes[wpc];
		xlatwinst();
	}

	# Record final label
	wlabels[len codes] = pcdis;
}

#
# Return offset for return value (if any).
#

WREGRET: con 32;  # Return value goes at offset REGRET*IBY2WD = 4*8 = 32

#
# WASM-specific module data size (no module data for now)
#

wdisnvar()
{
	discon(0);  # no module data
}

#
# WASM-specific var directive for assembly output (no module data)
#

wasmvar()
{
	bout.puts("\tvar\t@mp,0\n");
}

#
# WASM-specific module data output (empty for now)
#

wdisvar()
{
	# no module data to write, but must terminate the data section
	bout.putb(byte 0);
}

#
# WASM-specific dis output - simplified version without Java relocations
#

wdisout()
{
	discon(XMAGIC);
	discon(DONTCOMPILE);	# runtime "hints"
	disstackext();		# minimum stack extent size
	disninst();		# number of instructions
	wdisnvar();		# number of module data bytes (0 for WASM)
	disndesc();		# number of type descriptors
	disnlinks();		# number of links
	disentry();		# entry point
	disinst();		# instructions
	disdesc();		# type descriptors
	wdisvar();		# module data (empty for WASM)
	dismod();		# module name
	dislinks();		# link section
}

#
# Translate an entire WASM module to Dis.
#

wxlate(m: ref Mod)
{
	if(m.codesection == nil || m.funcsection == nil || m.typesection == nil)
		return;

	# Set module name
	THISCLASS = "Wasm";

	# Reset global instruction list
	ihead = nil;
	itail = nil;
	pcdis = 0;
	maxframe = 0;
	nlinks = 0;
	links = nil;

	# Create module data descriptor (id=0) for WASM (empty, no pointers)
	mpdescid(0, 0, array [0] of byte);

	for(i := 0; i < len m.codesection.codes; i++) {
		wcode := m.codesection.codes[i];
		typeidx := m.funcsection.funcs[i];
		functype := m.typesection.types[typeidx];

		wftype = functype;

		# Initialize frame for this function
		wopenframe(functype, wcode.locals);

		# Record start PC for this function
		funcpc := pcdis;

		# Simulate to allocate frame positions
		simwasm(wcode.code, functype);

		# Translate to Dis instructions
		wasm2dis(wcode.code);

		# Copy return value to return location if function returns a value
		if(len functype.rets > 0) {
			# Find the last instruction that produced a value (has non-nil dst)
			for(pc := len wcode.code - 1; pc >= 0; pc--) {
				if(wcode.code[pc].dst != nil) {
					imov := newi(wmovinst(functype.rets[0]));
					*imov.s = *wcode.code[pc].dst;
					addrdind(imov.d, Afpind, WREGRET, 0);
					break;
				}
			}
		}

		# Add return instruction at end
		iret := newi(IRET);
		iret = iret;  # suppress warning

		# Close frame and get type descriptor
		tid := wcloseframe();

		# Create link for this function
		funcname := sys->sprint("func%d", i);
		xtrnlink(tid, funcpc, wfuncsig(functype), funcname, "");
	}

	# Set first function as entry point if no main was found
	if(pc == -1 && nlinks > 0)
		setentry(0, 0);
}
