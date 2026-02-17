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
	# Limbo signature format: f(params)return where return is 'n' for void
	s := "f(";
	for(i = 0; i < len ft.args; i++) {
		if(i > 0)
			s += ",";
		s += wsigchar(ft.args[i]);
	}
	s += ")";
	if(len ft.rets == 0)
		s += "n";  # Tnone = void return
	else {
		for(i = 0; i < len ft.rets; i++)
			s += wsigchar(ft.rets[i]);
	}

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
# Function call support - track function info for internal calls
# (wmod is declared in simwasm.b)
#
wfunctids: array of int;	# type descriptor ID for each function
wfuncpcs: array of int;		# entry PC for each function

# Track calls for patching
Callpatch: adt {
	callinst: ref Inst;	# the call instruction to patch
	funcidx: int;		# target function index
};
wcallinsts: list of ref Callpatch;

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
# Translate i32 binary arithmetic operation (commutative: add, mul, and, or, xor).
#

xi32binop(disop: int)
{
	i := newi(disop);
	# Use recorded source PCs from simulation instead of wsrc
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*i.s = *wcodes[Wi.src1pc].dst;
		*i.m = *wcodes[Wi.src2pc].dst;
	} else {
		*i.s = *wsrc(1);	# first operand (deeper in stack)
		*i.m = *wsrc(0);	# second operand (top of stack)
	}
	*i.d = *Wi.dst;
}

#
# Translate i32 binary arithmetic operation (non-commutative: sub, div, mod, shl, shr).
# Dis operations: dst = src2 OP src1
# WASM operations: result = operand1 OP operand2, where operand2 is top of stack
# So we need: src1 = wsrc(0) (top), src2 = wsrc(1) (second from top)
#

xi32binop_nc(disop: int)
{
	i := newi(disop);
	# Use recorded source PCs from simulation instead of wsrc
	# Note: swapped compared to commutative operations
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*i.s = *wcodes[Wi.src2pc].dst;	# top of stack (operand2)
		*i.m = *wcodes[Wi.src1pc].dst;	# second from top (operand1)
	} else {
		*i.s = *wsrc(0);	# top of stack (operand2)
		*i.m = *wsrc(1);	# second from top (operand1)
	}
	*i.d = *Wi.dst;
}

#
# Translate unsigned i32 division/modulo.
# We need to mask operands to 32 bits first to treat them as unsigned.
# This converts negative 64-bit values to positive 32-bit unsigned values.
#

xi32binop_unsigned(disop: int)
{
	# Get temporary registers for masked operands
	tmp1 := getreg(DIS_W);
	tmp2 := getreg(DIS_W);

	# Get mask constant in module data (64-bit big for ANDW)
	maskoff := mpbig(big 16rFFFFFFFF);

	# Mask first operand (operand1, deeper in stack) to 32 bits
	iand1 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand1.s = *wcodes[Wi.src1pc].dst;
	else
		*iand1.s = *wsrc(1);
	addrsind(iand1.m, Amp, maskoff);
	addrsind(iand1.d, Afp, tmp1);

	# Mask second operand (operand2, top of stack) to 32 bits
	iand2 := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand2.s = *wcodes[Wi.src2pc].dst;
	else
		*iand2.s = *wsrc(0);
	addrsind(iand2.m, Amp, maskoff);
	addrsind(iand2.d, Afp, tmp2);

	# Perform the operation (division or modulo)
	# Note: swapped operands for Dis semantics (dst = src2 OP src1)
	i := newi(disop);
	addrsind(i.s, Afp, tmp2);  # divisor (operand2)
	addrsind(i.m, Afp, tmp1);  # dividend (operand1)
	*i.d = *Wi.dst;

	# Release temp registers - use the instruction addresses
	relreg(iand1.d);
	relreg(iand2.d);
}

#
# Translate i32 shift operation.
# WASM requires shift count to be masked to 5 bits (count & 31).
#

xi32shift(disop: int)
{
	# Get mask constant (31 = 0x1F) in module data
	maskoff := mpbig(big 31);

	# Use destination register for masked shift count
	# First, mask shift count and store in destination
	iand := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand.s = *wcodes[Wi.src2pc].dst;
	else
		*iand.s = *wsrc(0);
	addrsind(iand.m, Amp, maskoff);
	*iand.d = *Wi.dst;  # Store masked count in dest temporarily

	# Perform the shift operation
	# Dis: dst = src2 OP src1 (value shifted by count)
	# So src1 = masked_count (now in dst), src2 = value
	i := newi(disop);
	*i.s = *Wi.dst;  # shift count (masked, from dest)
	if(Wi.src1pc >= 0)
		*i.m = *wcodes[Wi.src1pc].dst;  # value to shift
	else
		*i.m = *wsrc(1);
	*i.d = *Wi.dst;
}

#
# Translate unsigned i32 right shift.
# Need to mask both the shift count (to 5 bits) and the value (to 32 bits for unsigned).
#

xi32shift_unsigned(disop: int)
{
	# Get one temporary register for the masked value
	tmpval := getreg(DIS_W);

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	mask5off := mpbig(big 31);

	# Mask value (operand1, deeper in stack) to 32 bits
	iand1 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand1.s = *wcodes[Wi.src1pc].dst;
	else
		*iand1.s = *wsrc(1);
	addrsind(iand1.m, Amp, mask32off);
	addrsind(iand1.d, Afp, tmpval);

	# Mask shift count (operand2, top of stack) to 5 bits
	# Store in destination register temporarily
	iand2 := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand2.s = *wcodes[Wi.src2pc].dst;
	else
		*iand2.s = *wsrc(0);
	addrsind(iand2.m, Amp, mask5off);
	*iand2.d = *Wi.dst;

	# Perform the shift operation
	i := newi(disop);
	*i.s = *Wi.dst;  # shift count (from dest)
	addrsind(i.m, Afp, tmpval);  # masked value
	*i.d = *Wi.dst;

	# Release temp register
	relreg(iand1.d);
}

#
# Translate i32 rotate left.
# rotl(x, n) = (x << n) | (x >> (32 - n)) where n is masked to 5 bits
# and x is treated as unsigned 32-bit.
#

xi32rotl()
{
	# Allocate temporary registers
	tmp_cnt := getreg(DIS_W);
	tmp_val := getreg(DIS_W);
	tmp_left := getreg(DIS_W);
	tmp_rcnt := getreg(DIS_W);

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	mask5off := mpbig(big 31);

	# cnt = n & 31 (mask shift count to 5 bits)
	iand1 := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand1.s = *wcodes[Wi.src2pc].dst;
	else
		*iand1.s = *wsrc(0);
	addrsind(iand1.m, Amp, mask5off);
	addrsind(iand1.d, Afp, tmp_cnt);

	# val = x & 0xFFFFFFFF (mask value to 32 bits for unsigned)
	iand2 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand2.s = *wcodes[Wi.src1pc].dst;
	else
		*iand2.s = *wsrc(1);
	addrsind(iand2.m, Amp, mask32off);
	addrsind(iand2.d, Afp, tmp_val);

	# left = val << cnt
	ishl := newi(ISHLW);
	addrsind(ishl.s, Afp, tmp_cnt);
	addrsind(ishl.m, Afp, tmp_val);
	addrsind(ishl.d, Afp, tmp_left);

	# rcnt = 32 - cnt
	imov := newi(IMOVW);
	addrimm(imov.s, 32);
	addrsind(imov.d, Afp, tmp_rcnt);

	isub := newi(ISUBW);
	addrsind(isub.s, Afp, tmp_cnt);
	addrsind(isub.m, Afp, tmp_rcnt);
	addrsind(isub.d, Afp, tmp_rcnt);

	# right = val >> rcnt (logical shift)
	ilsr := newi(ILSRW);
	addrsind(ilsr.s, Afp, tmp_rcnt);
	addrsind(ilsr.m, Afp, tmp_val);
	*ilsr.d = *Wi.dst;

	# result = left | right
	ior := newi(IORW);
	addrsind(ior.s, Afp, tmp_left);
	*ior.m = *Wi.dst;
	*ior.d = *Wi.dst;

	# Release temp registers
	relreg(iand1.d);
	relreg(iand2.d);
	relreg(ishl.d);
	relreg(isub.d);
}

#
# Translate i32 rotate right.
# rotr(x, n) = (x >> n) | (x << (32 - n)) where n is masked to 5 bits
# and x is treated as unsigned 32-bit.
#

xi32rotr()
{
	# Allocate temporary registers
	tmp_cnt := getreg(DIS_W);
	tmp_val := getreg(DIS_W);
	tmp_right := getreg(DIS_W);
	tmp_lcnt := getreg(DIS_W);

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	mask5off := mpbig(big 31);

	# cnt = n & 31 (mask shift count to 5 bits)
	iand1 := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand1.s = *wcodes[Wi.src2pc].dst;
	else
		*iand1.s = *wsrc(0);
	addrsind(iand1.m, Amp, mask5off);
	addrsind(iand1.d, Afp, tmp_cnt);

	# val = x & 0xFFFFFFFF (mask value to 32 bits for unsigned)
	iand2 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand2.s = *wcodes[Wi.src1pc].dst;
	else
		*iand2.s = *wsrc(1);
	addrsind(iand2.m, Amp, mask32off);
	addrsind(iand2.d, Afp, tmp_val);

	# right = val >> cnt (logical shift)
	ilsr := newi(ILSRW);
	addrsind(ilsr.s, Afp, tmp_cnt);
	addrsind(ilsr.m, Afp, tmp_val);
	addrsind(ilsr.d, Afp, tmp_right);

	# lcnt = 32 - cnt
	imov := newi(IMOVW);
	addrimm(imov.s, 32);
	addrsind(imov.d, Afp, tmp_lcnt);

	isub := newi(ISUBW);
	addrsind(isub.s, Afp, tmp_cnt);
	addrsind(isub.m, Afp, tmp_lcnt);
	addrsind(isub.d, Afp, tmp_lcnt);

	# left = val << lcnt
	ishl := newi(ISHLW);
	addrsind(ishl.s, Afp, tmp_lcnt);
	addrsind(ishl.m, Afp, tmp_val);
	*ishl.d = *Wi.dst;

	# result = right | left
	ior := newi(IORW);
	addrsind(ior.s, Afp, tmp_right);
	*ior.m = *Wi.dst;
	*ior.d = *Wi.dst;

	# Release temp registers
	relreg(iand1.d);
	relreg(iand2.d);
	relreg(ilsr.d);
	relreg(isub.d);
}

#
# Simplified i32 rotate left.
# rotl(x, n) = (x << n) | (x >> (32 - n)) where n is masked to 5 bits
# and x is treated as unsigned 32-bit.
#
# IMPORTANT: getreg() may return the same registers that held src1/src2.
# We use Wi.dst (known safe) for one temp, and read src2 FIRST since
# the fresh temp (from getreg) might overlap with src2's location.
# Within one instruction, read happens before write, so reading src2 into
# a fresh temp that might be src1's location is safe, THEN we can read src1.
#

xi32rotl_simple()
{
	# Mask constants (use mpbig for 64-bit SUBW)
	mask32off := mpbig(big 16rFFFFFFFF);
	mask5off := mpbig(big 31);
	const32off := mpbig(big 32);

	# Allocate temps - these might overlap with src1/src2 locations
	tmp_val := getreg(DIS_W);  # will hold masked value
	tmp_left := getreg(DIS_W); # left shift result
	tmp_rcnt := getreg(DIS_W); # right count

	# CRITICAL: Read src2 (count) FIRST into Wi.dst (known safe location)
	# because tmp_val might be allocated at src2's location
	iand_cnt := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand_cnt.s = *wcodes[Wi.src2pc].dst;
	else
		*iand_cnt.s = *wsrc(0);
	addrsind(iand_cnt.m, Amp, mask5off);
	*iand_cnt.d = *Wi.dst;  # Store count in dst (known safe)

	# Now read src1 (value) - safe even if tmp_val was src2's location
	iand_val := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand_val.s = *wcodes[Wi.src1pc].dst;
	else
		*iand_val.s = *wsrc(1);
	addrsind(iand_val.m, Amp, mask32off);
	addrsind(iand_val.d, Afp, tmp_val);

	# left = val << cnt (cnt is in Wi.dst)
	ishl := newi(ISHLW);
	*ishl.s = *Wi.dst;  # count from dst
	addrsind(ishl.m, Afp, tmp_val);
	addrsind(ishl.d, Afp, tmp_left);

	# rcnt = 32 - cnt
	isub := newi(ISUBW);
	*isub.s = *Wi.dst;  # count from dst
	addrsind(isub.m, Amp, const32off);
	addrsind(isub.d, Afp, tmp_rcnt);

	# right = val >> rcnt (logical)
	ilsr := newi(ILSRW);
	addrsind(ilsr.s, Afp, tmp_rcnt);
	addrsind(ilsr.m, Afp, tmp_val);
	*ilsr.d = *Wi.dst;

	# result = left | right
	ior := newi(IORW);
	addrsind(ior.s, Afp, tmp_left);
	*ior.m = *Wi.dst;
	*ior.d = *Wi.dst;

	# Release temp registers
	relreg(iand_val.d);
	relreg(ishl.d);
	relreg(isub.d);
}

#
# Simplified i32 rotate right.
# rotr(x, n) = (x >> n) | (x << (32 - n)) where n is masked to 5 bits
# and x is treated as unsigned 32-bit.
#
# IMPORTANT: Same pattern as rotl - read src2 (count) first into Wi.dst,
# then read src1 (value) into a getreg temp which might overlap with src2.
#

xi32rotr_simple()
{
	# Mask constants (use mpbig for 64-bit SUBW)
	mask32off := mpbig(big 16rFFFFFFFF);
	mask5off := mpbig(big 31);
	const32off := mpbig(big 32);

	# Allocate temp registers - might overlap with src1/src2
	tmp_val := getreg(DIS_W);   # masked value
	tmp_right := getreg(DIS_W); # right shift result
	tmp_lcnt := getreg(DIS_W);  # left count

	# CRITICAL: Read src2 (count) FIRST into Wi.dst (known safe)
	iand_cnt := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand_cnt.s = *wcodes[Wi.src2pc].dst;
	else
		*iand_cnt.s = *wsrc(0);
	addrsind(iand_cnt.m, Amp, mask5off);
	*iand_cnt.d = *Wi.dst;

	# Now read src1 (value) - safe even if tmp_val was src2's location
	iand_val := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand_val.s = *wcodes[Wi.src1pc].dst;
	else
		*iand_val.s = *wsrc(1);
	addrsind(iand_val.m, Amp, mask32off);
	addrsind(iand_val.d, Afp, tmp_val);

	# right = val >> cnt (logical), cnt is in Wi.dst
	ilsr := newi(ILSRW);
	*ilsr.s = *Wi.dst;
	addrsind(ilsr.m, Afp, tmp_val);
	addrsind(ilsr.d, Afp, tmp_right);

	# lcnt = 32 - cnt
	isub := newi(ISUBW);
	*isub.s = *Wi.dst;
	addrsind(isub.m, Amp, const32off);
	addrsind(isub.d, Afp, tmp_lcnt);

	# left = val << lcnt
	ishl := newi(ISHLW);
	addrsind(ishl.s, Afp, tmp_lcnt);
	addrsind(ishl.m, Afp, tmp_val);
	*ishl.d = *Wi.dst;

	# result = right | left
	ior := newi(IORW);
	addrsind(ior.s, Afp, tmp_right);
	*ior.m = *Wi.dst;
	*ior.d = *Wi.dst;

	# Release temp registers
	relreg(iand_val.d);
	relreg(ilsr.d);
	relreg(isub.d);
}

#
# Translate i32 count leading zeros.
# Uses binary search: check top half, if 0 then add bits and shift.
# clz(0) = 32, clz(0x80000000) = 0, clz(1) = 31
#

xi32clz()
{
	# Save starting PC for branch target calculation
	start_pc := pcdis;
	end_pc := start_pc + 25;

	# Allocate registers
	tmp_x := getreg(DIS_W);  # working value
	tmp_n := getreg(DIS_W);  # count
	tmp_t := getreg(DIS_W);  # temporary for AND result

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	mask16off := mpbig(big 16rFFFF0000);
	mask8off := mpbig(big 16rFF000000);
	mask4off := mpbig(big 16rF0000000);
	mask2off := mpbig(big 16rC0000000);
	mask1off := mpbig(big 16r80000000);

	# PC 0: x = input & 0xFFFFFFFF
	iand0 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand0.s = *wcodes[Wi.src1pc].dst;
	else
		*iand0.s = *wsrc(0);
	addrsind(iand0.m, Amp, mask32off);
	addrsind(iand0.d, Afp, tmp_x);

	# PC 1: if x != 0, skip to PC 4
	ibr_nz := newi(IBNEW);
	addrsind(ibr_nz.s, Afp, tmp_x);
	addrimm(ibr_nz.m, 0);
	addrimm(ibr_nz.d, start_pc + 4);

	# PC 2: dst = 32
	imov_32 := newi(IMOVW);
	addrimm(imov_32.s, 32);
	*imov_32.d = *Wi.dst;

	# PC 3: jump to end
	ijmp := newi(IJMP);
	addrimm(ijmp.d, end_pc);

	# PC 4: n = 0
	imov_n := newi(IMOVW);
	addrimm(imov_n.s, 0);
	addrsind(imov_n.d, Afp, tmp_n);

	# Step 1: if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
	# PC 5
	iand1 := newi(IANDW);
	addrsind(iand1.s, Afp, tmp_x);
	addrsind(iand1.m, Amp, mask16off);
	addrsind(iand1.d, Afp, tmp_t);
	# PC 6
	ibr1 := newi(IBNEW);
	addrsind(ibr1.s, Afp, tmp_t);
	addrimm(ibr1.m, 0);
	addrimm(ibr1.d, start_pc + 9);
	# PC 7
	iadd1 := newi(IADDW);
	addrimm(iadd1.s, 16);
	addrsind(iadd1.m, Afp, tmp_n);
	addrsind(iadd1.d, Afp, tmp_n);
	# PC 8
	ishl1 := newi(ISHLW);
	addrimm(ishl1.s, 16);
	addrsind(ishl1.m, Afp, tmp_x);
	addrsind(ishl1.d, Afp, tmp_x);

	# Step 2: if ((x & 0xFF000000) == 0) { n += 8; x <<= 8; }
	# PC 9
	iand2 := newi(IANDW);
	addrsind(iand2.s, Afp, tmp_x);
	addrsind(iand2.m, Amp, mask8off);
	addrsind(iand2.d, Afp, tmp_t);
	# PC 10
	ibr2 := newi(IBNEW);
	addrsind(ibr2.s, Afp, tmp_t);
	addrimm(ibr2.m, 0);
	addrimm(ibr2.d, start_pc + 13);
	# PC 11
	iadd2 := newi(IADDW);
	addrimm(iadd2.s, 8);
	addrsind(iadd2.m, Afp, tmp_n);
	addrsind(iadd2.d, Afp, tmp_n);
	# PC 12
	ishl2 := newi(ISHLW);
	addrimm(ishl2.s, 8);
	addrsind(ishl2.m, Afp, tmp_x);
	addrsind(ishl2.d, Afp, tmp_x);

	# Step 3: if ((x & 0xF0000000) == 0) { n += 4; x <<= 4; }
	# PC 13
	iand3 := newi(IANDW);
	addrsind(iand3.s, Afp, tmp_x);
	addrsind(iand3.m, Amp, mask4off);
	addrsind(iand3.d, Afp, tmp_t);
	# PC 14
	ibr3 := newi(IBNEW);
	addrsind(ibr3.s, Afp, tmp_t);
	addrimm(ibr3.m, 0);
	addrimm(ibr3.d, start_pc + 17);
	# PC 15
	iadd3 := newi(IADDW);
	addrimm(iadd3.s, 4);
	addrsind(iadd3.m, Afp, tmp_n);
	addrsind(iadd3.d, Afp, tmp_n);
	# PC 16
	ishl3 := newi(ISHLW);
	addrimm(ishl3.s, 4);
	addrsind(ishl3.m, Afp, tmp_x);
	addrsind(ishl3.d, Afp, tmp_x);

	# Step 4: if ((x & 0xC0000000) == 0) { n += 2; x <<= 2; }
	# PC 17
	iand4 := newi(IANDW);
	addrsind(iand4.s, Afp, tmp_x);
	addrsind(iand4.m, Amp, mask2off);
	addrsind(iand4.d, Afp, tmp_t);
	# PC 18
	ibr4 := newi(IBNEW);
	addrsind(ibr4.s, Afp, tmp_t);
	addrimm(ibr4.m, 0);
	addrimm(ibr4.d, start_pc + 21);
	# PC 19
	iadd4 := newi(IADDW);
	addrimm(iadd4.s, 2);
	addrsind(iadd4.m, Afp, tmp_n);
	addrsind(iadd4.d, Afp, tmp_n);
	# PC 20
	ishl4 := newi(ISHLW);
	addrimm(ishl4.s, 2);
	addrsind(ishl4.m, Afp, tmp_x);
	addrsind(ishl4.d, Afp, tmp_x);

	# Step 5: if ((x & 0x80000000) == 0) { n += 1; }
	# PC 21
	iand5 := newi(IANDW);
	addrsind(iand5.s, Afp, tmp_x);
	addrsind(iand5.m, Amp, mask1off);
	addrsind(iand5.d, Afp, tmp_t);
	# PC 22
	ibr5 := newi(IBNEW);
	addrsind(ibr5.s, Afp, tmp_t);
	addrimm(ibr5.m, 0);
	addrimm(ibr5.d, start_pc + 24);
	# PC 23
	iadd5 := newi(IADDW);
	addrimm(iadd5.s, 1);
	addrsind(iadd5.m, Afp, tmp_n);
	addrsind(iadd5.d, Afp, tmp_n);

	# PC 24: dst = n
	imov_final := newi(IMOVW);
	addrsind(imov_final.s, Afp, tmp_n);
	*imov_final.d = *Wi.dst;

	# Release temp registers
	relreg(iand0.d);
	relreg(imov_n.d);
	relreg(iand1.d);
}

#
# Translate i32 count trailing zeros.
# Uses binary search: check bottom half, if 0 then add bits and shift right.
# ctz(0) = 32, ctz(1) = 0, ctz(0x80000000) = 31
#

xi32ctz()
{
	# Save starting PC for branch target calculation
	start_pc := pcdis;
	end_pc := start_pc + 25;

	# Allocate registers
	tmp_x := getreg(DIS_W);  # working value
	tmp_n := getreg(DIS_W);  # count
	tmp_t := getreg(DIS_W);  # temporary for AND result

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	mask16off := mpbig(big 16r0000FFFF);
	mask8off := mpbig(big 16r000000FF);
	mask4off := mpbig(big 16r0000000F);
	mask2off := mpbig(big 16r00000003);
	mask1off := mpbig(big 16r00000001);

	# PC 0: x = input & 0xFFFFFFFF
	iand0 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand0.s = *wcodes[Wi.src1pc].dst;
	else
		*iand0.s = *wsrc(0);
	addrsind(iand0.m, Amp, mask32off);
	addrsind(iand0.d, Afp, tmp_x);

	# PC 1: if x != 0, skip to PC 4
	ibr_nz := newi(IBNEW);
	addrsind(ibr_nz.s, Afp, tmp_x);
	addrimm(ibr_nz.m, 0);
	addrimm(ibr_nz.d, start_pc + 4);

	# PC 2: dst = 32
	imov_32 := newi(IMOVW);
	addrimm(imov_32.s, 32);
	*imov_32.d = *Wi.dst;

	# PC 3: jump to end
	ijmp := newi(IJMP);
	addrimm(ijmp.d, end_pc);

	# PC 4: n = 0
	imov_n := newi(IMOVW);
	addrimm(imov_n.s, 0);
	addrsind(imov_n.d, Afp, tmp_n);

	# Step 1: if ((x & 0x0000FFFF) == 0) { n += 16; x >>= 16; }
	# PC 5
	iand1 := newi(IANDW);
	addrsind(iand1.s, Afp, tmp_x);
	addrsind(iand1.m, Amp, mask16off);
	addrsind(iand1.d, Afp, tmp_t);
	# PC 6
	ibr1 := newi(IBNEW);
	addrsind(ibr1.s, Afp, tmp_t);
	addrimm(ibr1.m, 0);
	addrimm(ibr1.d, start_pc + 9);
	# PC 7
	iadd1 := newi(IADDW);
	addrimm(iadd1.s, 16);
	addrsind(iadd1.m, Afp, tmp_n);
	addrsind(iadd1.d, Afp, tmp_n);
	# PC 8
	ilsr1 := newi(ILSRW);
	addrimm(ilsr1.s, 16);
	addrsind(ilsr1.m, Afp, tmp_x);
	addrsind(ilsr1.d, Afp, tmp_x);

	# Step 2: if ((x & 0x000000FF) == 0) { n += 8; x >>= 8; }
	# PC 9
	iand2 := newi(IANDW);
	addrsind(iand2.s, Afp, tmp_x);
	addrsind(iand2.m, Amp, mask8off);
	addrsind(iand2.d, Afp, tmp_t);
	# PC 10
	ibr2 := newi(IBNEW);
	addrsind(ibr2.s, Afp, tmp_t);
	addrimm(ibr2.m, 0);
	addrimm(ibr2.d, start_pc + 13);
	# PC 11
	iadd2 := newi(IADDW);
	addrimm(iadd2.s, 8);
	addrsind(iadd2.m, Afp, tmp_n);
	addrsind(iadd2.d, Afp, tmp_n);
	# PC 12
	ilsr2 := newi(ILSRW);
	addrimm(ilsr2.s, 8);
	addrsind(ilsr2.m, Afp, tmp_x);
	addrsind(ilsr2.d, Afp, tmp_x);

	# Step 3: if ((x & 0x0000000F) == 0) { n += 4; x >>= 4; }
	# PC 13
	iand3 := newi(IANDW);
	addrsind(iand3.s, Afp, tmp_x);
	addrsind(iand3.m, Amp, mask4off);
	addrsind(iand3.d, Afp, tmp_t);
	# PC 14
	ibr3 := newi(IBNEW);
	addrsind(ibr3.s, Afp, tmp_t);
	addrimm(ibr3.m, 0);
	addrimm(ibr3.d, start_pc + 17);
	# PC 15
	iadd3 := newi(IADDW);
	addrimm(iadd3.s, 4);
	addrsind(iadd3.m, Afp, tmp_n);
	addrsind(iadd3.d, Afp, tmp_n);
	# PC 16
	ilsr3 := newi(ILSRW);
	addrimm(ilsr3.s, 4);
	addrsind(ilsr3.m, Afp, tmp_x);
	addrsind(ilsr3.d, Afp, tmp_x);

	# Step 4: if ((x & 0x00000003) == 0) { n += 2; x >>= 2; }
	# PC 17
	iand4 := newi(IANDW);
	addrsind(iand4.s, Afp, tmp_x);
	addrsind(iand4.m, Amp, mask2off);
	addrsind(iand4.d, Afp, tmp_t);
	# PC 18
	ibr4 := newi(IBNEW);
	addrsind(ibr4.s, Afp, tmp_t);
	addrimm(ibr4.m, 0);
	addrimm(ibr4.d, start_pc + 21);
	# PC 19
	iadd4 := newi(IADDW);
	addrimm(iadd4.s, 2);
	addrsind(iadd4.m, Afp, tmp_n);
	addrsind(iadd4.d, Afp, tmp_n);
	# PC 20
	ilsr4 := newi(ILSRW);
	addrimm(ilsr4.s, 2);
	addrsind(ilsr4.m, Afp, tmp_x);
	addrsind(ilsr4.d, Afp, tmp_x);

	# Step 5: if ((x & 0x00000001) == 0) { n += 1; }
	# PC 21
	iand5 := newi(IANDW);
	addrsind(iand5.s, Afp, tmp_x);
	addrsind(iand5.m, Amp, mask1off);
	addrsind(iand5.d, Afp, tmp_t);
	# PC 22
	ibr5 := newi(IBNEW);
	addrsind(ibr5.s, Afp, tmp_t);
	addrimm(ibr5.m, 0);
	addrimm(ibr5.d, start_pc + 24);
	# PC 23
	iadd5 := newi(IADDW);
	addrimm(iadd5.s, 1);
	addrsind(iadd5.m, Afp, tmp_n);
	addrsind(iadd5.d, Afp, tmp_n);

	# PC 24: dst = n
	imov_final := newi(IMOVW);
	addrsind(imov_final.s, Afp, tmp_n);
	*imov_final.d = *Wi.dst;

	# Release temp registers
	relreg(iand0.d);
	relreg(imov_n.d);
	relreg(iand1.d);
}

#
# Translate i32 population count (count of 1 bits).
# Uses parallel bit counting algorithm.
#

xi32popcnt()
{
	# Allocate registers
	tmp_x := getreg(DIS_W);  # working value
	tmp_t := getreg(DIS_W);  # temporary

	# Mask constants in module data
	mask32off := mpbig(big 16rFFFFFFFF);
	m1off := mpbig(big 16r55555555);  # 0101...
	m2off := mpbig(big 16r33333333);  # 0011...
	m4off := mpbig(big 16r0F0F0F0F);  # 00001111...
	m8off := mpbig(big 16r00FF00FF);  # 0000000011111111...
	m16off := mpbig(big 16r0000FFFF); # lower 16 bits

	# x = input & 0xFFFFFFFF
	iand0 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand0.s = *wcodes[Wi.src1pc].dst;
	else
		*iand0.s = *wsrc(0);
	addrsind(iand0.m, Amp, mask32off);
	addrsind(iand0.d, Afp, tmp_x);

	# Step 1: x = (x & m1) + ((x >> 1) & m1)
	# t = x >> 1
	ilsr1 := newi(ILSRW);
	addrimm(ilsr1.s, 1);
	addrsind(ilsr1.m, Afp, tmp_x);
	addrsind(ilsr1.d, Afp, tmp_t);
	# t = t & m1
	iand1t := newi(IANDW);
	addrsind(iand1t.s, Afp, tmp_t);
	addrsind(iand1t.m, Amp, m1off);
	addrsind(iand1t.d, Afp, tmp_t);
	# x = x & m1
	iand1x := newi(IANDW);
	addrsind(iand1x.s, Afp, tmp_x);
	addrsind(iand1x.m, Amp, m1off);
	addrsind(iand1x.d, Afp, tmp_x);
	# x = x + t
	iadd1 := newi(IADDW);
	addrsind(iadd1.s, Afp, tmp_t);
	addrsind(iadd1.m, Afp, tmp_x);
	addrsind(iadd1.d, Afp, tmp_x);

	# Step 2: x = (x & m2) + ((x >> 2) & m2)
	ilsr2 := newi(ILSRW);
	addrimm(ilsr2.s, 2);
	addrsind(ilsr2.m, Afp, tmp_x);
	addrsind(ilsr2.d, Afp, tmp_t);
	iand2t := newi(IANDW);
	addrsind(iand2t.s, Afp, tmp_t);
	addrsind(iand2t.m, Amp, m2off);
	addrsind(iand2t.d, Afp, tmp_t);
	iand2x := newi(IANDW);
	addrsind(iand2x.s, Afp, tmp_x);
	addrsind(iand2x.m, Amp, m2off);
	addrsind(iand2x.d, Afp, tmp_x);
	iadd2 := newi(IADDW);
	addrsind(iadd2.s, Afp, tmp_t);
	addrsind(iadd2.m, Afp, tmp_x);
	addrsind(iadd2.d, Afp, tmp_x);

	# Step 3: x = (x & m4) + ((x >> 4) & m4)
	ilsr3 := newi(ILSRW);
	addrimm(ilsr3.s, 4);
	addrsind(ilsr3.m, Afp, tmp_x);
	addrsind(ilsr3.d, Afp, tmp_t);
	iand3t := newi(IANDW);
	addrsind(iand3t.s, Afp, tmp_t);
	addrsind(iand3t.m, Amp, m4off);
	addrsind(iand3t.d, Afp, tmp_t);
	iand3x := newi(IANDW);
	addrsind(iand3x.s, Afp, tmp_x);
	addrsind(iand3x.m, Amp, m4off);
	addrsind(iand3x.d, Afp, tmp_x);
	iadd3 := newi(IADDW);
	addrsind(iadd3.s, Afp, tmp_t);
	addrsind(iadd3.m, Afp, tmp_x);
	addrsind(iadd3.d, Afp, tmp_x);

	# Step 4: x = (x & m8) + ((x >> 8) & m8)
	ilsr4 := newi(ILSRW);
	addrimm(ilsr4.s, 8);
	addrsind(ilsr4.m, Afp, tmp_x);
	addrsind(ilsr4.d, Afp, tmp_t);
	iand4t := newi(IANDW);
	addrsind(iand4t.s, Afp, tmp_t);
	addrsind(iand4t.m, Amp, m8off);
	addrsind(iand4t.d, Afp, tmp_t);
	iand4x := newi(IANDW);
	addrsind(iand4x.s, Afp, tmp_x);
	addrsind(iand4x.m, Amp, m8off);
	addrsind(iand4x.d, Afp, tmp_x);
	iadd4 := newi(IADDW);
	addrsind(iadd4.s, Afp, tmp_t);
	addrsind(iadd4.m, Afp, tmp_x);
	addrsind(iadd4.d, Afp, tmp_x);

	# Step 5: x = (x & m16) + ((x >> 16) & m16)
	ilsr5 := newi(ILSRW);
	addrimm(ilsr5.s, 16);
	addrsind(ilsr5.m, Afp, tmp_x);
	addrsind(ilsr5.d, Afp, tmp_t);
	iand5t := newi(IANDW);
	addrsind(iand5t.s, Afp, tmp_t);
	addrsind(iand5t.m, Amp, m16off);
	addrsind(iand5t.d, Afp, tmp_t);
	iand5x := newi(IANDW);
	addrsind(iand5x.s, Afp, tmp_x);
	addrsind(iand5x.m, Amp, m16off);
	addrsind(iand5x.d, Afp, tmp_x);
	iadd5 := newi(IADDW);
	addrsind(iadd5.s, Afp, tmp_t);
	addrsind(iadd5.m, Afp, tmp_x);
	*iadd5.d = *Wi.dst;

	# Release temp registers
	relreg(iand0.d);
	relreg(ilsr1.d);
}

#
# Translate i64 count leading zeros.
# Uses binary search: check top half, if 0 then add bits and shift.
# clz(0) = 64, clz(0x8000000000000000) = 0, clz(1) = 63
#

xi64clz()
{
	# Save starting PC for branch target calculation
	start_pc := pcdis;
	end_pc := start_pc + 31;  # 6 steps + zero check + NOPs

	# Allocate registers (64-bit for value, 64-bit for count since result is i64)
	tmp_x := getreg(DIS_L);  # working value
	tmp_n := getreg(DIS_L);  # count (result is i64)
	tmp_t := getreg(DIS_L);  # temporary for AND result

	# Mask constants in module data (64-bit)
	mask32off := mpbig(big 16rFFFFFFFF00000000);
	mask16off := mpbig(big 16rFFFF000000000000);
	mask8off := mpbig(big 16rFF00000000000000);
	mask4off := mpbig(big 16rF000000000000000);
	mask2off := mpbig(big 16rC000000000000000);
	mask1off := mpbig(big 16r8000000000000000);

	# PC 0: x = input (copy to working register)
	imov0 := newi(IMOVL);
	if(Wi.src1pc >= 0)
		*imov0.s = *wcodes[Wi.src1pc].dst;
	else
		*imov0.s = *wsrc(0);
	addrsind(imov0.d, Afp, tmp_x);

	# PC 1: if x != 0, skip to PC 4
	ibr_nz := newi(IBNEL);
	addrsind(ibr_nz.s, Afp, tmp_x);
	addrimm(ibr_nz.m, 0);
	addrimm(ibr_nz.d, start_pc + 4);

	# PC 2: dst = 64 (zero case)
	imov_64 := newi(IMOVL);
	addrimm(imov_64.s, 64);
	*imov_64.d = *Wi.dst;

	# PC 3: jump to end
	ijmp := newi(IJMP);
	addrimm(ijmp.d, end_pc);

	# PC 4: n = 0
	imov_n := newi(IMOVL);
	addrimm(imov_n.s, 0);
	addrsind(imov_n.d, Afp, tmp_n);

	# Step 1: if ((x & 0xFFFFFFFF00000000) == 0) { n += 32; x <<= 32; }
	# PC 5
	iand1 := newi(IANDL);
	addrsind(iand1.s, Afp, tmp_x);
	addrsind(iand1.m, Amp, mask32off);
	addrsind(iand1.d, Afp, tmp_t);
	# PC 6
	ibr1 := newi(IBNEL);
	addrsind(ibr1.s, Afp, tmp_t);
	addrimm(ibr1.m, 0);
	addrimm(ibr1.d, start_pc + 9);
	# PC 7
	iadd1 := newi(IADDL);
	addrimm(iadd1.s, 32);
	addrsind(iadd1.m, Afp, tmp_n);
	addrsind(iadd1.d, Afp, tmp_n);
	# PC 8
	ishl1 := newi(ISHLL);
	addrimm(ishl1.s, 32);
	addrsind(ishl1.m, Afp, tmp_x);
	addrsind(ishl1.d, Afp, tmp_x);

	# Step 2: if ((x & 0xFFFF000000000000) == 0) { n += 16; x <<= 16; }
	# PC 9
	iand2 := newi(IANDL);
	addrsind(iand2.s, Afp, tmp_x);
	addrsind(iand2.m, Amp, mask16off);
	addrsind(iand2.d, Afp, tmp_t);
	# PC 10
	ibr2 := newi(IBNEL);
	addrsind(ibr2.s, Afp, tmp_t);
	addrimm(ibr2.m, 0);
	addrimm(ibr2.d, start_pc + 13);
	# PC 11
	iadd2 := newi(IADDL);
	addrimm(iadd2.s, 16);
	addrsind(iadd2.m, Afp, tmp_n);
	addrsind(iadd2.d, Afp, tmp_n);
	# PC 12
	ishl2 := newi(ISHLL);
	addrimm(ishl2.s, 16);
	addrsind(ishl2.m, Afp, tmp_x);
	addrsind(ishl2.d, Afp, tmp_x);

	# Step 3: if ((x & 0xFF00000000000000) == 0) { n += 8; x <<= 8; }
	# PC 13
	iand3 := newi(IANDL);
	addrsind(iand3.s, Afp, tmp_x);
	addrsind(iand3.m, Amp, mask8off);
	addrsind(iand3.d, Afp, tmp_t);
	# PC 14
	ibr3 := newi(IBNEL);
	addrsind(ibr3.s, Afp, tmp_t);
	addrimm(ibr3.m, 0);
	addrimm(ibr3.d, start_pc + 17);
	# PC 15
	iadd3 := newi(IADDL);
	addrimm(iadd3.s, 8);
	addrsind(iadd3.m, Afp, tmp_n);
	addrsind(iadd3.d, Afp, tmp_n);
	# PC 16
	ishl3 := newi(ISHLL);
	addrimm(ishl3.s, 8);
	addrsind(ishl3.m, Afp, tmp_x);
	addrsind(ishl3.d, Afp, tmp_x);

	# Step 4: if ((x & 0xF000000000000000) == 0) { n += 4; x <<= 4; }
	# PC 17
	iand4 := newi(IANDL);
	addrsind(iand4.s, Afp, tmp_x);
	addrsind(iand4.m, Amp, mask4off);
	addrsind(iand4.d, Afp, tmp_t);
	# PC 18
	ibr4 := newi(IBNEL);
	addrsind(ibr4.s, Afp, tmp_t);
	addrimm(ibr4.m, 0);
	addrimm(ibr4.d, start_pc + 21);
	# PC 19
	iadd4 := newi(IADDL);
	addrimm(iadd4.s, 4);
	addrsind(iadd4.m, Afp, tmp_n);
	addrsind(iadd4.d, Afp, tmp_n);
	# PC 20
	ishl4 := newi(ISHLL);
	addrimm(ishl4.s, 4);
	addrsind(ishl4.m, Afp, tmp_x);
	addrsind(ishl4.d, Afp, tmp_x);

	# Step 5: if ((x & 0xC000000000000000) == 0) { n += 2; x <<= 2; }
	# PC 21
	iand5 := newi(IANDL);
	addrsind(iand5.s, Afp, tmp_x);
	addrsind(iand5.m, Amp, mask2off);
	addrsind(iand5.d, Afp, tmp_t);
	# PC 22
	ibr5 := newi(IBNEL);
	addrsind(ibr5.s, Afp, tmp_t);
	addrimm(ibr5.m, 0);
	addrimm(ibr5.d, start_pc + 25);
	# PC 23
	iadd5 := newi(IADDL);
	addrimm(iadd5.s, 2);
	addrsind(iadd5.m, Afp, tmp_n);
	addrsind(iadd5.d, Afp, tmp_n);
	# PC 24
	ishl5 := newi(ISHLL);
	addrimm(ishl5.s, 2);
	addrsind(ishl5.m, Afp, tmp_x);
	addrsind(ishl5.d, Afp, tmp_x);

	# Step 6: if ((x & 0x8000000000000000) == 0) { n += 1; }
	# PC 25
	iand6 := newi(IANDL);
	addrsind(iand6.s, Afp, tmp_x);
	addrsind(iand6.m, Amp, mask1off);
	addrsind(iand6.d, Afp, tmp_t);
	# PC 26
	ibr6 := newi(IBNEL);
	addrsind(ibr6.s, Afp, tmp_t);
	addrimm(ibr6.m, 0);
	addrimm(ibr6.d, start_pc + 28);
	# PC 27
	iadd6 := newi(IADDL);
	addrimm(iadd6.s, 1);
	addrsind(iadd6.m, Afp, tmp_n);
	addrsind(iadd6.d, Afp, tmp_n);

	# PC 28-30: dst = n (3 NOPs to reach end_pc=31)
	imov_final := newi(IMOVL);
	addrsind(imov_final.s, Afp, tmp_n);
	*imov_final.d = *Wi.dst;

	inop1 := newi(INOP);
	inop2 := newi(INOP);

	# Release temp registers
	relreg(imov0.d);
	relreg(imov_n.d);
	relreg(iand1.d);
}

#
# Translate i64 count trailing zeros.
# Uses binary search: check bottom half, if 0 then add bits and shift right.
# ctz(0) = 64, ctz(1) = 0, ctz(0x8000000000000000) = 63
#

xi64ctz()
{
	# Save starting PC for branch target calculation
	start_pc := pcdis;
	end_pc := start_pc + 31;

	# Allocate registers
	tmp_x := getreg(DIS_L);  # working value
	tmp_n := getreg(DIS_L);  # count
	tmp_t := getreg(DIS_L);  # temporary for AND result

	# Mask constants in module data (64-bit, low bits)
	mask32off := mpbig(big 16r00000000FFFFFFFF);
	mask16off := mpbig(big 16r000000000000FFFF);
	mask8off := mpbig(big 16r00000000000000FF);
	mask4off := mpbig(big 16r000000000000000F);
	mask2off := mpbig(big 16r0000000000000003);
	mask1off := mpbig(big 16r0000000000000001);

	# PC 0: x = input
	imov0 := newi(IMOVL);
	if(Wi.src1pc >= 0)
		*imov0.s = *wcodes[Wi.src1pc].dst;
	else
		*imov0.s = *wsrc(0);
	addrsind(imov0.d, Afp, tmp_x);

	# PC 1: if x != 0, skip to PC 4
	ibr_nz := newi(IBNEL);
	addrsind(ibr_nz.s, Afp, tmp_x);
	addrimm(ibr_nz.m, 0);
	addrimm(ibr_nz.d, start_pc + 4);

	# PC 2: dst = 64
	imov_64 := newi(IMOVL);
	addrimm(imov_64.s, 64);
	*imov_64.d = *Wi.dst;

	# PC 3: jump to end
	ijmp := newi(IJMP);
	addrimm(ijmp.d, end_pc);

	# PC 4: n = 0
	imov_n := newi(IMOVL);
	addrimm(imov_n.s, 0);
	addrsind(imov_n.d, Afp, tmp_n);

	# Step 1: if ((x & 0x00000000FFFFFFFF) == 0) { n += 32; x >>= 32; }
	# PC 5
	iand1 := newi(IANDL);
	addrsind(iand1.s, Afp, tmp_x);
	addrsind(iand1.m, Amp, mask32off);
	addrsind(iand1.d, Afp, tmp_t);
	# PC 6
	ibr1 := newi(IBNEL);
	addrsind(ibr1.s, Afp, tmp_t);
	addrimm(ibr1.m, 0);
	addrimm(ibr1.d, start_pc + 9);
	# PC 7
	iadd1 := newi(IADDL);
	addrimm(iadd1.s, 32);
	addrsind(iadd1.m, Afp, tmp_n);
	addrsind(iadd1.d, Afp, tmp_n);
	# PC 8
	ilsr1 := newi(ILSRL);
	addrimm(ilsr1.s, 32);
	addrsind(ilsr1.m, Afp, tmp_x);
	addrsind(ilsr1.d, Afp, tmp_x);

	# Step 2: if ((x & 0x000000000000FFFF) == 0) { n += 16; x >>= 16; }
	# PC 9
	iand2 := newi(IANDL);
	addrsind(iand2.s, Afp, tmp_x);
	addrsind(iand2.m, Amp, mask16off);
	addrsind(iand2.d, Afp, tmp_t);
	# PC 10
	ibr2 := newi(IBNEL);
	addrsind(ibr2.s, Afp, tmp_t);
	addrimm(ibr2.m, 0);
	addrimm(ibr2.d, start_pc + 13);
	# PC 11
	iadd2 := newi(IADDL);
	addrimm(iadd2.s, 16);
	addrsind(iadd2.m, Afp, tmp_n);
	addrsind(iadd2.d, Afp, tmp_n);
	# PC 12
	ilsr2 := newi(ILSRL);
	addrimm(ilsr2.s, 16);
	addrsind(ilsr2.m, Afp, tmp_x);
	addrsind(ilsr2.d, Afp, tmp_x);

	# Step 3: if ((x & 0x00000000000000FF) == 0) { n += 8; x >>= 8; }
	# PC 13
	iand3 := newi(IANDL);
	addrsind(iand3.s, Afp, tmp_x);
	addrsind(iand3.m, Amp, mask8off);
	addrsind(iand3.d, Afp, tmp_t);
	# PC 14
	ibr3 := newi(IBNEL);
	addrsind(ibr3.s, Afp, tmp_t);
	addrimm(ibr3.m, 0);
	addrimm(ibr3.d, start_pc + 17);
	# PC 15
	iadd3 := newi(IADDL);
	addrimm(iadd3.s, 8);
	addrsind(iadd3.m, Afp, tmp_n);
	addrsind(iadd3.d, Afp, tmp_n);
	# PC 16
	ilsr3 := newi(ILSRL);
	addrimm(ilsr3.s, 8);
	addrsind(ilsr3.m, Afp, tmp_x);
	addrsind(ilsr3.d, Afp, tmp_x);

	# Step 4: if ((x & 0x000000000000000F) == 0) { n += 4; x >>= 4; }
	# PC 17
	iand4 := newi(IANDL);
	addrsind(iand4.s, Afp, tmp_x);
	addrsind(iand4.m, Amp, mask4off);
	addrsind(iand4.d, Afp, tmp_t);
	# PC 18
	ibr4 := newi(IBNEL);
	addrsind(ibr4.s, Afp, tmp_t);
	addrimm(ibr4.m, 0);
	addrimm(ibr4.d, start_pc + 21);
	# PC 19
	iadd4 := newi(IADDL);
	addrimm(iadd4.s, 4);
	addrsind(iadd4.m, Afp, tmp_n);
	addrsind(iadd4.d, Afp, tmp_n);
	# PC 20
	ilsr4 := newi(ILSRL);
	addrimm(ilsr4.s, 4);
	addrsind(ilsr4.m, Afp, tmp_x);
	addrsind(ilsr4.d, Afp, tmp_x);

	# Step 5: if ((x & 0x0000000000000003) == 0) { n += 2; x >>= 2; }
	# PC 21
	iand5 := newi(IANDL);
	addrsind(iand5.s, Afp, tmp_x);
	addrsind(iand5.m, Amp, mask2off);
	addrsind(iand5.d, Afp, tmp_t);
	# PC 22
	ibr5 := newi(IBNEL);
	addrsind(ibr5.s, Afp, tmp_t);
	addrimm(ibr5.m, 0);
	addrimm(ibr5.d, start_pc + 25);
	# PC 23
	iadd5 := newi(IADDL);
	addrimm(iadd5.s, 2);
	addrsind(iadd5.m, Afp, tmp_n);
	addrsind(iadd5.d, Afp, tmp_n);
	# PC 24
	ilsr5 := newi(ILSRL);
	addrimm(ilsr5.s, 2);
	addrsind(ilsr5.m, Afp, tmp_x);
	addrsind(ilsr5.d, Afp, tmp_x);

	# Step 6: if ((x & 0x0000000000000001) == 0) { n += 1; }
	# PC 25
	iand6 := newi(IANDL);
	addrsind(iand6.s, Afp, tmp_x);
	addrsind(iand6.m, Amp, mask1off);
	addrsind(iand6.d, Afp, tmp_t);
	# PC 26
	ibr6 := newi(IBNEL);
	addrsind(ibr6.s, Afp, tmp_t);
	addrimm(ibr6.m, 0);
	addrimm(ibr6.d, start_pc + 28);
	# PC 27
	iadd6 := newi(IADDL);
	addrimm(iadd6.s, 1);
	addrsind(iadd6.m, Afp, tmp_n);
	addrsind(iadd6.d, Afp, tmp_n);

	# PC 28-30: dst = n
	imov_final := newi(IMOVL);
	addrsind(imov_final.s, Afp, tmp_n);
	*imov_final.d = *Wi.dst;

	inop1 := newi(INOP);
	inop2 := newi(INOP);

	# Release temp registers
	relreg(imov0.d);
	relreg(imov_n.d);
	relreg(iand1.d);
}

#
# Translate i64 population count (count of 1 bits).
# Uses parallel bit counting algorithm extended to 64 bits.
#

xi64popcnt()
{
	# Allocate registers
	tmp_x := getreg(DIS_L);  # working value
	tmp_t := getreg(DIS_L);  # temporary

	# Mask constants in module data (64-bit)
	m1off := mpbig(big 16r5555555555555555);  # 0101...
	m2off := mpbig(big 16r3333333333333333);  # 0011...
	m4off := mpbig(big 16r0F0F0F0F0F0F0F0F);  # 00001111...
	m8off := mpbig(big 16r00FF00FF00FF00FF);  # 8-bit groups
	m16off := mpbig(big 16r0000FFFF0000FFFF); # 16-bit groups
	m32off := mpbig(big 16r00000000FFFFFFFF); # 32-bit groups

	# x = input
	imov0 := newi(IMOVL);
	if(Wi.src1pc >= 0)
		*imov0.s = *wcodes[Wi.src1pc].dst;
	else
		*imov0.s = *wsrc(0);
	addrsind(imov0.d, Afp, tmp_x);

	# Step 1: x = (x & m1) + ((x >> 1) & m1)
	# t = x >> 1
	ilsr1 := newi(ILSRL);
	addrimm(ilsr1.s, 1);
	addrsind(ilsr1.m, Afp, tmp_x);
	addrsind(ilsr1.d, Afp, tmp_t);
	# t = t & m1
	iand1t := newi(IANDL);
	addrsind(iand1t.s, Afp, tmp_t);
	addrsind(iand1t.m, Amp, m1off);
	addrsind(iand1t.d, Afp, tmp_t);
	# x = x & m1
	iand1x := newi(IANDL);
	addrsind(iand1x.s, Afp, tmp_x);
	addrsind(iand1x.m, Amp, m1off);
	addrsind(iand1x.d, Afp, tmp_x);
	# x = x + t
	iadd1 := newi(IADDL);
	addrsind(iadd1.s, Afp, tmp_t);
	addrsind(iadd1.m, Afp, tmp_x);
	addrsind(iadd1.d, Afp, tmp_x);

	# Step 2: x = (x & m2) + ((x >> 2) & m2)
	ilsr2 := newi(ILSRL);
	addrimm(ilsr2.s, 2);
	addrsind(ilsr2.m, Afp, tmp_x);
	addrsind(ilsr2.d, Afp, tmp_t);
	iand2t := newi(IANDL);
	addrsind(iand2t.s, Afp, tmp_t);
	addrsind(iand2t.m, Amp, m2off);
	addrsind(iand2t.d, Afp, tmp_t);
	iand2x := newi(IANDL);
	addrsind(iand2x.s, Afp, tmp_x);
	addrsind(iand2x.m, Amp, m2off);
	addrsind(iand2x.d, Afp, tmp_x);
	iadd2 := newi(IADDL);
	addrsind(iadd2.s, Afp, tmp_t);
	addrsind(iadd2.m, Afp, tmp_x);
	addrsind(iadd2.d, Afp, tmp_x);

	# Step 3: x = (x & m4) + ((x >> 4) & m4)
	ilsr3 := newi(ILSRL);
	addrimm(ilsr3.s, 4);
	addrsind(ilsr3.m, Afp, tmp_x);
	addrsind(ilsr3.d, Afp, tmp_t);
	iand3t := newi(IANDL);
	addrsind(iand3t.s, Afp, tmp_t);
	addrsind(iand3t.m, Amp, m4off);
	addrsind(iand3t.d, Afp, tmp_t);
	iand3x := newi(IANDL);
	addrsind(iand3x.s, Afp, tmp_x);
	addrsind(iand3x.m, Amp, m4off);
	addrsind(iand3x.d, Afp, tmp_x);
	iadd3 := newi(IADDL);
	addrsind(iadd3.s, Afp, tmp_t);
	addrsind(iadd3.m, Afp, tmp_x);
	addrsind(iadd3.d, Afp, tmp_x);

	# Step 4: x = (x & m8) + ((x >> 8) & m8)
	ilsr4 := newi(ILSRL);
	addrimm(ilsr4.s, 8);
	addrsind(ilsr4.m, Afp, tmp_x);
	addrsind(ilsr4.d, Afp, tmp_t);
	iand4t := newi(IANDL);
	addrsind(iand4t.s, Afp, tmp_t);
	addrsind(iand4t.m, Amp, m8off);
	addrsind(iand4t.d, Afp, tmp_t);
	iand4x := newi(IANDL);
	addrsind(iand4x.s, Afp, tmp_x);
	addrsind(iand4x.m, Amp, m8off);
	addrsind(iand4x.d, Afp, tmp_x);
	iadd4 := newi(IADDL);
	addrsind(iadd4.s, Afp, tmp_t);
	addrsind(iadd4.m, Afp, tmp_x);
	addrsind(iadd4.d, Afp, tmp_x);

	# Step 5: x = (x & m16) + ((x >> 16) & m16)
	ilsr5 := newi(ILSRL);
	addrimm(ilsr5.s, 16);
	addrsind(ilsr5.m, Afp, tmp_x);
	addrsind(ilsr5.d, Afp, tmp_t);
	iand5t := newi(IANDL);
	addrsind(iand5t.s, Afp, tmp_t);
	addrsind(iand5t.m, Amp, m16off);
	addrsind(iand5t.d, Afp, tmp_t);
	iand5x := newi(IANDL);
	addrsind(iand5x.s, Afp, tmp_x);
	addrsind(iand5x.m, Amp, m16off);
	addrsind(iand5x.d, Afp, tmp_x);
	iadd5 := newi(IADDL);
	addrsind(iadd5.s, Afp, tmp_t);
	addrsind(iadd5.m, Afp, tmp_x);
	addrsind(iadd5.d, Afp, tmp_x);

	# Step 6: x = (x & m32) + ((x >> 32) & m32)
	ilsr6 := newi(ILSRL);
	addrimm(ilsr6.s, 32);
	addrsind(ilsr6.m, Afp, tmp_x);
	addrsind(ilsr6.d, Afp, tmp_t);
	iand6t := newi(IANDL);
	addrsind(iand6t.s, Afp, tmp_t);
	addrsind(iand6t.m, Amp, m32off);
	addrsind(iand6t.d, Afp, tmp_t);
	iand6x := newi(IANDL);
	addrsind(iand6x.s, Afp, tmp_x);
	addrsind(iand6x.m, Amp, m32off);
	addrsind(iand6x.d, Afp, tmp_x);
	iadd6 := newi(IADDL);
	addrsind(iadd6.s, Afp, tmp_t);
	addrsind(iadd6.m, Afp, tmp_x);
	*iadd6.d = *Wi.dst;

	# Release temp registers
	relreg(imov0.d);
	relreg(ilsr1.d);
}

#
# Translate i64 binary arithmetic operation (commutative).
#

xi64binop(disop: int)
{
	i := newi(disop);
	# Use recorded source PCs from simulation instead of wsrc
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*i.s = *wcodes[Wi.src1pc].dst;
		*i.m = *wcodes[Wi.src2pc].dst;
	} else {
		*i.s = *wsrc(1);
		*i.m = *wsrc(0);
	}
	*i.d = *Wi.dst;
}

#
# Translate i64 binary arithmetic operation (non-commutative).
#

xi64binop_nc(disop: int)
{
	i := newi(disop);
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*i.s = *wcodes[Wi.src2pc].dst;
		*i.m = *wcodes[Wi.src1pc].dst;
	} else {
		*i.s = *wsrc(0);
		*i.m = *wsrc(1);
	}
	*i.d = *Wi.dst;
}

#
# Translate f32/f64 binary operation.
#

xfbinop(disop: int)
{
	i := newi(disop);
	# Use recorded source PCs from simulation instead of wsrc
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*i.s = *wcodes[Wi.src1pc].dst;
		*i.m = *wcodes[Wi.src2pc].dst;
	} else {
		*i.s = *wsrc(1);
		*i.m = *wsrc(0);
	}
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
	# Use recorded source PCs from simulation instead of wsrc
	if(Wi.src1pc >= 0 && Wi.src2pc >= 0) {
		*ibr.s = *wcodes[Wi.src1pc].dst;
		*ibr.m = *wcodes[Wi.src2pc].dst;
	} else {
		*ibr.s = *wsrc(1);
		*ibr.m = *wsrc(0);
	}
	addrimm(ibr.d, pcdis + 1);  # skip next instruction

	# Set destination to 0 (false)
	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;
}

#
# Translate i32 unsigned comparison.
# Mask both operands to 32 bits before comparing to treat them as unsigned.
#

xi32cmp_unsigned(disbranchop: int)
{
	# Allocate temps for masked values
	tmp1 := getreg(DIS_W);
	tmp2 := getreg(DIS_W);
	mask32off := mpbig(big 16rFFFFFFFF);

	# Mask first operand (src1 = deeper in stack)
	iand1 := newi(IANDW);
	if(Wi.src1pc >= 0)
		*iand1.s = *wcodes[Wi.src1pc].dst;
	else
		*iand1.s = *wsrc(1);
	addrsind(iand1.m, Amp, mask32off);
	addrsind(iand1.d, Afp, tmp1);

	# Mask second operand (src2 = top of stack)
	iand2 := newi(IANDW);
	if(Wi.src2pc >= 0)
		*iand2.s = *wcodes[Wi.src2pc].dst;
	else
		*iand2.s = *wsrc(0);
	addrsind(iand2.m, Amp, mask32off);
	addrsind(iand2.d, Afp, tmp2);

	# Set destination to 1 (true)
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	# Branch over the "set to 0" if condition is true
	ibr := newi(disbranchop);
	addrsind(ibr.s, Afp, tmp1);
	addrsind(ibr.m, Afp, tmp2);
	addrimm(ibr.d, pcdis + 1);  # skip next instruction

	# Set destination to 0 (false)
	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;

	# Release temps
	relreg(iand1.d);
	relreg(iand2.d);
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
	# IMPORTANT: The source and destination might be the same register.
	# We must copy the input to a temp before writing to dst.

	tmp := getreg(DIS_W);

	# Copy input to temp first
	imov := newi(IMOVW);
	*imov.s = *wsrc(0);
	addrsind(imov.d, Afp, tmp);

	# Set destination to 1 (true)
	iset := newi(IMOVW);
	addrimm(iset.s, 1);
	*iset.d = *Wi.dst;

	# Branch over the "set to 0" if input (from temp) == 0
	ibr := newi(IBEQW);
	addrsind(ibr.s, Afp, tmp);
	addrimm(ibr.m, 0);
	addrimm(ibr.d, pcdis + 1);

	# Set destination to 0 (false)
	iclr := newi(IMOVW);
	addrimm(iclr.s, 0);
	*iclr.d = *Wi.dst;

	relreg(imov.d);
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
# Memory load helper - loads nbytes from memory at address into Wi.dst.
# signed indicates whether to sign-extend the result.
# dtype is DIS_W for i32/f32 or DIS_L for i64/f64.
#
xmemload(nbytes: int, signed: int, dtype: byte)
{
	# Get address from source operand and add static offset
	# Wi.src1pc has the PC of instruction that produced the address
	# Wi.arg2 has the static offset from the load instruction

	# Protect all WASM stack registers from being reused by getreg.
	# The simulation phase runs all instructions ahead of code generation,
	# so registers for values still on the stack may have refcnt=0 (freed
	# by later instructions like br_if or select). Bump refcnts of all
	# previously-used temp slots to prevent overlap with our temporaries.
	saved_tmpssz := tmpssz;
	saved_refcnts := array[saved_tmpssz] of int;
	for(si := 0; si < saved_tmpssz; si += IBY2WD) {
		saved_refcnts[si] = tmps[si].refcnt;
		if(tmps[si].dtype != DIS_X && tmps[si].refcnt == 0)
			tmps[si].refcnt = 1;
	}

	# Allocate temporaries
	tmp_memptr := getreg(DIS_P);  # memory array pointer
	tmp_idx := getreg(DIS_W);     # byte index for iteration
	tmp_baddr := getreg(DIS_W);   # byte address (interior pointer from indb, not GC-traced)
	tmp_byte := getreg(DIS_W);    # single byte value

	# Copy source address to tmp_idx FIRST before any other getreg calls
	# This ensures we don't overwrite the source operand
	imova := newi(IMOVW);
	if(Wi.src1pc >= 0)
		*imova.s = *wcodes[Wi.src1pc].dst;
	else
		*imova.s = *wsrc(0);
	addrsind(imova.d, Afp, tmp_idx);

	# Add static offset if non-zero
	if(Wi.arg2 != 0) {
		off := mpword(Wi.arg2);
		iadd := newi(IADDW);
		addrsind(iadd.s, Afp, tmp_idx);
		addrsind(iadd.m, Amp, off);
		addrsind(iadd.d, Afp, tmp_idx);
	}

	# Load memory pointer from module data: movp WMEM_PTR(mp), tmp_memptr
	imovp := newi(IMOVP);
	addrsind(imovp.s, Amp, WMEM_PTR);
	addrsind(imovp.d, Afp, tmp_memptr);

	# Initialize result to 0
	if(dtype == DIS_L) {
		izero := newi(IMOVL);
		addrimm(izero.s, 0);
		*izero.d = *Wi.dst;
	} else {
		izero := newi(IMOVW);
		addrimm(izero.s, 0);
		*izero.d = *Wi.dst;
	}

	# Load bytes in little-endian order (byte 0 is LSB)
	for(b := 0; b < nbytes; b++) {
		# Calculate byte index: addr + b
		# indb syntax: indb array, dst, index
		# where s=array, m=dst (result address), d=index
		if(b == 0) {
			# First byte, addr is already in tmp_idx
			iindb := newi(IINDB);
			addrsind(iindb.s, Afp, tmp_memptr);   # array
			addrsind(iindb.m, Afp, tmp_baddr);    # result address
			addrsind(iindb.d, Afp, tmp_idx);      # index
		} else {
			# Subsequent bytes: increment address
			iinc := newi(IADDW);
			addrimm(iinc.s, 1);
			addrsind(iinc.m, Afp, tmp_idx);
			addrsind(iinc.d, Afp, tmp_idx);

			iindb := newi(IINDB);
			addrsind(iindb.s, Afp, tmp_memptr);   # array
			addrsind(iindb.m, Afp, tmp_baddr);    # result address
			addrsind(iindb.d, Afp, tmp_idx);      # index
		}

		# Load byte: movb 0(tmp_baddr), tmp_byte
		imovb := newi(IMOVB);
		addrdind(imovb.s, Afpind, tmp_baddr, 0);
		addrsind(imovb.d, Afp, tmp_byte);

		# Extend byte to word: cvtbw
		icvt := newi(ICVTBW);
		addrsind(icvt.s, Afp, tmp_byte);
		addrsind(icvt.d, Afp, tmp_byte);

		# Shift byte to correct position: byte << (b * 8)
		if(b > 0) {
			ishl := newi(ISHLW);
			addrimm(ishl.s, b * 8);
			addrsind(ishl.m, Afp, tmp_byte);
			addrsind(ishl.d, Afp, tmp_byte);
		}

		# OR into result
		if(dtype == DIS_L) {
			# For 64-bit, extend byte to big first
			icvtl := newi(ICVTWL);
			addrsind(icvtl.s, Afp, tmp_byte);
			addrsind(icvtl.d, Afp, tmp_byte);

			ior := newi(IORL);
			addrsind(ior.s, Afp, tmp_byte);
			*ior.m = *Wi.dst;
			*ior.d = *Wi.dst;
		} else {
			ior := newi(IORW);
			addrsind(ior.s, Afp, tmp_byte);
			*ior.m = *Wi.dst;
			*ior.d = *Wi.dst;
		}
	}

	# Sign extension if needed
	if(signed) {
		# Check if high bit of loaded value is set
		# For nbytes=1: bit 7 (mask 0x80)
		# For nbytes=2: bit 15 (mask 0x8000)
		# For nbytes=4: bit 31 (mask 0x80000000)
		signbit := 1 << (nbytes * 8 - 1);
		signmask: big;
		case nbytes {
		1 =>
			if(dtype == DIS_L)
				signmask = big 16rFFFFFFFFFFFFFF00;
			else
				signmask = big 16rFFFFFF00;
		2 =>
			if(dtype == DIS_L)
				signmask = big 16rFFFFFFFFFFFF0000;
			else
				signmask = big 16rFFFF0000;
		4 =>
			signmask = big 16rFFFFFFFF00000000;
		}

		# Test sign bit: and dst, signbit, tmp
		signoff := mpword(signbit);
		iand := newi(IANDW);
		*iand.s = *Wi.dst;
		addrsind(iand.m, Amp, signoff);
		addrsind(iand.d, Afp, tmp_byte);

		# Branch if zero (no sign extension needed)
		ibr := newi(IBEQW);
		addrsind(ibr.s, Afp, tmp_byte);
		addrimm(ibr.m, 0);
		addrimm(ibr.d, pcdis + 1);  # skip next instruction (the sign ext OR)

		# OR with sign extension mask
		maskoff := mpbig(signmask);
		if(dtype == DIS_L) {
			ior := newi(IORL);
			addrsind(ior.s, Amp, maskoff);
			*ior.m = *Wi.dst;
			*ior.d = *Wi.dst;
		} else {
			ior := newi(IORW);
			addrsind(ior.s, Amp, maskoff);
			*ior.m = *Wi.dst;
			*ior.d = *Wi.dst;
		}
	}

	# Release temporaries
	relreg(ref Addr(Afp, 0, tmp_memptr));
	relreg(ref Addr(Afp, 0, tmp_idx));
	relreg(ref Addr(Afp, 0, tmp_baddr));
	relreg(ref Addr(Afp, 0, tmp_byte));

	# Restore saved refcnts
	for(si = 0; si < saved_tmpssz; si += IBY2WD)
		tmps[si].refcnt = saved_refcnts[si];
}

#
# Memory store helper - stores nbytes to memory at address from value.
# dtype is DIS_W for i32/f32 or DIS_L for i64/f64.
#
xmemstore(nbytes: int, dtype: byte)
{
	# Wi.src1pc has address, Wi.src2pc has value
	# Wi.arg2 has the static offset

	# Allocate temporaries
	tmp_memptr := getreg(DIS_P);  # memory array pointer
	tmp_addr := getreg(DIS_W);    # effective address (copy of runtime addr)
	tmp_baddr := getreg(DIS_W);   # byte address (interior pointer from indb, not GC-traced)
	tmp_byte := getreg(DIS_W);    # single byte value
	tmp_val := getreg(dtype);     # value to store (working copy)

	# IMPORTANT: Copy both source operands to temps FIRST before any computation
	# This prevents getreg from returning registers that are still in use by sources

	# Copy value to working register first (value might be in a temp that will be reused)
	if(dtype == DIS_L) {
		imov := newi(IMOVL);
		if(Wi.src2pc >= 0)
			*imov.s = *wcodes[Wi.src2pc].dst;
		else
			*imov.s = *wsrc(0);
		addrsind(imov.d, Afp, tmp_val);
	} else {
		imov := newi(IMOVW);
		if(Wi.src2pc >= 0)
			*imov.s = *wcodes[Wi.src2pc].dst;
		else
			*imov.s = *wsrc(0);
		addrsind(imov.d, Afp, tmp_val);
	}

	# Copy address to tmp_addr (address might overlap with value's register after simulation)
	imova := newi(IMOVW);
	if(Wi.src1pc >= 0)
		*imova.s = *wcodes[Wi.src1pc].dst;
	else
		*imova.s = *wsrc(1);  # address is second from top (below value)
	addrsind(imova.d, Afp, tmp_addr);

	# Add static offset to address if non-zero
	if(Wi.arg2 != 0) {
		off := mpword(Wi.arg2);
		iadd := newi(IADDW);
		addrsind(iadd.s, Afp, tmp_addr);
		addrsind(iadd.m, Amp, off);
		addrsind(iadd.d, Afp, tmp_addr);
	}

	# Load memory pointer from module data
	imovp := newi(IMOVP);
	addrsind(imovp.s, Amp, WMEM_PTR);
	addrsind(imovp.d, Afp, tmp_memptr);

	# Store bytes in little-endian order
	# indb syntax: indb array, dst, index
	# where s=array, m=dst (result address), d=index
	for(b := 0; b < nbytes; b++) {
		# Get index into array: addr + b
		if(b == 0) {
			iindb := newi(IINDB);
			addrsind(iindb.s, Afp, tmp_memptr);   # array
			addrsind(iindb.m, Afp, tmp_baddr);    # result address
			addrsind(iindb.d, Afp, tmp_addr);     # index
		} else {
			# Increment address
			iinc := newi(IADDW);
			addrimm(iinc.s, 1);
			addrsind(iinc.m, Afp, tmp_addr);
			addrsind(iinc.d, Afp, tmp_addr);

			iindb := newi(IINDB);
			addrsind(iindb.s, Afp, tmp_memptr);   # array
			addrsind(iindb.m, Afp, tmp_baddr);    # result address
			addrsind(iindb.d, Afp, tmp_addr);     # index
		}

		# Extract low byte: and val, 0xFF, tmp_byte
		maskoff := mpword(16rFF);
		if(dtype == DIS_L) {
			iand := newi(IANDL);
			addrsind(iand.s, Afp, tmp_val);
			addrsind(iand.m, Amp, maskoff);
			addrsind(iand.d, Afp, tmp_byte);
		} else {
			iand := newi(IANDW);
			addrsind(iand.s, Afp, tmp_val);
			addrsind(iand.m, Amp, maskoff);
			addrsind(iand.d, Afp, tmp_byte);
		}

		# Convert to byte
		icvt := newi(ICVTWB);
		addrsind(icvt.s, Afp, tmp_byte);
		addrsind(icvt.d, Afp, tmp_byte);

		# Store byte: movb tmp_byte, 0(tmp_baddr)
		imovb := newi(IMOVB);
		addrsind(imovb.s, Afp, tmp_byte);
		addrdind(imovb.d, Afpind, tmp_baddr, 0);

		# Shift value right by 8 for next byte
		if(b < nbytes - 1) {
			if(dtype == DIS_L) {
				ishr := newi(ILSRL);
				addrimm(ishr.s, 8);
				addrsind(ishr.m, Afp, tmp_val);
				addrsind(ishr.d, Afp, tmp_val);
			} else {
				ishr := newi(ILSRW);
				addrimm(ishr.s, 8);
				addrsind(ishr.m, Afp, tmp_val);
				addrsind(ishr.d, Afp, tmp_val);
			}
		}
	}

	# Release temporaries
	relreg(ref Addr(Afp, 0, tmp_memptr));
	relreg(ref Addr(Afp, 0, tmp_addr));
	relreg(ref Addr(Afp, 0, tmp_baddr));
	relreg(ref Addr(Afp, 0, tmp_byte));
	relreg(ref Addr(Afp, 0, tmp_val));
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

	# control flow
	Wblock or Wloop =>
		;  # block/loop markers, no direct instruction

	Wif =>
		# Generate conditional branch: if condition == 0, jump to else or end
		i = newi(IBEQW);
		*i.s = *wsrc(0);
		addrimm(i.m, 0);
		addrimm(i.d, 0);  # target patched later
		Wi.disinst = i;

	Welse =>
		# For then branch: copy result value to return area before jumping
		if(Wi.branchsrc != nil) {
			imov := newi(wmovinst(Wi.targettype));
			*imov.s = *Wi.branchsrc;
			addrdind(imov.d, Afpind, WREGRET, 0);
		}
		# Generate unconditional jump to skip else block (for then branch)
		i = newi(IJMP);
		addrimm(i.d, 0);  # target patched later
		Wi.disinst = i;
		# Record where else body actually starts (after the jmp)
		# This is used by Wif to know where to branch
		Wi.elsepc = pcdis;

	Wend =>
		;  # end marker, no direct instruction

	Wbr =>
		# If target block has result type, copy value first
		if(Wi.branchsrc != nil) {
			imov := newi(wmovinst(Wi.targettype));
			*imov.s = *Wi.branchsrc;
			addrdind(imov.d, Afpind, WREGRET, 0);
		}
		i = newi(IJMP);
		addrimm(i.d, 0);  # target patched later
		Wi.disinst = i;

	Wbr_if =>
		# If target block has result type, we need special handling
		# The value to keep is below the condition on stack
		if(Wi.branchsrc != nil) {
			# Copy value to return area, then branch if condition != 0
			imov := newi(wmovinst(Wi.targettype));
			*imov.s = *Wi.branchsrc;
			addrdind(imov.d, Afpind, WREGRET, 0);
		}
		# Branch if top of stack (condition) is non-zero
		i = newi(IBNEW);
		*i.s = *wsrc(0);
		addrimm(i.m, 0);
		addrimm(i.d, 0);  # target patched later
		Wi.disinst = i;

	Wbr_table =>
		# br_table instruction - generate cascading conditional branches
		# brtable array has labels[0..n-1] followed by default label at [n]
		if(Wi.brtable != nil && Wi.brtargets != nil) {
			nlabels := len Wi.brtable - 1;  # exclude default
			Wi.brinsts = array[nlabels + 1] of ref Inst;
			# If target block has result type, copy value to return area first
			if(Wi.branchsrc != nil) {
				imov := newi(wmovinst(Wi.targettype));
				*imov.s = *Wi.branchsrc;
				addrdind(imov.d, Afpind, WREGRET, 0);
			}
			# Generate conditional branches for each label index
			for(bi := 0; bi < nlabels; bi++) {
				# If index == bi, jump to labels[bi]
				ibr := newi(IBEQW);
				*ibr.s = *wsrc(0);  # index from stack
				addrimm(ibr.m, bi);
				addrimm(ibr.d, 0);  # target patched later
				Wi.brinsts[bi] = ibr;
			}
			# Default branch (unconditional jump)
			ijmp := newi(IJMP);
			addrimm(ijmp.d, 0);  # target patched later
			Wi.brinsts[nlabels] = ijmp;
		}

	Wreturn =>
		# Copy return value if any
		if(len wftype.rets > 0) {
			imov := newi(wmovinst(wftype.rets[0]));
			*imov.s = *wsrc(0);
			addrdind(imov.d, Afpind, WREGRET, 0);
		}
		i = newi(IRET);

	Wcall =>
		# Function call - arg1 is target function index
		# WASM function index space: imports first, then locals
		funcidx := Wi.arg1;

		if(funcidx < nimportfuncs && wimporttypes != nil) {
			# --- IMPORTED FUNCTION CALL ---
			calleetype := wimporttypes[funcidx];
			modidx := wimportmodidx[funcidx];
			linkidx := wimportfuncidx[funcidx];
			modptroff := wimpmodptroff[modidx];
			nargs := len calleetype.args;

			# mframe modptroff(mp), $linkidx, frametemp(fp)
			frametemp := getreg(DIS_W);
			imf := newi(IMFRAME);
			addrsind(imf.s, Amp, modptroff);
			addrimm(imf.m, linkidx);
			addrsind(imf.d, Afp, frametemp);

			# Copy arguments to callee's frame
			paramoff := NREG * IBY2WD + 3 * IBY2WD;
			for(ai := 0; ai < nargs; ai++) {
				argtype := calleetype.args[ai];
				dtype := w2dtype(argtype);
				paramoff = align(paramoff, cellsize[int dtype]);
				stackdepth := nargs - 1 - ai;
				imov := newi(wmovinst(argtype));
				*imov.s = *wsrc(stackdepth);
				addrdind(imov.d, Afpind, frametemp, paramoff);
				paramoff += cellsize[int dtype];
			}

			# Set up return pointer if needed
			if(len calleetype.rets > 0 && Wi.dst != nil) {
				ilea := newi(ILEA);
				*ilea.s = *Wi.dst;
				addrdind(ilea.d, Afpind, frametemp, WREGRET);
			}

			# mcall frametemp(fp), $linkidx, modptroff(mp)
			imc := newi(IMCALL);
			addrsind(imc.s, Afp, frametemp);
			addrimm(imc.m, linkidx);
			addrsind(imc.d, Amp, modptroff);

			relreg(ref Addr(Afp, 0, frametemp));
		} else {
			# --- LOCAL FUNCTION CALL ---
			localidx := funcidx - nimportfuncs;

			# Get callee's function type
			if(wmod == nil || wmod.funcsection == nil || wmod.typesection == nil) {
				i = newi(INOP);
			} else if(localidx < 0 || localidx >= len wmod.funcsection.funcs) {
				i = newi(INOP);
			} else {
				typeidx := wmod.funcsection.funcs[localidx];
				calleetype := wmod.typesection.types[typeidx];
				nargs := len calleetype.args;

				# Get callee's type descriptor ID
				calltid := -1;
				if(localidx < len wfunctids)
					calltid = wfunctids[localidx];

				if(calltid < 0) {
					i = newi(INOP);
				} else {
					frametemp := getreg(DIS_W);

					iframe := newi(IFRAME);
					addrimm(iframe.s, calltid);
					addrsind(iframe.d, Afp, frametemp);

					paramoff := NREG * IBY2WD + 3 * IBY2WD;
					for(ai := 0; ai < nargs; ai++) {
						argtype := calleetype.args[ai];
						dtype := w2dtype(argtype);
						paramoff = align(paramoff, cellsize[int dtype]);
						stackdepth := nargs - 1 - ai;
						imov := newi(wmovinst(argtype));
						*imov.s = *wsrc(stackdepth);
						addrdind(imov.d, Afpind, frametemp, paramoff);
						paramoff += cellsize[int dtype];
					}

					if(len calleetype.rets > 0 && Wi.dst != nil) {
						ilea := newi(ILEA);
						*ilea.s = *Wi.dst;
						addrdind(ilea.d, Afpind, frametemp, WREGRET);
					}

					icall := newi(ICALL);
					addrsind(icall.s, Afp, frametemp);
					addrimm(icall.d, 0);  # PC patched later

					# Record call for patching (using local index)
					wcallinsts = ref Callpatch(icall, localidx) :: wcallinsts;

					relreg(ref Addr(Afp, 0, frametemp));
				}
			}
		}

	Wcall_indirect =>
		# Indirect call - for now, just set return value to -1
		# TODO: Implement proper function table support
		if(Wi.dst != nil) {
			i = newi(IMOVW);
			addrimm(i.s, -1);
			*i.d = *Wi.dst;
		}

	# parametric instructions
	Wdrop =>
		# No Dis instruction needed, register already released in sim
		;

	Wselect =>
		# select(c, v1, v2) = c ? v1 : v2
		# WASM stack: [val1, val2, cond] where cond is on top
		# if cond != 0: result = val1
		# if cond == 0: result = val2
		# Implement as: dst = val1; if(cond!=0) skip next; dst = val2
		# Use recorded source PCs from simulation (not wsrc which has register reuse issues)
		src_v1 := wcodes[Wi.src1pc].dst;
		src_v2 := wcodes[Wi.src2pc].dst;
		src_cond := wcodes[Wi.src3pc].dst;

		imov1 := newi(IMOVW);
		*imov1.s = *src_v1;  # val1
		*imov1.d = *Wi.dst;

		ibr := newi(IBNEW);
		*ibr.s = *src_cond;  # cond
		addrimm(ibr.m, 0);
		addrimm(ibr.d, pcdis + 1);

		imov2 := newi(IMOVW);
		*imov2.s = *src_v2;  # val2
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
		gidx := Wi.arg1;
		i = newi(wmovinst(wglobaltypes[gidx]));
		addrsind(i.s, Amp, wglobaloffs[gidx]);
		*i.d = *Wi.dst;

	Wglobal_set =>
		gidx := Wi.arg1;
		i = newi(wmovinst(wglobaltypes[gidx]));
		*i.s = *wsrc(0);
		addrsind(i.d, Amp, wglobaloffs[gidx]);

	# memory instructions - loads
	Wi32_load =>
		xmemload(4, 0, DIS_W);

	Wi32_load8_s =>
		xmemload(1, 1, DIS_W);

	Wi32_load8_u =>
		xmemload(1, 0, DIS_W);

	Wi32_load16_s =>
		xmemload(2, 1, DIS_W);

	Wi32_load16_u =>
		xmemload(2, 0, DIS_W);

	Wi64_load =>
		xmemload(8, 0, DIS_L);

	Wi64_load8_s =>
		xmemload(1, 1, DIS_L);

	Wi64_load8_u =>
		xmemload(1, 0, DIS_L);

	Wi64_load16_s =>
		xmemload(2, 1, DIS_L);

	Wi64_load16_u =>
		xmemload(2, 0, DIS_L);

	Wi64_load32_s =>
		xmemload(4, 1, DIS_L);

	Wi64_load32_u =>
		xmemload(4, 0, DIS_L);

	Wf32_load =>
		# Load 4 bytes as i32, then reinterpret as float
		xmemload(4, 0, DIS_W);

	Wf64_load =>
		# Load 8 bytes as i64, then reinterpret as float
		xmemload(8, 0, DIS_L);

	# memory instructions - stores
	Wi32_store =>
		xmemstore(4, DIS_W);

	Wi32_store8 =>
		xmemstore(1, DIS_W);

	Wi32_store16 =>
		xmemstore(2, DIS_W);

	Wi64_store =>
		xmemstore(8, DIS_L);

	Wi64_store8 =>
		xmemstore(1, DIS_L);

	Wi64_store16 =>
		xmemstore(2, DIS_L);

	Wi64_store32 =>
		xmemstore(4, DIS_L);

	Wf32_store =>
		# Store float bits as 4 bytes
		xmemstore(4, DIS_W);

	Wf64_store =>
		# Store float bits as 8 bytes
		xmemstore(8, DIS_L);

	# numeric instructions - constants
	Wi32_const =>
		i = newi(IMOVW);
		if(notimmable(Wi.arg1)) {
			off := mpword(Wi.arg1);
			addrsind(i.s, Amp, off);
		} else
			addrimm(i.s, Wi.arg1);
		*i.d = *Wi.dst;

	Wi64_const =>
		# 64-bit constants go in module data
		i = newi(IMOVL);
		off := mpbig(big Wi.arg1);
		addrsind(i.s, Amp, off);
		*i.d = *Wi.dst;

	Wf32_const =>
		# Convert f32 bits to real and store in module data
		rv := math->bits32real(Wi.arg1);
		off := mpreal(rv);
		i = newi(IMOVF);
		addrsind(i.s, Amp, off);
		*i.d = *Wi.dst;

	Wf64_const =>
		# Reconstruct f64 bits and convert to real
		bv := big Wi.arg1 | (big Wi.arg2 << 32);
		rv := math->bits64real(bv);
		off := mpreal(rv);
		i = newi(IMOVF);
		addrsind(i.s, Amp, off);
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
		# Unsigned comparison - mask to 32 bits then compare
		xi32cmp_unsigned(IBLTW);

	Wi32_gt_s =>
		xi32cmp(IBGTW);

	Wi32_gt_u =>
		xi32cmp_unsigned(IBGTW);

	Wi32_le_s =>
		xi32cmp(IBLEW);

	Wi32_le_u =>
		xi32cmp_unsigned(IBLEW);

	Wi32_ge_s =>
		xi32cmp(IBGEW);

	Wi32_ge_u =>
		xi32cmp_unsigned(IBGEW);

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
	Wi32_clz =>
		xi32clz();

	Wi32_ctz =>
		xi32ctz();

	Wi32_popcnt =>
		xi32popcnt();

	# i32 binary operations
	Wi32_add =>
		xi32binop(IADDW);

	Wi32_sub =>
		xi32binop_nc(ISUBW);

	Wi32_mul =>
		xi32binop(IMULW);

	Wi32_div_s =>
		xi32binop_nc(IDIVW);

	Wi32_div_u =>
		xi32binop_unsigned(IDIVW);

	Wi32_rem_s =>
		xi32binop_nc(IMODW);

	Wi32_rem_u =>
		xi32binop_unsigned(IMODW);

	Wi32_and =>
		xi32binop(IANDW);

	Wi32_or =>
		xi32binop(IORW);

	Wi32_xor =>
		xi32binop(IXORW);

	Wi32_shl =>
		xi32shift(ISHLW);

	Wi32_shr_s =>
		xi32shift(ISHRW);

	Wi32_shr_u =>
		xi32shift_unsigned(ILSRW);

	Wi32_rotl =>
		# rotl(x, n) = (x << n) | (x >> (32-n)), where n is masked to 5 bits
		# and x is treated as unsigned 32-bit
		xi32rotl_simple();

	Wi32_rotr =>
		# rotr(x, n) = (x >> n) | (x << (32-n)), where n is masked to 5 bits
		# and x is treated as unsigned 32-bit
		xi32rotr_simple();

	# i64 unary operations
	Wi64_clz =>
		xi64clz();

	Wi64_ctz =>
		xi64ctz();

	Wi64_popcnt =>
		xi64popcnt();

	# i64 binary operations
	Wi64_add =>
		xi64binop(IADDL);

	Wi64_sub =>
		xi64binop_nc(ISUBL);

	Wi64_mul =>
		xi64binop(IMULL);

	Wi64_div_s =>
		xi64binop_nc(IDIVL);

	Wi64_div_u =>
		xi64binop_nc(IDIVL);  # simplified

	Wi64_rem_s =>
		xi64binop_nc(IMODL);

	Wi64_rem_u =>
		xi64binop_nc(IMODL);  # simplified

	Wi64_and =>
		xi64binop(IANDL);

	Wi64_or =>
		xi64binop(IORL);

	Wi64_xor =>
		xi64binop(IXORL);

	Wi64_shl =>
		xi64binop_nc(ISHLL);

	Wi64_shr_s =>
		xi64binop_nc(ISHRL);

	Wi64_shr_u =>
		xi64binop_nc(ILSRL);

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

	# sign extension - shift left then arithmetic shift right
	# On 64-bit Dis, we need to shift by 56/48 to put the value at the top
	Wi32_extend8_s =>
		i = newi(ISHLW);
		addrimm(i.s, 56);  # 64 - 8 = 56
		*i.m = *wsrc(0);
		*i.d = *Wi.dst;
		i = newi(ISHRW);
		addrimm(i.s, 56);
		*i.m = *Wi.dst;
		*i.d = *Wi.dst;

	Wi32_extend16_s =>
		i = newi(ISHLW);
		addrimm(i.s, 48);  # 64 - 16 = 48
		*i.m = *wsrc(0);
		*i.d = *Wi.dst;
		i = newi(ISHRW);
		addrimm(i.s, 48);
		*i.m = *Wi.dst;
		*i.d = *Wi.dst;

	Wi64_extend8_s or Wi64_extend16_s or Wi64_extend32_s =>
		# Placeholder
		i = newi(IMOVL);
		*i.s = *wsrc(0);
		*i.d = *Wi.dst;

	Wmemory_size =>
		# Return memory size in pages (64KB each)
		# lena memptr, tmp; lsrw $16, tmp, dst
		tmp_memptr := getreg(DIS_P);
		tmp_len := getreg(DIS_W);

		# Load memory pointer
		imovp := newi(IMOVP);
		addrsind(imovp.s, Amp, WMEM_PTR);
		addrsind(imovp.d, Afp, tmp_memptr);

		# Get array length
		ilena := newi(ILENA);
		addrsind(ilena.s, Afp, tmp_memptr);
		addrsind(ilena.d, Afp, tmp_len);

		# Divide by 65536 (shift right 16)
		ishr := newi(ILSRW);
		addrimm(ishr.s, 16);
		addrsind(ishr.m, Afp, tmp_len);
		*ishr.d = *Wi.dst;

		relreg(ref Addr(Afp, 0, tmp_memptr));
		relreg(ref Addr(Afp, 0, tmp_len));

	Wmemory_grow =>
		# memory.grow is not fully implemented - return -1 to indicate failure
		# A full implementation would:
		# 1. Get current size
		# 2. Allocate new larger array
		# 3. Copy old contents to new array
		# 4. Update WMEM_PTR
		# 5. Return old page count
		i = newi(IMOVW);
		addrimm(i.s, -1);
		*i.d = *Wi.dst;

	* =>
		# Unknown opcode - generate nop
		i = newi(INOP);
	}
}

#
# Patch a branch instruction's target to the correct Dis PC.
#

DEBUG_PATCH: con 0;

wpatchbranch(w: ref Winst, targetpc: int)
{
	if(w.disinst == nil) {
		if(DEBUG_PATCH)
			sys->print("  wpatchbranch: disinst is nil\n");
		return;
	}
	if(targetpc < 0 || targetpc > len wcodes) {
		fatal("wpatchbranch: invalid target " + string targetpc);
		return;
	}
	dispc := wlabels[targetpc];
	if(dispc < 0) {
		fatal("wpatchbranch: unresolved label for WASM PC " + string targetpc);
		return;
	}
	if(DEBUG_PATCH)
		sys->print("  patch opcode %d: wasm targetpc=%d -> dis pc=%d\n", w.opcode, targetpc, dispc);
	addrimm(w.disinst.d, dispc);
}

#
# Patch all branch targets after translation.
#

wpatchbranches(codes: array of ref Winst)
{
	for(pc := 0; pc < len codes; pc++) {
		w := codes[pc];
		case w.opcode {
		Wif =>
			# If there's an else clause, jump to else body; otherwise jump to end
			if(DEBUG_PATCH)
				sys->print("  Wif at wpc %d: elsepc=%d, targetpc=%d\n", pc, w.elsepc, w.targetpc);
			if(w.elsepc >= 0) {
				# Find the Welse instruction and get the actual else body start
				elseInst := codes[w.elsepc];
				if(elseInst.elsepc > 0) {
					# elseInst.elsepc was set during translation to the Dis PC of else body
					if(DEBUG_PATCH)
						sys->print("    -> using else body dis pc=%d\n", elseInst.elsepc);
					addrimm(w.disinst.d, elseInst.elsepc);
				} else
					wpatchbranch(w, w.elsepc);
			} else
				wpatchbranch(w, w.targetpc);
		Welse =>
			if(DEBUG_PATCH)
				sys->print("  Welse at wpc %d: targetpc=%d, branchsrc=%x, elsepc(dis)=%d\n", pc, w.targetpc, w.branchsrc != nil, w.elsepc);
			# If then branch already copied to return area, skip epilogue and jump to ret
			if(w.branchsrc != nil) {
				# Jump past epilogue (+1 for copy instruction, lands on ret)
				dispc := wlabels[w.targetpc];
				if(dispc >= 0) {
					if(DEBUG_PATCH)
						sys->print("    -> skipping epilogue, jmp to dis pc=%d\n", dispc + 1);
					addrimm(w.disinst.d, dispc + 1);
				}
			} else
				wpatchbranch(w, w.targetpc);
		Wbr or Wbr_if =>
			wpatchbranch(w, w.targetpc);
		Wbr_table =>
			# Patch all br_table targets
			if(w.brinsts != nil && w.brtargets != nil) {
				for(bi := 0; bi < len w.brinsts; bi++) {
					if(w.brinsts[bi] != nil) {
						targetpc := w.brtargets[bi];
						dispc := wlabels[targetpc];
						if(dispc >= 0) {
							# If we already copied branchsrc, skip past block's epilogue copy
							if(w.branchsrc != nil)
								dispc++;
							addrimm(w.brinsts[bi].d, dispc);
						}
					}
				}
			}
		}
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

	# Patch all branch targets
	wpatchbranches(codes);
}

#
# Return offset for return value (if any).
#

WREGRET: con 32;  # Return value goes at offset REGRET*IBY2WD = 4*8 = 32

#
# WASM linear memory support
#
WMEM_PTR: con 0;  # Module data offset for memory array pointer
WMEM_PAGES: int;  # Number of 64KB pages
WMEM_DESC: int;   # Type descriptor ID for memory byte array element
hasmemory: int;   # Whether module has memory
wmeminittid: int; # Type descriptor ID for init function frame

#
# WASM globals support
#
wglobaloffs:	array of int;	# mp offset for each global
wglobaltypes:	array of int;	# wasm type (I32, I64, F32, F64) for each global

#
# WASM imports support
#
nimportfuncs:	int;			# number of imported functions
wimporttypes:	array of ref FuncType;	# type for each imported function
wimportmodidx:	array of int;		# unique module index for each import
wimportfuncidx:	array of int;		# function index within its module's LDT
wimportuniqmods:	array of string;	# unique module names
nimportuniqmods:	int;			# number of unique modules
wimpmodpathoff:	array of int;		# mp offset of path string for each module
wimpmodptroff:	array of int;		# mp offset of module pointer for each module

#
# Module data for constants (floats and large integers)
#

MpConst: adt {
	off:	int;
	kind:	int;	# DEFW, DEFF, DEFL, or DEFS
	ival:	int;
	rval:	real;
	bval:	big;
	sval:	string;
};

mpconsts:	list of ref MpConst;
mpoff:		int;

#
# Allocate a real (64-bit float) in module data.
#

mpreal(v: real): int
{
	mpoff = align(mpoff, IBY2LG);
	off := mpoff;
	mpoff += IBY2LG;
	mpconsts = ref MpConst(off, DEFF, 0, v, big 0, nil) :: mpconsts;
	return off;
}

#
# Allocate a word (32-bit int) in module data.
#

mpword(v: int): int
{
	mpoff = align(mpoff, IBY2WD);
	off := mpoff;
	mpoff += IBY2WD;
	mpconsts = ref MpConst(off, DEFW, v, 0.0, big 0, nil) :: mpconsts;
	return off;
}

#
# Allocate a big (64-bit int) in module data.
#

mpbig(v: big): int
{
	mpoff = align(mpoff, IBY2LG);
	off := mpoff;
	mpoff += IBY2LG;
	mpconsts = ref MpConst(off, DEFL, 0, 0.0, v, nil) :: mpconsts;
	return off;
}

#
# Allocate a string pointer in module data.
# Returns the mp offset where the string pointer lives.
#

mpstring(s: string): int
{
	mpoff = align(mpoff, IBY2WD);
	off := mpoff;
	mpoff += IBY2WD;
	mpconsts = ref MpConst(off, DEFS, 0, 0.0, big 0, s) :: mpconsts;
	return off;
}

#
# WASM-specific module data size
#

wdisnvar()
{
	discon(mpoff);
}

#
# WASM-specific var directive for assembly output
#

wasmvar()
{
	bout.puts("\tvar\t@mp," + string mpoff + "\n");

	# Output module data constants for assembly
	rl: list of ref MpConst;
	for(l := mpconsts; l != nil; l = tl l)
		rl = hd l :: rl;
	for(; rl != nil; rl = tl rl) {
		c := hd rl;
		case c.kind {
		DEFW =>
			bout.puts("\tword\t@mp+" + string c.off + "," + string c.ival + "\n");
		DEFF =>
			bout.puts("\treal\t@mp+" + string c.off + "," + string c.rval + "\n");
		DEFL =>
			bout.puts("\tlong\t@mp+" + string c.off + "," + string c.bval + "\n");
		DEFS =>
			bout.puts("\tstring\t@mp+" + string c.off + ",\"" + c.sval + "\"\n");
		}
	}
}

#
# WASM-specific module data output
#

wdisvar()
{
	# Output module data constants in offset order
	# First reverse the list to get forward order
	rl: list of ref MpConst;
	for(l := mpconsts; l != nil; l = tl l)
		rl = hd l :: rl;

	# Write each constant
	for(; rl != nil; rl = tl rl) {
		c := hd rl;
		case c.kind {
		DEFW =>
			disint(c.off, c.ival);
		DEFF =>
			disreal(c.off, c.rval);
		DEFL =>
			dislong(c.off, c.bval);
		DEFS =>
			disstring(c.off, c.sval);
		}
	}

	# Flush any remaining cached data
	disflush(-1, -1, 0);

	# Terminate the data section
	bout.putb(byte 0);
}

#
# WASM-specific dis output - simplified version without Java relocations
#

wdisout()
{
	discon(XMAGIC);
	rtflags := DONTCOMPILE;
	if(nimportuniqmods > 0)
		rtflags |= HASLDT;
	discon(rtflags);	# runtime "hints"
	disstackext();		# minimum stack extent size
	disninst();		# number of instructions
	wdisnvar();		# number of module data bytes
	disndesc();		# number of type descriptors
	disnlinks();		# number of links
	disentry();		# entry point
	disinst();		# instructions
	disdesc();		# type descriptors
	wdisvar();		# module data
	dismod();		# module name
	dislinks();		# link section
	if(nimportuniqmods > 0)
		wdisldts();	# linkage descriptor tables
}

#
# Emit LDTS section for .dis binary output.
# One linkage descriptor table per unique imported module.
#
wdisldts()
{
	discon(nimportuniqmods);
	for(mi := 0; mi < nimportuniqmods; mi++) {
		# Count functions imported from this module
		nfuncs := 0;
		for(fi := 0; fi < nimportfuncs; fi++)
			if(wimportmodidx[fi] == mi)
				nfuncs++;
		discon(nfuncs);

		# Emit each function entry (in order of wimportfuncidx)
		for(fi = 0; fi < nimportfuncs; fi++) {
			if(wimportmodidx[fi] != mi)
				continue;
			ft := wimporttypes[fi];
			sig := wfuncsig(ft);
			disword(sig);

			# Get function name from import section
			fname := wimportfuncname(fi);
			d := array of byte fname;
			bout.write(d, len d);
			bout.putb(byte 0);
		}
	}
	discon(0);  # terminator
}

#
# Emit LDTS section for assembly output.
#
wasmldts()
{
	# Compute total size of linkage descriptor data
	# For now just emit the ldts directive with number of tables
	bout.puts("\tldts\t@ldt," + string nimportuniqmods + "\n");
	ldtoff := 0;
	for(mi := 0; mi < nimportuniqmods; mi++) {
		# Count functions from this module
		nfuncs := 0;
		for(fi := 0; fi < nimportfuncs; fi++)
			if(wimportmodidx[fi] == mi)
				nfuncs++;
		bout.puts("\tword\t@ldt+" + string ldtoff + "," + string nfuncs + "\n");
		ldtoff += IBY2WD;
		for(fi = 0; fi < nimportfuncs; fi++) {
			if(wimportmodidx[fi] != mi)
				continue;
			ft := wimporttypes[fi];
			sig := wfuncsig(ft);
			fname := wimportfuncname(fi);
			# Word-align
			ldtoff = align(ldtoff, IBY2WD);
			bout.puts("\text\t@ldt+" + string ldtoff + ",0x" + hex(sig, 0) + ",\"" + fname + "\"\n");
			# Advance past sig (4 bytes) + name + null + alignment
			ldtoff += IBY2WD + len array of byte fname + 1;
		}
		ldtoff = align(ldtoff, IBY2WD);
	}
}

#
# Get the function name for import function index fi.
#
wimportfuncname(fi: int): string
{
	idx := 0;
	if(wmod != nil && wmod.importsection != nil) {
		for(ii := 0; ii < len wmod.importsection.imports; ii++) {
			pick imp := wmod.importsection.imports[ii] {
			Func =>
				if(idx == fi)
					return imp.name;
				idx++;
			}
		}
	}
	return "unknown";
}

#
# Generate initialization function.
# This allocates a byte array for WASM linear memory, initializes it
# with data from the data section, and loads imported modules.
#
genmeminit(m: ref Mod)
{
	# Open frame for init function - no params, no locals, no return
	frameoff = NREG * IBY2WD + 3 * IBY2WD;
	tmpslwm = frameoff;
	tmpssz = frameoff;
	tmps = array [tmpssz] of { * => Fp(byte 0, 0) };

	initpc := pcdis;

	# Memory initialization
	if(hasmemory) {
		# Create type descriptor for byte array element (1 byte, no pointers)
		WMEM_DESC = descid(1, 0, array[0] of byte);

		# Allocate byte array: newaz $count, $typedesc, temp
		memsize := m.memorysection.memories[0].min * 65536;
		if(memsize == 0)
			memsize = 65536;  # default to 1 page if min is 0
		WMEM_PAGES = m.memorysection.memories[0].min;
		temp := getreg(DIS_P);

		inewa := newi(INEWAZ);
		addrimm(inewa.s, memsize);
		addrimm(inewa.m, WMEM_DESC);
		addrsind(inewa.d, Afp, temp);

		# Store array pointer in module data: movp temp(fp), WMEM_PTR(mp)
		imov := newi(IMOVP);
		addrsind(imov.s, Afp, temp);
		addrsind(imov.d, Amp, WMEM_PTR);

		# Initialize memory with data section contents
		if(m.datasection != nil) {
			for(i := 0; i < len m.datasection.segments; i++) {
				seg := m.datasection.segments[i];
				if(seg.memidx < 0)  # skip passive segments
					continue;
				if(len seg.data == 0)  # skip empty segments
					continue;

				tmp_ptr := getreg(DIS_W);

				for(j := 0; j < len seg.data; j++) {
					byteoff := seg.offset + j;
					byteval := int seg.data[j];

					iindb := newi(IINDB);
					addrsind(iindb.s, Afp, temp);
					addrsind(iindb.m, Afp, tmp_ptr);
					addrimm(iindb.d, byteoff);

					imovb := newi(IMOVB);
					addrimm(imovb.s, byteval);
					addrdind(imovb.d, Afpind, tmp_ptr, 0);
				}

				relreg(ref Addr(Afp, 0, tmp_ptr));
			}
		}

		relreg(ref Addr(Afp, 0, temp));
	}

	# Load imported modules
	for(mi := 0; mi < nimportuniqmods; mi++) {
		# load pathoff(mp), $ldtidx, ptroff(mp)
		iload := newi(ILOAD);
		addrsind(iload.s, Amp, wimpmodpathoff[mi]);
		addrimm(iload.m, mi);
		addrsind(iload.d, Amp, wimpmodptroff[mi]);
	}

	# Return
	iret := newi(IRET);
	iret = iret;

	# Close frame
	frameoff = align(frameoff, IBY2LG);
	if(frameoff > maxframe)
		maxframe = frameoff;

	# Create frame descriptor for init (marks pointer temporaries)
	inittid := wframedesc();

	# Link init function and set as module entry point
	wmeminittid = inittid;
	xtrnlink(inittid, initpc, wfuncsig(ref FuncType(array[0] of int, array[0] of int)), "init", "");
	setentry(initpc, inittid);

	# Reset frame state for subsequent functions
	frameoff = 0;
	tmpslwm = 0;
	tmpssz = 0;
	tmps = nil;
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

	# Reset module data state
	mpoff = 0;
	mpconsts = nil;

	# Count imported functions and build import metadata
	nimportfuncs = 0;
	wimporttypes = nil;
	wimportmodidx = nil;
	wimportfuncidx = nil;
	wimportuniqmods = nil;
	nimportuniqmods = 0;
	wimpmodpathoff = nil;
	wimpmodptroff = nil;

	if(m.importsection != nil && len m.importsection.imports > 0) {
		# First pass: count function imports
		for(ii := 0; ii < len m.importsection.imports; ii++) {
			pick imp := m.importsection.imports[ii] {
			Func =>
				nimportfuncs++;
			}
		}

		if(nimportfuncs > 0) {
			wimporttypes = array[nimportfuncs] of ref FuncType;
			wimportmodidx = array[nimportfuncs] of int;
			wimportfuncidx = array[nimportfuncs] of int;

			# Collect unique module names and build per-import metadata
			uniqmods: list of string;
			nuniq := 0;
			fidx := 0;
			for(ii = 0; ii < len m.importsection.imports; ii++) {
				pick imp := m.importsection.imports[ii] {
				Func =>
					wimporttypes[fidx] = m.typesection.types[imp.typeidx];
					# Find or add unique module
					modname := imp.modname;
					modidx := -1;
					ui := 0;
					for(ul := uniqmods; ul != nil; ul = tl ul) {
						if(hd ul == modname) {
							modidx = ui;
							break;
						}
						ui++;
					}
					if(modidx < 0) {
						modidx = nuniq;
						uniqmods = uniqmods;  # keep list
						# Append to end of list
						if(uniqmods == nil)
							uniqmods = modname :: nil;
						else {
							# Build new list with modname at end
							rev: list of string;
							for(tmp := uniqmods; tmp != nil; tmp = tl tmp)
								rev = hd tmp :: rev;
							uniqmods = modname :: nil;
							for(; rev != nil; rev = tl rev)
								uniqmods = hd rev :: uniqmods;
						}
						nuniq++;
					}
					wimportmodidx[fidx] = modidx;
					fidx++;
				}
			}

			# Convert unique module list to array
			nimportuniqmods = nuniq;
			wimportuniqmods = array[nuniq] of string;
			ui2 := 0;
			for(ul2 := uniqmods; ul2 != nil; ul2 = tl ul2)
				wimportuniqmods[ui2++] = hd ul2;

			# Compute per-module function indices
			# wimportfuncidx[i] = index of import i among imports from the same module
			perfunccount := array[nuniq] of { * => 0 };
			fidx = 0;
			for(ii = 0; ii < len m.importsection.imports; ii++) {
				pick imp := m.importsection.imports[ii] {
				Func =>
					modidx := wimportmodidx[fidx];
					wimportfuncidx[fidx] = perfunccount[modidx]++;
					fidx++;
				}
			}
		}
	}

	# Check for memory section and reserve space for memory pointer
	hasmemory = 0;
	if(m.memorysection != nil && len m.memorysection.memories > 0) {
		hasmemory = 1;
		# Reserve space for WMEM_PTR (pointer to memory array) at offset 0
		# WMEM_PTR is already con 0, so mpoff starts after it
		mpoff = IBY2WD;  # pointer size
	}

	# Allocate mp space for globals
	wglobaloffs = nil;
	wglobaltypes = nil;
	if(m.globalsection != nil && len m.globalsection.globals > 0) {
		ng := len m.globalsection.globals;
		wglobaloffs = array[ng] of int;
		wglobaltypes = array[ng] of int;
		for(gi := 0; gi < ng; gi++) {
			g := m.globalsection.globals[gi];
			wglobaltypes[gi] = g.valtype;
			case g.valtype {
			I32 =>
				wglobaloffs[gi] = mpword(int g.initval);
			I64 =>
				wglobaloffs[gi] = mpbig(g.initval);
			F32 =>
				# initval holds IEEE 754 bits as big
				wglobaloffs[gi] = mpreal(math->bits32real(int g.initval));
			F64 =>
				wglobaloffs[gi] = mpreal(math->bits64real(g.initval));
			}
		}
	}

	# Reserve mp space for import module paths and pointers
	if(nimportuniqmods > 0) {
		wimpmodpathoff = array[nimportuniqmods] of int;
		wimpmodptroff = array[nimportuniqmods] of int;
		for(mi := 0; mi < nimportuniqmods; mi++) {
			# Store module path string in mp
			path := "./" + wimportuniqmods[mi] + ".dis";
			wimpmodpathoff[mi] = mpstring(path);
		}
		for(mi = 0; mi < nimportuniqmods; mi++) {
			# Reserve slot for module pointer (result of load)
			mpoff = align(mpoff, IBY2WD);
			wimpmodptroff[mi] = mpoff;
			mpoff += IBY2WD;
		}
	}

	# Generate memory init function (also handles import loading)
	if(hasmemory || nimportuniqmods > 0)
		genmeminit(m);

	# Initialize function call support
	wmod = m;
	nfuncs := len m.codesection.codes;
	wfunctids = array[nfuncs] of { * => -1 };
	wfuncpcs = array[nfuncs] of { * => -1 };
	wcallinsts = nil;

	for(i := 0; i < len m.codesection.codes; i++) {
		wcode := m.codesection.codes[i];
		typeidx := m.funcsection.funcs[i];
		functype := m.typesection.types[typeidx];

		wftype = functype;

		# Initialize frame for this function
		wopenframe(functype, wcode.locals);

		# Record start PC for this function
		funcpc := pcdis;

		# Initialize local variables to 0 (WASM requires this)
		winitlocals(functype, wcode.locals);

		# Simulate to allocate frame positions
		simwasm(wcode.code, functype);

		# Translate to Dis instructions
		wasm2dis(wcode.code);

		# Copy return value to return location if function returns a value
		if(len functype.rets > 0 && wreturnaddr != nil) {
			imov := newi(wmovinst(functype.rets[0]));
			*imov.s = *wreturnaddr;
			addrdind(imov.d, Afpind, WREGRET, 0);
		}

		# Add return instruction at end
		iret := newi(IRET);
		iret = iret;  # suppress warning

		# Close frame and get type descriptor
		tid := wcloseframe();

		# Store function info for internal calls
		wfunctids[i] = tid;
		wfuncpcs[i] = funcpc;

		# Create link for this function only if it's exported
		# Note: export idx is in WASM function index space (imports + locals)
		if(m.exportsection != nil) {
			for(j := 0; j < len m.exportsection.exports; j++) {
				exp := m.exportsection.exports[j];
				if(exp.kind == 0 && exp.idx == i + nimportfuncs) {
					funcname := sanitizename(exp.name);
					xtrnlink(tid, funcpc, wfuncsig(functype), funcname, "");
					break;
				}
			}
		}
	}

	# Patch all call targets (funcidx is local index, already adjusted)
	for(cl := wcallinsts; cl != nil; cl = tl cl) {
		cp := hd cl;
		if(cp.funcidx >= 0 && cp.funcidx < len wfuncpcs) {
			targetpc := wfuncpcs[cp.funcidx];
			if(targetpc >= 0)
				addrimm(cp.callinst.d, targetpc);
		}
	}

	# Create module data descriptor (id=0) for WASM
	mpoff = align(mpoff, IBY2LG);
	maplen := mpoff / (8*IBY2WD) + (mpoff % (8*IBY2WD) != 0);
	mpmap := array[maplen] of { * => byte 0 };
	# Mark WMEM_PTR as a pointer in the map (offset 0, first word)
	if(hasmemory && maplen > 0)
		setbit(mpmap, WMEM_PTR);
	# Mark import module path strings as pointers
	for(mi := 0; mi < nimportuniqmods; mi++) {
		setbit(mpmap, wimpmodpathoff[mi]);
		setbit(mpmap, wimpmodptroff[mi]);
	}
	mpdescid(mpoff, maplen, mpmap);

}
