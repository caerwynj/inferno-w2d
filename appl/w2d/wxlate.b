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
	*ibr.s = *wsrc(1);
	*ibr.m = *wsrc(0);
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
	Wi64_clz or Wi64_ctz or Wi64_popcnt =>
		i = newi(IMOVL);
		addrimm(i.s, 0);
		*i.d = *Wi.dst;

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
						if(dispc >= 0)
							addrimm(w.brinsts[bi].d, dispc);
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
# Module data for constants (floats and large integers)
#

MpConst: adt {
	off:	int;
	kind:	int;	# DEFW, DEFF, or DEFL
	ival:	int;
	rval:	real;
	bval:	big;
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
	mpconsts = ref MpConst(off, DEFF, 0, v, big 0) :: mpconsts;
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
	mpconsts = ref MpConst(off, DEFW, v, 0.0, big 0) :: mpconsts;
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
	mpconsts = ref MpConst(off, DEFL, 0, 0.0, v) :: mpconsts;
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

	# Reset module data state
	mpoff = 0;
	mpconsts = nil;

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

		# Create link for this function - use export name if available
		funcname := sys->sprint("func%d", i);
		if(m.exportsection != nil) {
			for(j := 0; j < len m.exportsection.exports; j++) {
				exp := m.exportsection.exports[j];
				if(exp.kind == 0 && exp.idx == i) {  # kind 0 = function
					funcname = sanitizename(exp.name);
					break;
				}
			}
		}
		xtrnlink(tid, funcpc, wfuncsig(functype), funcname, "");
	}

	# Create module data descriptor (id=0) for WASM
	# WASM has no pointer types, so the map is all zeros
	mpoff = align(mpoff, IBY2LG);
	maplen := mpoff / (8*IBY2WD) + (mpoff % (8*IBY2WD) != 0);
	mpdescid(mpoff, maplen, array[maplen] of { * => byte 0 });

	# Set first function as entry point if no main was found
	if(pc == -1 && nlinks > 0)
		setentry(0, 0);
}
