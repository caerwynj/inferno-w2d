#
# Simulate the WASM stack machine on a function.
#

WSTK_SIZE:	con 256;		# max stack depth
WCTRL_SIZE:	con 64;			# max control stack depth

wstack:		array of ref WResult;	# simulated WASM stack
wtos:		int;			# top of stack index

cstack:		array of ref WBlock;	# control stack
ctos:		int;			# control stack top

wfunctype:	ref FuncType;		# current function's type
wcode:		array of ref Winst;	# current function's code

wreturnaddr:	ref Addr;		# address of function return value (stack top at end)

# Module reference for function calls
wmod:		ref Mod;

#
# Push a result onto the simulated stack.
#

wpush(r: ref WResult)
{
	if(wtos >= WSTK_SIZE)
		fatal("wasm stack overflow");
	wstack[wtos++] = r;
}

#
# Pop a result from the simulated stack.
#

wpop(): ref WResult
{
	if(wtos == 0)
		fatal("wasm stack underflow");
	return wstack[--wtos];
}

#
# Peek at stack without popping.
#

wpeek(n: int): ref WResult
{
	if(wtos <= n)
		fatal("wasm stack underflow in peek");
	return wstack[wtos - 1 - n];
}

#
# Push a control block.
#

wpushcontrol(kind: int, startpc: int, endpc: int, resulttype: int)
{
	if(ctos >= WCTRL_SIZE)
		fatal("wasm control stack overflow");
	parent: ref WBlock = nil;
	if(ctos > 0)
		parent = cstack[ctos-1];
	cstack[ctos++] = ref WBlock(kind, startpc, endpc, resulttype, parent, wtos);
}

#
# Pop a control block.
#

wpopcontrol(): ref WBlock
{
	if(ctos == 0)
		fatal("wasm control stack underflow");
	return cstack[--ctos];
}

#
# Get label (control block) at depth n.
# n=0 is the innermost block.
#

wgetlabel(n: int): ref WBlock
{
	if(n >= ctos)
		fatal("wasm invalid label depth");
	return cstack[ctos - 1 - n];
}

#
# Find matching end for a block/loop/if starting at pc.
# Returns the index of the end instruction.
#

wfindend(startpc: int): int
{
	depth := 1;
	for(pc := startpc + 1; pc < len wcode; pc++) {
		case wcode[pc].opcode {
		Wblock or Wloop or Wif =>
			depth++;
		Wend =>
			depth--;
			if(depth == 0)
				return pc;
		}
	}
	fatal("wasm: no matching end for block at " + string startpc);
	return -1;
}

#
# Find else clause for an if starting at pc.
# Returns -1 if no else clause.
#

wfindelse(startpc: int): int
{
	depth := 1;
	for(pc := startpc + 1; pc < len wcode; pc++) {
		case wcode[pc].opcode {
		Wblock or Wloop or Wif =>
			depth++;
		Welse =>
			if(depth == 1)
				return pc;
		Wend =>
			depth--;
			if(depth == 0)
				return -1;
		}
	}
	return -1;
}

#
# Allocate a destination register for an instruction and record it.
#

wallocdst(pc: int, wtype: int)
{
	Wi := wcode[pc];
	Wi.dst = ref Addr(byte 0, 0, 0);
	addrsind(Wi.dst, Afp, getreg(w2dtype(wtype)));
}

#
# Release register used by an instruction's destination.
#

wreldst(pc: int)
{
	Wi := wcode[pc];
	if(Wi.dst != nil)
		relreg(Wi.dst);
}

#
# Get source address from producer instruction.
#

wgetsrc(r: ref WResult): ref Addr
{
	Wi := wcode[r.pc];
	if(Wi.dst == nil)
		fatal("wgetsrc: instruction at " + string r.pc + " has no dst");
	return Wi.dst;
}

#
# Simulate a single WASM instruction.
#

simwinst(pc: int)
{
	Wi := wcode[pc];
	r, r1, r2, r3: ref WResult;

	case Wi.opcode {
	# unreachable and nop
	Wunreachable =>
		;
	Wnop =>
		;

	# control flow
	Wblock =>
		endpc := wfindend(pc);
		wpushcontrol(WBLOCK_BLOCK, pc, endpc, Wi.arg1);

	Wloop =>
		endpc := wfindend(pc);
		wpushcontrol(WBLOCK_LOOP, pc, endpc, Wi.arg1);

	Wif =>
		r = wpop();
		wreldst(r.pc);
		endpc := wfindend(pc);
		elsepc := wfindelse(pc);
		wpushcontrol(WBLOCK_IF, pc, endpc, Wi.arg1);
		# Record branch targets for code generation
		Wi.targetpc = endpc;
		Wi.targettype = Wi.arg1;
		Wi.elsepc = elsepc;

	Welse =>
		# Record jump target (end of if block) for the then branch
		if(ctos > 0) {
			blk := cstack[ctos-1];
			Wi.targetpc = blk.endpc;
			Wi.targettype = blk.resulttype;
			# If block has result type, capture the then branch's value
			if(blk.resulttype != -1 && blk.resulttype != 16r40 && wtos > 0) {
				r = wpeek(0);
				Wi.branchsrc = wgetsrc(r);
			}
		}

	Wend =>
		if(ctos > 0) {
			blk := wpopcontrol();
			# if block has a result, it should be on stack
			if(blk.resulttype != -1 && blk.resulttype != 16r40) {
				# result stays on stack
			}
		}

	Wbr =>
		# unconditional branch - label index in arg1
		labelidx := Wi.arg1;
		blk := wgetlabel(labelidx);
		# For loops, branch to start; for blocks/if, branch to end
		if(blk.kind == WBLOCK_LOOP)
			Wi.targetpc = blk.startpc;
		else
			Wi.targetpc = blk.endpc;
		Wi.targettype = blk.resulttype;
		# If target block has result type, capture the value source
		if(blk.resulttype != -1 && blk.resulttype != 16r40 && wtos > 0) {
			r = wpeek(0);
			Wi.branchsrc = wgetsrc(r);
		}

	Wbr_if =>
		# conditional branch - pops condition
		r = wpop();
		wreldst(r.pc);
		labelidx := Wi.arg1;
		blk := wgetlabel(labelidx);
		if(blk.kind == WBLOCK_LOOP)
			Wi.targetpc = blk.startpc;
		else
			Wi.targetpc = blk.endpc;
		Wi.targettype = blk.resulttype;
		# If target block has result type, the "kept" value is below the condition
		# Note: we already popped condition, so wpeek(0) is the kept value
		if(blk.resulttype != -1 && blk.resulttype != 16r40 && wtos > 0) {
			r = wpeek(0);
			Wi.branchsrc = wgetsrc(r);
		}

	Wbr_table =>
		# branch table - pops index
		r = wpop();
		wreldst(r.pc);
		# Resolve all branch targets
		if(Wi.brtable != nil) {
			Wi.brtargets = array[len Wi.brtable] of int;
			# Use default label's block to get result type (all targets must have compatible types)
			defaultlabelidx := Wi.brtable[len Wi.brtable - 1];
			defaultblk := wgetlabel(defaultlabelidx);
			Wi.targettype = defaultblk.resulttype;
			# If target block has result type, capture the kept value (below the index)
			if(defaultblk.resulttype != -1 && defaultblk.resulttype != 16r40 && wtos > 0) {
				r = wpeek(0);
				Wi.branchsrc = wgetsrc(r);
			}
			for(i := 0; i < len Wi.brtable; i++) {
				labelidx := Wi.brtable[i];
				blk := wgetlabel(labelidx);
				if(blk.kind == WBLOCK_LOOP)
					Wi.brtargets[i] = blk.startpc;
				else
					Wi.brtargets[i] = blk.endpc;
			}
		}

	Wreturn =>
		# return pops values based on function return type
		if(len wfunctype.rets > 0) {
			r = wpop();
			# don't release - need to copy to return location
		}

	Wcall =>
		# function call - arg1 is function index
		funcidx := Wi.arg1;
		if(wmod != nil && wmod.funcsection != nil && wmod.typesection != nil &&
		   funcidx >= 0 && funcidx < len wmod.funcsection.funcs) {
			typeidx := wmod.funcsection.funcs[funcidx];
			calleetype := wmod.typesection.types[typeidx];

			# Pop arguments (they're on stack in order: arg0 deepest, argN-1 on top)
			for(ai := len calleetype.args - 1; ai >= 0; ai--) {
				r = wpop();
				# Don't release - wxlate copies them to callee frame
			}

			# Push return value if any
			if(len calleetype.rets > 0) {
				wallocdst(pc, calleetype.rets[0]);
				wpush(ref WResult(calleetype.rets[0], pc));
			}
		}

	Wcall_indirect =>
		# indirect call - arg1 is type index, pops [args..., table_index]
		r = wpop();  # table index
		wreldst(r.pc);
		# Pop arguments based on type signature
		typeidx := Wi.arg1;
		if(wmod != nil && wmod.typesection != nil &&
		   typeidx >= 0 && typeidx < len wmod.typesection.types) {
			calleetype := wmod.typesection.types[typeidx];
			# Pop arguments
			for(ai := len calleetype.args - 1; ai >= 0; ai--) {
				r = wpop();
				wreldst(r.pc);
			}
			# Push return value if any
			if(len calleetype.rets > 0) {
				wallocdst(pc, calleetype.rets[0]);
				wpush(ref WResult(calleetype.rets[0], pc));
			}
		}

	# parametric instructions
	Wdrop =>
		r = wpop();
		wreldst(r.pc);

	Wselect =>
		r3 = wpop();  # condition
		r2 = wpop();  # val2
		r1 = wpop();  # val1
		# Record source PCs BEFORE releasing registers
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		Wi.src3pc = r3.pc;
		wreldst(r3.pc);
		wreldst(r2.pc);
		wreldst(r1.pc);
		wallocdst(pc, r1.wtype);
		wpush(ref WResult(r1.wtype, pc));

	# variable instructions
	Wlocal_get =>
		dtype := wlocaltype(Wi.arg1);
		wtype := I32;
		if(dtype == DIS_L)
			wtype = I64;
		wallocdst(pc, wtype);
		wpush(ref WResult(wtype, pc));

	Wlocal_set =>
		r = wpop();
		wreldst(r.pc);

	Wlocal_tee =>
		r = wpeek(0);  # peek, don't pop
		# no dst allocation needed, value stays on stack

	Wglobal_get =>
		wallocdst(pc, I32);  # assume i32 for now
		wpush(ref WResult(I32, pc));

	Wglobal_set =>
		r = wpop();
		wreldst(r.pc);

	# memory instructions - load
	Wi32_load or Wi32_load8_s or Wi32_load8_u or Wi32_load16_s or Wi32_load16_u =>
		r = wpop();  # address
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_load or Wi64_load8_s or Wi64_load8_u or Wi64_load16_s or Wi64_load16_u or
	Wi64_load32_s or Wi64_load32_u =>
		r = wpop();  # address
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	Wf32_load =>
		r = wpop();  # address
		wreldst(r.pc);
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	Wf64_load =>
		r = wpop();  # address
		wreldst(r.pc);
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	# memory instructions - store
	Wi32_store or Wi32_store8 or Wi32_store16 =>
		r2 = wpop();  # value
		r1 = wpop();  # address
		wreldst(r2.pc);
		wreldst(r1.pc);

	Wi64_store or Wi64_store8 or Wi64_store16 or Wi64_store32 =>
		r2 = wpop();  # value
		r1 = wpop();  # address
		wreldst(r2.pc);
		wreldst(r1.pc);

	Wf32_store =>
		r2 = wpop();  # value
		r1 = wpop();  # address
		wreldst(r2.pc);
		wreldst(r1.pc);

	Wf64_store =>
		r2 = wpop();  # value
		r1 = wpop();  # address
		wreldst(r2.pc);
		wreldst(r1.pc);

	Wmemory_size =>
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wmemory_grow =>
		r = wpop();  # pages
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	# numeric instructions - constants
	Wi32_const =>
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_const =>
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	Wf32_const =>
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	Wf64_const =>
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	# i32 comparison operations
	Wi32_eqz =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi32_eq or Wi32_ne or Wi32_lt_s or Wi32_lt_u or Wi32_gt_s or Wi32_gt_u or
	Wi32_le_s or Wi32_le_u or Wi32_ge_s or Wi32_ge_u =>
		r2 = wpop();
		r1 = wpop();
		# Record source PCs BEFORE releasing registers
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		wallocdst(pc, I32);
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I32, pc));

	# i64 comparison operations
	Wi64_eqz =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_eq or Wi64_ne or Wi64_lt_s or Wi64_lt_u or Wi64_gt_s or Wi64_gt_u or
	Wi64_le_s or Wi64_le_u or Wi64_ge_s or Wi64_ge_u =>
		r2 = wpop();
		r1 = wpop();
		wallocdst(pc, I32);
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I32, pc));

	# f32 comparison operations
	Wf32_eq or Wf32_ne or Wf32_lt or Wf32_gt or Wf32_le or Wf32_ge =>
		r2 = wpop();
		r1 = wpop();
		wallocdst(pc, I32);
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I32, pc));

	# f64 comparison operations
	Wf64_eq or Wf64_ne or Wf64_lt or Wf64_gt or Wf64_le or Wf64_ge =>
		r2 = wpop();
		r1 = wpop();
		wallocdst(pc, I32);
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I32, pc));

	# i32 unary operations
	Wi32_clz or Wi32_ctz or Wi32_popcnt =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	# i32 binary operations
	Wi32_add or Wi32_sub or Wi32_mul or Wi32_div_s or Wi32_div_u or
	Wi32_rem_s or Wi32_rem_u or Wi32_and or Wi32_or or Wi32_xor or
	Wi32_shl or Wi32_shr_s or Wi32_shr_u or Wi32_rotl or Wi32_rotr =>
		r2 = wpop();
		r1 = wpop();
		# Allocate destination BEFORE releasing sources to avoid reusing source registers
		wallocdst(pc, I32);
		# Record source instruction PCs for translation
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I32, pc));

	# i64 unary operations
	Wi64_clz or Wi64_ctz or Wi64_popcnt =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	# i64 binary operations
	Wi64_add or Wi64_sub or Wi64_mul or Wi64_div_s or Wi64_div_u or
	Wi64_rem_s or Wi64_rem_u or Wi64_and or Wi64_or or Wi64_xor or
	Wi64_shl or Wi64_shr_s or Wi64_shr_u or Wi64_rotl or Wi64_rotr =>
		r2 = wpop();
		r1 = wpop();
		# Allocate destination BEFORE releasing sources to avoid reusing source registers
		wallocdst(pc, I64);
		# Record source instruction PCs for translation
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(I64, pc));

	# f32 unary operations
	Wf32_abs or Wf32_neg or Wf32_ceil or Wf32_floor or Wf32_trunc or
	Wf32_nearest or Wf32_sqrt =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	# f32 binary operations
	Wf32_add or Wf32_sub or Wf32_mul or Wf32_div or Wf32_min or Wf32_max or Wf32_copysign =>
		r2 = wpop();
		r1 = wpop();
		# Allocate destination BEFORE releasing sources to avoid reusing source registers
		wallocdst(pc, F32);
		# Record source instruction PCs for translation
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(F32, pc));

	# f64 unary operations
	Wf64_abs or Wf64_neg or Wf64_ceil or Wf64_floor or Wf64_trunc or
	Wf64_nearest or Wf64_sqrt =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	# f64 binary operations
	Wf64_add or Wf64_sub or Wf64_mul or Wf64_div or Wf64_min or Wf64_max or Wf64_copysign =>
		r2 = wpop();
		r1 = wpop();
		# Allocate destination BEFORE releasing sources to avoid reusing source registers
		wallocdst(pc, F64);
		# Record source instruction PCs for translation
		Wi.src1pc = r1.pc;
		Wi.src2pc = r2.pc;
		wreldst(r2.pc);
		wreldst(r1.pc);
		wpush(ref WResult(F64, pc));

	# conversions
	Wi32_wrap_i64 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi32_trunc_f32_s or Wi32_trunc_f32_u or Wi32_trunc_f64_s or Wi32_trunc_f64_u =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_extend_i32_s or Wi64_extend_i32_u =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	Wi64_trunc_f32_s or Wi64_trunc_f32_u or Wi64_trunc_f64_s or Wi64_trunc_f64_u =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	Wf32_convert_i32_s or Wf32_convert_i32_u or Wf32_convert_i64_s or Wf32_convert_i64_u =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	Wf32_demote_f64 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	Wf64_convert_i32_s or Wf64_convert_i32_u or Wf64_convert_i64_s or Wf64_convert_i64_u =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	Wf64_promote_f32 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	# reinterpret
	Wi32_reinterpret_f32 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_reinterpret_f64 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	Wf32_reinterpret_i32 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F32);
		wpush(ref WResult(F32, pc));

	Wf64_reinterpret_i64 =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, F64);
		wpush(ref WResult(F64, pc));

	# sign extension
	Wi32_extend8_s or Wi32_extend16_s =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I32);
		wpush(ref WResult(I32, pc));

	Wi64_extend8_s or Wi64_extend16_s or Wi64_extend32_s =>
		r = wpop();
		wreldst(r.pc);
		wallocdst(pc, I64);
		wpush(ref WResult(I64, pc));

	* =>
		fatal("simwasm: unknown opcode " + string Wi.opcode);
	}
}

#
# Simulate the WASM function to allocate frame positions.
#

simwasm(code: array of ref Winst, functype: ref FuncType)
{
	wstack = array [WSTK_SIZE] of ref WResult;
	wtos = 0;
	cstack = array [WCTRL_SIZE] of ref WBlock;
	ctos = 0;
	wfunctype = functype;
	wcode = code;
	wreturnaddr = nil;

	# push implicit function block
	wpushcontrol(WBLOCK_BLOCK, -1, len code - 1, -1);

	for(pc := 0; pc < len code; pc++)
		simwinst(pc);

	# Record the return value source (stack top at function end)
	if(len functype.rets > 0 && wtos > 0) {
		r := wstack[wtos - 1];
		wreturnaddr = wgetsrc(r);
	}

	wstack = nil;
	cstack = nil;
}
