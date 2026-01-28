MAGIC: 		con 16r6d736100;
VERSION:	con 1;

SCUSTOM,
STYPE,
SIMPORT,
SFUNC,
STABLE,
SMEMORY,
SGLOBAL,
SEXPORT,
SSTART,
SELEMENT,
SCODE,
SDATA: con iota;

I32: con 16r7f;
I64: con 16r7e;
F32: con 16r7d;
F64: con 16r7c;

Limit: adt {
	min: int;
	max: int;
};

FuncType: adt {
	args: array of int;
	rets: array of int;
};

TypeSection: adt {
	size: int;
	types: array of ref FuncType;
};

Import: adt {
	modname: string;
	name: string;	
	desc: int;
	pick {
	Func => typeidx: int;
	Table =>  min,max: int;
	Mem => min,max: int;
	Global => valtyp, mut: int;
	}
};	

ImportSection: adt {
	size: int;
	imports: array of ref Import;
};

Wlocal: adt {
	count: int;
	localtyp: int;
};

# Stack value tracking
WResult: adt {
	wtype:	int;		# I32, I64, F32, F64
	pc:	int;		# instruction index that produced this value
};

# Control block types
WBLOCK_BLOCK,
WBLOCK_LOOP,
WBLOCK_IF: con iota;

# Control block tracking
WBlock: adt {
	kind:		int;		# WBLOCK_BLOCK, WBLOCK_LOOP, WBLOCK_IF
	startpc:	int;		# instruction index of block start
	endpc:		int;		# instruction index of block end
	resulttype:	int;		# block result type (-1 for none)
	parent:		cyclic ref WBlock;	# enclosing block
	stackdepth:	int;		# stack depth at block entry
};

Winst: adt {
	opcode: int;
	arg1, arg2: int;
	dst: ref Addr;		# destination register for this instruction
	# Branch target info (set during simulation for br/br_if/if/else)
	targetpc: int;		# WASM PC of branch target
	targettype: int;	# result type of target block (-1 or 0x40 for void)
	branchsrc: ref Addr;	# value to copy as block result (for typed blocks)
	elsepc: int;		# WASM PC of else clause (for if blocks)
	disinst: ref Inst;	# Dis instruction for patching (for branches)
};

Wcode:adt {
	size: int;
	locals: array of ref Wlocal;
	code: array of ref Winst;	
};

FuncSection: adt {
	size: int;
	funcs: array of int;
};

CodeSection: adt {
	size: int;
	codes: array of ref Wcode;
};

Export: adt {
	name: string;
	kind: int;	# 0=func, 1=table, 2=mem, 3=global
	idx: int;
};

ExportSection: adt {
	size: int;
	exports: array of ref Export;
};

Mod: adt
{
	magic:  	int;
	version: 	int;

	importsection: ref ImportSection;
	typesection: ref TypeSection;
	funcsection: ref FuncSection;
	codesection: ref CodeSection;
	exportsection: ref ExportSection;
};
