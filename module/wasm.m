Wasm: module
{
	PATH:		con "/dis/wasm.dis";

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

	Local: adt {
		count: int;
		localtyp: int;
	};

	Winst: adt {
		opcode: int;
		arg1, arg2: int;
	};

	Code:adt {
		size: int;
		locals: array of ref Local;
		code: array of ref Winst;	
	};

	FuncSection: adt {
		size: int;
		funcs: array of int;
	};

	CodeSection: adt {
		size: int;
		codes: array of ref Code;
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

	Memory: adt {
		min: int;
		max: int;  # -1 if no max
	};

	MemorySection: adt {
		size: int;
		memories: array of ref Memory;
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
		memorysection: ref MemorySection;
	};

	init:		fn();
	loadobj:	fn(file: string): (ref Mod, string);
	op2s:	fn(op: int): string;
};

