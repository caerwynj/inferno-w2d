Wasm: module 
{
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
		pick {
		Func => typeidx: int;
		Table =>  min,max: int;
		Mem => min,max: int;
		Global => valtyp, mut: int;
		}
	};	

	ImportSection: adt {
		size: int;
		modname: string;
		name: string;	
		desc: int;
		imports: array of ref Import;
	};

	FuncSection: adt {
		size: int;
		funcs: array of int;
	};

	Local: adt {
		count: int;
		localtyp: int;
	};

	Winst: adt {
		opcode: int;
		arg1, arg2: int;
	};

	Func:adt {
		locals: array of ref Local;
		code: array of ref Winst;	
	};

	CodeSection: adt {
		size: int;
		funcs: array of ref Func;
	};


	Mod: adt
	{
		magic:  	int;
		version: 	int;

		importsection: ref ImportSection;
		typesection: ref TypeSection;
		funcsection: ref FuncSection;
		codesection: ref CodeSection;
	};

	init:		fn();
	loadobj:	fn(file: string): (ref Mod, string);
	op2s:	fn(op: int): string;
};

