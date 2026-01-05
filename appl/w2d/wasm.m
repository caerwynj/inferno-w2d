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

Winst: adt {
	opcode: int;
	arg1, arg2: int;
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

Mod: adt
{
	magic:  	int;
	version: 	int;

	importsection: ref ImportSection;
	typesection: ref TypeSection;
	funcsection: ref FuncSection;
	codesection: ref CodeSection;
};
