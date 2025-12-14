Wasm: module 
{
	MAGIC: 		con 16r6d736100;
	VERSION:	con 1;
	
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

	Mod: adt
	{
		magic:  	int;
		version: 	int;
		name:	string;
	};

	init:		fn();
	loadobj:	fn(file: string): (ref Mod, string);
	op2s:	fn(op: int): string;
};

