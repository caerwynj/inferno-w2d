Dispatcher: module
{
	Arg: adt {
		pick {
		I32 => v: int;
		I64 => v: big;
		F32 => v: real;
		F64 => v: real;
		}
	};

	init: fn();
	loadmod: fn(path: string): string;
	dispatch: fn(funcname: string, args: list of ref Arg): ref Arg;

	# Arg constructors
	argi32: fn(v: int): ref Arg;
	argi64: fn(v: big): ref Arg;
	argf32: fn(v: real): ref Arg;
	argf64: fn(v: real): ref Arg;
};
