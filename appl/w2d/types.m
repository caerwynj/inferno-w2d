_MUSTCOMPILE:		con MUSTCOMPILE<<16;
_DONTCOMPILE:		con DONTCOMPILE<<16;

# Dis operand classification

Anone,
Aimm,
Amp,
Ampind,
Afp,
Afpind,
Aend:			con byte iota;

# Dis n(fp) types

DIS_X,					# not yet typed
DIS_W,					# word (32-bit int)
DIS_L,					# long (64-bit)
DIS_P:			con byte iota;	# pointer

Hashsize:		con 31;
ALLOCINCR:		con 16;

Addr: adt {			# Dis operand
	mode:	byte;		# Anone, Aimm, Amp, etc.
	ival:	int;		# immediate, $ival
	offset:	int;		# single indirect, offset(fp)
				# double indirect, offset(ival(fp))
};

Inst: adt {				# Dis instruction
	op:	byte;			# op code
	s:	ref Addr;		# source
	m:	ref Addr;		# middle
	d:	ref Addr;		# destination
	pc:	int;			# 0-based instruction offset
	line:	int;			# source line number
	next:	cyclic ref Inst;
};
