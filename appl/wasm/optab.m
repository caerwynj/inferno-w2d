optab := array[] of {
	"unreachable",	#0x00
	"nop",		#0x01
	"block",	#0x02
	"loop",		#0x03
	"if",		#0x04
	"else",		#0x05
	"",
	"",
	"",
	"",
	"",
	"end",		#0x0b
	"br",		#0x0c
	"br_if",	#0x0d
	"br_table",	#0x0e
	"return",	#0x0f
	"call",		#0x10
	"call_indirect", #0x11
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"drop",		#0x1a
	"select",	#0x1b
	"",
	"",
	"",
	"",
	"local.get",	#0x20
	"local.set",	#0x21
	"local.tee",	#0x22
	"global.get",	#0x23
	"global.set",	#0x24
	"",
	"",
	"",
	"i32.load",	#0x28
	"i64.load",	#0x29
	"f32.load",	#0x2a
	"f64.load",	#0x2b
	"i32.load8_s",	#0x2c
	"i32.load16_s",	#0x2e
	"i64.load8_s",	#0x30
	"i64.load16_s",	#0x32
	"i64.load32_s",	#0x34
	"i32.load8_u",	#0x2d
	"i32.load16_u",	#0x2f
	"i64.load8_u",	#0x31
	"i64.load16_u",	#0x33
	"i64.load32_u",	#0x35
	"i32.store",	#0x36
	"i64.store",	#0x37
	"f32.store",	#0x38
	"f64.store",	#0x39
	"i32.store8",	#0x3a
	"i32.store16",	#0x3b
	"i64.store8",	#0x3c
	"i64.store16",	#0x3d
	"i64.store32",	#0x3e
	"memory.size",	#0x3f
	"memory.grow",	#0x40
	"i32.const",	#0x41
	"i64.const",	#0x42
	"f32.const",	#0x43
	"f64.const",	#0x44
	"i32.eqz",	#0x45
	"i32.eq",	#0x46
	"i32.ne",	#0x47
	"i32.lt_s",	#0x48
	"i32.lt_u",	#0x49
	"i32.gt_s",	#0x4a
	"i32.gt_u",	#0x4b
	"i32.le_s",	#0x4c
	"i32.le_u",	#0x4d
	"i32.ge_s",	#0x4e
	"i32.ge_u",	#0x4f
	"i64.eqz",	#0x50
	"i64.eq",	#0x51
	"i64.ne",	#0x52
	"i64.lt_s",	#0x53
	"i64.lt_u",	#0x54
	"i64.gt_s",	#0x55
	"i64.gt_u",	#0x56
	"i64.le_s",	#0x57
	"i64.le_u",	#0x58
	"i64.ge_s",	#0x59
	"i64.ge_u",	#0x5a
	"f32.eq",	#0x5b
	"f32.ne",	#0x5c
	"f32.lt",	#0x5d
	"f32.gt",	#0x5e
	"f32.le",	#0x5f
	"f32.ge",	#0x60
	"f64.eq",	#0x61
	"f64.ne",	#0x62
	"f64.lt",	#0x63
	"f64.gt",	#0x64
	"f64.le",	#0x65
	"f64.ge",	#x066
	"i32.clz",	#0x67
	"i32.ctz",	#0x68
	"i32.popcnt",	#0x69
	"i32.add",	#0x6a
	"i32.sub",	#0x6b
	"i32.mul",	#0x6c
	"i32.div_s",	#0x6d
	"i32.div_u",	#0x6e
	"i32.rem_s",	#0x6f
	"i32.rem_u",	#0x70
	"i32.and",	#0x71
	"i32.or",	#0x72
	"i32.xor",	#0x73
	"i32.shl",	#0x74
	"i32.shr_s",	#0x75
	"i32.shr_u",	#0x76
	"i32.rotl",	#0x77
	"i32.rotr",	#0x78
	"i64.clz",	#0x79
	"i64.ctz",	#0x7a
	"i64.popcnt",	#0x7b
	"i64.add",	#0x7c
	"i64.sub",	#0x7d
	"i64.mul",	#0x7e
	"i64.div_s",	#0x7f
	"i64.div_u",	#0x80
	"i64.rem_s",	#0x81
	"i64.rem_u",	#0x82
	"i64.and",	#0x83
	"i64.or",	#0x84
	"i64.xor",	#0x85
	"i64.shl",	#0x86
	"i64.shr_s",	#0x87
	"i64.shr_u",	#0x88
	"i64.rotl",	#0x89
	"i64.rotr",	#0x8a
	"f32.abs",	#0x8b
	"f32.neg",	#0x8c
	"f32.ceil",	#0x8d
	"f32.floor",	#0x8e
	"f32.trunc",	#0x8f
	"f32.nearest",	#0x90
	"f32.sqrt",	#0x91
	"f32.add",	#0x92
	"f32.sub",	#0x93
	"f32.mul",	#0x94
	"f32.div",	#0x95
	"f32.min",	#0x96
	"f32.max",	#0x97
	"f32.copysign",	#0x98
	"f64.abs",	#0x99
	"f64.neg",	#0x9a
	"f64.ceil",	#0x9b
	"f64.floor",	#0x9c
	"f64.trunc",	#0x9d
	"f64.nearest",	#0x9e
	"f64.sqrt",	#0x9f
	"f64.add",	#0xa0
	"f64.sub",	#0xa1
	"f64.mul",	#0xa2
	"f64.div",	#0xa3
	"f64.min",	#0xa4
	"f64.max",	#0xa5
	"f64.copysign", #0xa6
	"i32.wrap_i64",		#0xa7
	"i32.trunc_f32_s",	#0xa8
	"i32.trunc_f32_u",	#0xa9
	"i32.trunc_f64_s",	#0xaa
	"i32.trunc_f64_u",	#0xab
	"i64.extend_i32_s",	#0xac
	"i64.extend_i32_u",	#0xad
	"i64.trunc_f32_s",	#0xae
	"i64.trunc_f32_u",	#0xaf
	"i64.trunc_f64_s",	#0xb0
	"i64.trunc_f64_u",	#0xb1
	"f32.convert_i32_s",	#0xb2
	"f32.convert_i32_u",	#0xb3
	"f32.convert_i64_s",	#0xb4
	"f32.convert_i64_u",	#0xb5
	"f32.demote_f64",	#0xb6
	"f64.convert_i32_s",	#0xb7
	"f64.convert_i32_u",	#0xb8
	"f64.convert_i64_s",	#0xb9
	"f64.convert_i64_u",	#0xba
	"f64.promote_f32",	#0xbb
	"i32.reinterpret_f32",	#0xbc
	"i64.reinterpret_f64",	#0xbd
	"f32.reinterpret_i32",	#0xbe
	"f64.reinterpret_i64",	#0xbf
	"i32.extend8_s",	#0xc0
	"i32.extend16_s",	#0xc1
	"i64.extend8_s",	#0xc2
	"i64.extend16_s",	#0xc3
	"i64.extend32_s",	#0xc4
};

IUNREACHABLE,	#0X00
INOP,		#0X01
IBLOCK,	#0X02
ILOOP,		#0X03
IIF,		#0X04
IELSE,		#0X05
INA06,
INA07,
INA08,
INA09,
INA0A,
IEND,		#0X0B
IBR,		#0X0C
IBR_IF,	#0X0D
IBR_TABLE,	#0X0E
IRETURN,	#0X0F
ICALL,		#0X10
ICALL_INDIRECT, #0X11
INA12,
INA13,
INA14,
INA15,
INA16,
INA17,
INA18,
INA19,
IDROP,		#0X1A
ISELECT,	#0X1B
INA1C,
INA1D,
INA1E,
INA1F,
ILOCAL_GET,	#0X20
ILOCAL_SET,	#0X21
ILOCAL_TEE,	#0X22
IGLOBAL_GET,	#0X23
IGLOBAL_SET,	#0X24
INA25,
INA26,
INA27,
II32_LOAD,	#0X28
II64_LOAD,	#0X29
IF32_LOAD,	#0X2A
IF64_LOAD,	#0X2B
II32_LOAD8_S,	#0X2C
II32_LOAD16_S,	#0X2E
II64_LOAD8_S,	#0X30
II64_LOAD16_S,	#0X32
II64_LOAD32_S,	#0X34
II32_LOAD8_U,	#0X2D
II32_LOAD16_U,	#0X2F
II64_LOAD8_U,	#0X31
II64_LOAD16_U,	#0X33
II64_LOAD32_U,	#0X35
II32_STORE,	#0X36
II64_STORE,	#0X37
IF32_STORE,	#0X38
IF64_STORE,	#0X39
II32_STORE8,	#0X3A
II32_STORE16,	#0X3B
II64_STORE8,	#0X3C
II64_STORE16,	#0X3D
II64_STORE32,	#0X3E
IMEMORY_SIZE,	#0X3F
IMEMORY_GROW,	#0X40
II32_CONST,	#0X41
II64_CONST,	#0X42
IF32_CONST,	#0X43
IF64_CONST,	#0X44
II32_EQZ,	#0X45
II32_EQ,	#0X46
II32_NE,	#0X47
II32_LT_S,	#0X48
II32_LT_U,	#0X49
II32_GT_S,	#0X4A
II32_GT_U,	#0X4B
II32_LE_S,	#0X4C
II32_LE_U,	#0X4D
II32_GE_S,	#0X4E
II32_GE_U,	#0X4F
II64_EQZ,	#0X50
II64_EQ,	#0X51
II64_NE,	#0X52
II64_LT_S,	#0X53
II64_LT_U,	#0X54
II64_GT_S,	#0X55
II64_GT_U,	#0X56
II64_LE_S,	#0X57
II64_LE_U,	#0X58
II64_GE_S,	#0X59
II64_GE_U,	#0X5A
IF32_EQ,	#0X5B
IF32_NE,	#0X5C
IF32_LT,	#0X5D
IF32_GT,	#0X5E
IF32_LE,	#0X5F
IF32_GE,	#0X60
IF64_EQ,	#0X61
IF64_NE,	#0X62
IF64_LT,	#0X63
IF64_GT,	#0X64
IF64_LE,	#0X65
IF64_GE,	#X066
II32_CLZ,	#0X67
II32_CTZ,	#0X68
II32_POPCNT,	#0X69
II32_ADD,	#0X6A
II32_SUB,	#0X6B
II32_MUL,	#0X6C
II32_DIV_S,	#0X6D
II32_DIV_U,	#0X6E
II32_REM_S,	#0X6F
II32_REM_U,	#0X70
II32_AND,	#0X71
II32_OR,	#0X72
II32_XOR,	#0X73
II32_SHL,	#0X74
II32_SHR_S,	#0X75
II32_SHR_U,	#0X76
II32_ROTL,	#0X77
II32_ROTR,	#0X78
II64_CLZ,	#0X79
II64_CTZ,	#0X7A
II64_POPCNT,	#0X7B
II64_ADD,	#0X7C
II64_SUB,	#0X7D
II64_MUL,	#0X7E
II64_DIV_S,	#0X7F
II64_DIV_U,	#0X80
II64_REM_S,	#0X81
II64_REM_U,	#0X82
II64_AND,	#0X83
II64_OR,	#0X84
II64_XOR,	#0X85
II64_SHL,	#0X86
II64_SHR_S,	#0X87
II64_SHR_U,	#0X88
II64_ROTL,	#0X89
II64_ROTR,	#0X8A
IF32_ABS,	#0X8B
IF32_NEG,	#0X8C
IF32_CEIL,	#0X8D
IF32_FLOOR,	#0X8E
IF32_TRUNC,	#0X8F
IF32_NEAREST,	#0X90
IF32_SQRT,	#0X91
IF32_ADD,	#0X92
IF32_SUB,	#0X93
IF32_MUL,	#0X94
IF32_DIV,	#0X95
IF32_MIN,	#0X96
IF32_MAX,	#0X97
IF32_COPYSIGN,	#0X98
IF64_ABS,	#0X99
IF64_NEG,	#0X9A
IF64_CEIL,	#0X9B
IF64_FLOOR,	#0X9C
IF64_TRUNC,	#0X9D
IF64_NEAREST,	#0X9E
IF64_SQRT,	#0X9F
IF64_ADD,	#0XA0
IF64_SUB,	#0XA1
IF64_MUL,	#0XA2
IF64_DIV,	#0XA3
IF64_MIN,	#0XA4
IF64_MAX,	#0XA5
IF64_COPYSIGN, #0XA6
II32_WRAP_I64,		#0XA7
II32_TRUNC_F32_S,	#0XA8
II32_TRUNC_F32_U,	#0XA9
II32_TRUNC_F64_S,	#0XAA
II32_TRUNC_F64_U,	#0XAB
II64_EXTEND_I32_S,	#0XAC
II64_EXTEND_I32_U,	#0XAD
II64_TRUNC_F32_S,	#0XAE
II64_TRUNC_F32_U,	#0XAF
II64_TRUNC_F64_S,	#0XB0
II64_TRUNC_F64_U,	#0XB1
IF32_CONVERT_I32_S,	#0XB2
IF32_CONVERT_I32_U,	#0XB3
IF32_CONVERT_I64_S,	#0XB4
IF32_CONVERT_I64_U,	#0XB5
IF32_DEMOTE_F64,	#0XB6
IF64_CONVERT_I32_S,	#0XB7
IF64_CONVERT_I32_U,	#0XB8
IF64_CONVERT_I64_S,	#0XB9
IF64_CONVERT_I64_U,	#0XBA
IF64_PROMOTE_F32,	#0XBB
II32_REINTERPRET_F32,	#0XBC
II64_REINTERPRET_F64,	#0XBD
IF32_REINTERPRET_I32,	#0XBE
IF64_REINTERPRET_I64,	#0XBF
II32_EXTEND8_S,	#0XC0
II32_EXTEND16_S,	#0XC1
II64_EXTEND8_S,	#0XC2
II64_EXTEND16_S,	#0XC3
II64_EXTEND32_S: con iota;	#0xc4
	
sectab := array [] of {
	"CUSTOM",
	"TYPE",
	"IMPORT",
	"FUNC",
	"TABLE",
	"MEMORY",
	"GLOBAL",
	"EXPORT",
	"START",
	"ELEMENT",
	"CODE",
	"DATA"
};

