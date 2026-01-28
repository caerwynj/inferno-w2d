implement W2d;

include "sys.m";
include "bufio.m";
include "draw.m";
include "keyring.m";
include "math.m";
include "string.m";
include "isa.m";

include "types.m";

include "wasmisa.m";
include "optab.m";

W2d: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

include "arg.m";
include "main.b";

include "wasm.m";
include "wasmdas.b";

include "module.b";
include "entry.b";
include "desc.b";
include "links.b";
include "frame.b";
include "emit.b";
include "asm.b";
include "dis.b";
include "sbl.b";
include "util.b";

include "simwasm.b";
include "wxlate.b";
