implement Command;

include "sys.m";
sys: Sys;
include "draw.m";
include "wasm.m";
wasm: Wasm;

Command: module { init: fn(ctxt: ref Draw->Context, args: list of string); };

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	wasm = load Wasm "wasm.dis";
	wasm->init();

	args = tl args;
	if (args == nil) {
		sys->print("wasm file\n");
		exit;
	}

	file := hd args;
	(m, s) := wasm->loadobj(file);
	if(m != nil)
		sys->print("Magic %xd \n", m.magic);
	else
		sys->print("Error %s\n", s);
}


