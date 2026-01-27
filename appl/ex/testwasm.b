implement TestWasm;

include "sys.m";
	sys: Sys;

include "draw.m";

TestWasm: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

# Interface to the WASM-generated module
Wasm: module
{
	func0:	fn(a, b: int): int;  # add function
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;

	wasmfile := "add_opt.dis";
	if(len args > 1)
		wasmfile = hd tl args;

	sys->print("Loading WASM module: %s\n", wasmfile);

	wasm := load Wasm wasmfile;
	if(wasm == nil) {
		sys->print("Failed to load %s: %r\n", wasmfile);
		return;
	}

	sys->print("Module loaded successfully\n");

	# Test the add function
	a := 3;
	b := 5;
	sys->print("Testing func0(%d, %d)...\n", a, b);
	result := wasm->func0(a, b);
	sys->print("Result: %d\n", result);

	if(result == a + b)
		sys->print("TEST PASSED: %d + %d = %d\n", a, b, result);
	else
		sys->print("TEST FAILED: expected %d, got %d\n", a + b, result);
}
