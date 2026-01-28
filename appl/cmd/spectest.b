implement Spectest;

include "sys.m";
	sys: Sys;
	sprint: import sys;

include "draw.m";

include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;

include "json.m";
	json: JSON;
	JValue: import json;

include "math.m";
	math: Math;

Spectest: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

#
# Module interface for local_get tests.
# These signatures match the exported functions from local_get.0.wasm.
# Note: hyphens in export names are converted to underscores.
#

# Module interface for local_get tests
# Only include functions with signatures we know work
LocalGetMod: module {
	# () -> i32
	type_local_i32: fn(): int;

	# () -> i64
	type_local_i64: fn(): big;

	# () -> f32
	type_local_f32: fn(): real;

	# () -> f64
	type_local_f64: fn(): real;

	# (i32) -> i32
	type_param_i32: fn(a: int): int;
	as_block_value: fn(a: int): int;
	as_loop_value: fn(a: int): int;
	as_br_value: fn(a: int): int;
	as_br_if_value: fn(a: int): int;
	as_br_if_value_cond: fn(a: int): int;
	as_br_table_value: fn(a: int): int;
	as_return_value: fn(a: int): int;
	as_if_then: fn(a: int): int;
	as_if_else: fn(a: int): int;

	# (i64) -> i64
	type_param_i64: fn(a: big): big;

	# (f32) -> f32
	type_param_f32: fn(a: real): real;

	# (f64) -> f64
	type_param_f64: fn(a: real): real;

	# (i64, f32, f64, i32, i32) -> void
	type_mixed: fn(a: big, b: real, c: real, d: int, e: int);

	# (i64, f32, f64, i32, i32) -> f64
	read: fn(a: big, b: real, c: real, d: int, e: int): real;
};

wmod: LocalGetMod;
passed, failed, skipped: int;

init(nil: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	if(bufio == nil)
		fatal("can't load bufio");

	json = load JSON JSON->PATH;
	if(json == nil)
		fatal("can't load json");
	json->init(bufio);

	math = load Math Math->PATH;

	if(len argv < 2) {
		sys->print("usage: spectest test.json\n");
		raise "fail:usage";
	}

	testfile := hd tl argv;
	runtest(testfile);

	sys->print("\n=== Test Results ===\n");
	sys->print("Passed:  %d\n", passed);
	sys->print("Failed:  %d\n", failed);
	sys->print("Skipped: %d\n", skipped);
	total := passed + failed + skipped;
	sys->print("Total:   %d\n", total);
	if(passed > 0 && failed == 0)
		sys->print("\nAll executed tests passed.\n");
	else if(failed > 0)
		sys->print("\nSome tests failed.\n");
}

runtest(testfile: string)
{
	buf := bufio->open(testfile, Bufio->OREAD);
	if(buf == nil)
		fatal("can't open " + testfile);

	(jv, err) := json->readjson(buf);
	buf.close();
	if(err != nil)
		fatal("json parse error: " + err);

	if(!jv.isobject())
		fatal("expected JSON object");

	commands := jv.get("commands");
	if(commands == nil || !commands.isarray())
		fatal("expected commands array");

	pick ca := commands {
	Array =>
		for(i := 0; i < len ca.a; i++)
			runcmd(ca.a[i]);
	}
}

runcmd(cmd: ref JValue)
{
	if(!cmd.isobject())
		return;

	typev := cmd.get("type");
	if(typev == nil || !typev.isstring())
		return;

	pick tv := typev {
	String =>
		case tv.s {
		"module" =>
			loadmodule(cmd);
		"assert_return" =>
			assertreturn(cmd);
		"assert_invalid" =>
			assertinvalid(cmd);
		}
	}
}

assertinvalid(cmd: ref JValue)
{
	filenamev := cmd.get("filename");
	if(filenamev == nil || !filenamev.isstring())
		return;

	pick fv := filenamev {
	String =>
		# Convert .wasm filename to .dis
		name := fv.s;
		if(len name > 5 && name[len name - 5:] == ".wasm")
			name = name[:len name - 5] + ".dis";

		# Load from test directory
		path := "test/" + name;

		# Try to load module - it should fail
		tmod := load LocalGetMod path;
		if(tmod != nil) {
			sys->print("FAIL assert_invalid %s: module loaded but should have failed\n", name);
			failed++;
		} else {
			sys->print("PASS assert_invalid %s\n", name);
			passed++;
		}
	}
}

loadmodule(cmd: ref JValue)
{
	filenamev := cmd.get("filename");
	if(filenamev == nil || !filenamev.isstring())
		return;

	pick fv := filenamev {
	String =>
		# Convert .wasm filename to .dis
		name := fv.s;
		if(len name > 5 && name[len name - 5:] == ".wasm")
			name = name[:len name - 5] + ".dis";

		# Load from test directory
		path := "test/" + name;
		sys->print("Loading module: %s\n", path);

		wmod = load LocalGetMod path;
		if(wmod == nil)
			fatal("can't load module: " + path + ": " + sprint("%r"));
	}
}

assertreturn(cmd: ref JValue)
{
	action := cmd.get("action");
	if(action == nil || !action.isobject())
		return;

	fieldv := action.get("field");
	if(fieldv == nil || !fieldv.isstring())
		return;

	argsv := action.get("args");
	expectedv := cmd.get("expected");

	pick fv := fieldv {
	String =>
		funcname := fv.s;
		args := parseargs(argsv);
		expected := parseexpected(expectedv);
		callfunc(funcname, args, expected);
	}
}

# Argument representation
Arg: adt {
	pick {
	I32 => v: int;
	I64 => v: big;
	F32 => v: real;
	F64 => v: real;
	}
};

parseargs(argsv: ref JValue): list of ref Arg
{
	args: list of ref Arg;
	if(argsv == nil || !argsv.isarray())
		return nil;

	pick av := argsv {
	Array =>
		for(i := len av.a - 1; i >= 0; i--) {
			arg := parsearg(av.a[i]);
			if(arg != nil)
				args = arg :: args;
		}
	}
	return args;
}

parsearg(jv: ref JValue): ref Arg
{
	if(!jv.isobject())
		return nil;

	typev := jv.get("type");
	valuev := jv.get("value");
	if(typev == nil || valuev == nil)
		return nil;

	pick tv := typev {
	String =>
		pick vv := valuev {
		String =>
			case tv.s {
			"i32" =>
				return ref Arg.I32(int vv.s);
			"i64" =>
				return ref Arg.I64(big vv.s);
			"f32" =>
				# Value is bit representation
				bits := int vv.s;
				return ref Arg.F32(math->bits32real(bits));
			"f64" =>
				# Value is bit representation
				bits := big vv.s;
				return ref Arg.F64(math->bits64real(bits));
			}
		}
	}
	return nil;
}

parseexpected(expv: ref JValue): list of ref Arg
{
	return parseargs(expv);
}

#
# Sanitize function name: replace hyphens with underscores to match
# the sanitized names in the .dis file.
#

sanitizename(name: string): string
{
	s := "";
	for(i := 0; i < len name; i++) {
		c := name[i];
		if(c == '-')
			s[len s] = '_';
		else
			s[len s] = c;
	}
	return s;
}

callfunc(funcname: string, args: list of ref Arg, expected: list of ref Arg)
{
	if(wmod == nil) {
		sys->print("SKIP %s: no module loaded\n", funcname);
		skipped++;
		return;
	}

	# Call the function based on name (using sanitized names)
	result: ref Arg;
	sname := sanitizename(funcname);

	case sname {
	"type_local_i32" =>
		r := wmod->type_local_i32();
		result = ref Arg.I32(r);
	"type_local_i64" =>
		r := wmod->type_local_i64();
		result = ref Arg.I64(r);
	"type_local_f32" =>
		r := wmod->type_local_f32();
		result = ref Arg.F32(r);
	"type_local_f64" =>
		r := wmod->type_local_f64();
		result = ref Arg.F64(r);
	"type_param_i32" =>
		a := geti32(args);
		r := wmod->type_param_i32(a);
		result = ref Arg.I32(r);
	"type_param_i64" =>
		a := geti64(args);
		r := wmod->type_param_i64(a);
		result = ref Arg.I64(r);
	"type_param_f32" =>
		a := getf32(args);
		r := wmod->type_param_f32(a);
		result = ref Arg.F32(r);
	"type_param_f64" =>
		a := getf64(args);
		r := wmod->type_param_f64(a);
		result = ref Arg.F64(r);
	"as_block_value" =>
		a := geti32(args);
		r := wmod->as_block_value(a);
		result = ref Arg.I32(r);
	"as_loop_value" =>
		a := geti32(args);
		r := wmod->as_loop_value(a);
		result = ref Arg.I32(r);
	"as_br_value" =>
		a := geti32(args);
		r := wmod->as_br_value(a);
		result = ref Arg.I32(r);
	"as_br_if_value" =>
		a := geti32(args);
		r := wmod->as_br_if_value(a);
		result = ref Arg.I32(r);
	"as_br_if_value_cond" =>
		a := geti32(args);
		r := wmod->as_br_if_value_cond(a);
		result = ref Arg.I32(r);
	"as_br_table_value" =>
		a := geti32(args);
		r := wmod->as_br_table_value(a);
		result = ref Arg.I32(r);
	"as_return_value" =>
		a := geti32(args);
		r := wmod->as_return_value(a);
		result = ref Arg.I32(r);
	"as_if_then" =>
		a := geti32(args);
		r := wmod->as_if_then(a);
		result = ref Arg.I32(r);
	"as_if_else" =>
		a := geti32(args);
		r := wmod->as_if_else(a);
		result = ref Arg.I32(r);
	"type_mixed" =>
		(a1, a2, a3, a4, a5) := getmixed(args);
		wmod->type_mixed(a1, a2, a3, a4, a5);
		# no return value
	"read" =>
		(a1, a2, a3, a4, a5) := getmixed(args);
		r := wmod->read(a1, a2, a3, a4, a5);
		result = ref Arg.F64(r);
	* =>
		sys->print("SKIP %s: unsupported function signature\n", funcname);
		skipped++;
		return;
	}

	# Check result against expected
	if(expected == nil) {
		sys->print("PASS %s (no return value)\n", funcname);
		passed++;
		return;
	}

	exp := hd expected;
	if(result == nil) {
		sys->print("FAIL %s: expected return value, got none\n", funcname);
		failed++;
		return;
	}

	if(comparearg(result, exp)) {
		sys->print("PASS %s\n", funcname);
		passed++;
	} else {
		sys->print("FAIL %s: expected %s, got %s\n", funcname, argstr(exp), argstr(result));
		failed++;
	}
}

geti32(args: list of ref Arg): int
{
	if(args == nil)
		return 0;
	pick a := hd args {
	I32 => return a.v;
	}
	return 0;
}

geti64(args: list of ref Arg): big
{
	if(args == nil)
		return big 0;
	pick a := hd args {
	I64 => return a.v;
	}
	return big 0;
}

getf32(args: list of ref Arg): real
{
	if(args == nil)
		return 0.0;
	pick a := hd args {
	F32 => return a.v;
	F64 => return a.v;
	}
	return 0.0;
}

getf64(args: list of ref Arg): real
{
	if(args == nil)
		return 0.0;
	pick a := hd args {
	F32 => return a.v;
	F64 => return a.v;
	}
	return 0.0;
}

getmixed(args: list of ref Arg): (big, real, real, int, int)
{
	a1 := big 0;
	a2 := 0.0;
	a3 := 0.0;
	a4 := 0;
	a5 := 0;

	if(args != nil) {
		a1 = geti64(args);
		args = tl args;
	}
	if(args != nil) {
		a2 = getf32(args);
		args = tl args;
	}
	if(args != nil) {
		a3 = getf64(args);
		args = tl args;
	}
	if(args != nil) {
		a4 = geti32(args);
		args = tl args;
	}
	if(args != nil) {
		a5 = geti32(args);
	}
	return (a1, a2, a3, a4, a5);
}

comparearg(a, b: ref Arg): int
{
	pick aa := a {
	I32 =>
		pick bb := b {
		I32 => return aa.v == bb.v;
		}
	I64 =>
		pick bb := b {
		I64 => return aa.v == bb.v;
		}
	F32 =>
		pick bb := b {
		F32 => return math->realbits32(aa.v) == math->realbits32(bb.v);
		F64 => return math->realbits32(aa.v) == math->realbits32(bb.v);
		}
	F64 =>
		pick bb := b {
		F32 => return math->realbits64(aa.v) == math->realbits64(bb.v);
		F64 => return math->realbits64(aa.v) == math->realbits64(bb.v);
		}
	}
	return 0;
}

argstr(a: ref Arg): string
{
	pick aa := a {
	I32 => return sprint("i32:%d", aa.v);
	I64 => return sprint("i64:%bd", aa.v);
	F32 => return sprint("f32:%g", aa.v);
	F64 => return sprint("f64:%g", aa.v);
	}
	return "?";
}

fatal(msg: string)
{
	sys->print("spectest: %s\n", msg);
	raise "fail:error";
}
