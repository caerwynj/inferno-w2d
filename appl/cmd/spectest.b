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

include "dispatcher.m";

Spectest: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

dispatcher: Dispatcher;
passed, failed, skipped: int;
testdir: string;

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

	# Derive test directory from testfile
	testdir = "";
	for(i := len testfile - 1; i >= 0; i--) {
		if(testfile[i] == '/') {
			testdir = testfile[:i+1];
			break;
		}
	}

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
		path := testdir + name;

		# Try to load module - it should fail
		# Use Sys module type as a simple test if file is loadable as a .dis
		tmod := load Sys path;
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
		# Convert .wasm filename to .dis and derive basename
		name := fv.s;
		basename := name;
		if(len name > 5 && name[len name - 5:] == ".wasm")
			basename = name[:len name - 5];

		# Load dispatcher module
		dispatchpath := testdir + basename + "_dispatch.dis";
		sys->print("Loading dispatcher: %s\n", dispatchpath);

		dispatcher = load Dispatcher dispatchpath;
		if(dispatcher == nil)
			fatal("can't load dispatcher: " + dispatchpath + ": " + sprint("%r"));

		dispatcher->init();

		# Load the WASM module via dispatcher
		dispath := testdir + basename + ".dis";
		sys->print("Loading module: %s\n", dispath);

		err := dispatcher->loadmod(dispath);
		if(err != nil)
			fatal("can't load module: " + dispath + ": " + err);
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

# Parsed arg from JSON - simple representation
ParsedArg: adt {
	atype: string;	# "i32", "i64", "f32", "f64"
	ival: int;
	bval: big;
	rval: real;
};

parseargs(argsv: ref JValue): list of ref ParsedArg
{
	args: list of ref ParsedArg;
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

parsearg(jv: ref JValue): ref ParsedArg
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
				# Parse as big first, then sign-extend from 32 to 64 bits
				# WASM i32 values in JSON are given as unsigned 32-bit
				bval := big vv.s;
				# Mask to 32 bits, then sign-extend using shift
				ival := int (bval & big 16rFFFFFFFF);
				# Shift left 32, then arithmetic right 32 to sign-extend
				ival = (ival << 32) >> 32;
				return ref ParsedArg("i32", ival, big 0, 0.0);
			"i64" =>
				return ref ParsedArg("i64", 0, big vv.s, 0.0);
			"f32" =>
				# Parse as big first to handle unsigned bit patterns
				bits := int (big vv.s);
				return ref ParsedArg("f32", 0, big 0, math->bits32real(bits));
			"f64" =>
				bits := big vv.s;
				return ref ParsedArg("f64", 0, big 0, math->bits64real(bits));
			}
		}
	}
	return nil;
}

parseexpected(expv: ref JValue): list of ref ParsedArg
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
		if(c == '-' || c == '.')
			s[len s] = '_';
		else
			s[len s] = c;
	}
	# Escape Limbo reserved keywords by adding underscore suffix
	if(iskeyword(s))
		s += "_";
	return s;
}

iskeyword(s: string): int
{
	# Limbo reserved keywords that might conflict with WASM function names
	case s {
	"adt" or "alt" or "array" or "big" or "break" or "byte" or "case" or "chan" or
	"con" or "continue" or "cyclic" or "do" or "else" or "exception" or "exit" or
	"fn" or "for" or "hd" or "if" or "implement" or "import" or "include" or "int" or
	"len" or "list" or "load" or "module" or "nil" or "of" or "or" or "pick" or
	"raise" or "real" or "ref" or "return" or "self" or "spawn" or "string" or
	"tagof" or "tl" or "to" or "type" or "while" or "and" or "xor" =>
		return 1;
	}
	return 0;
}

# Convert ParsedArg list to Dispatcher Arg list
# Uses the dispatcher's arg constructor functions
toDispatcherArgs(args: list of ref ParsedArg): list of ref Dispatcher->Arg
{
	if(args == nil)
		return nil;

	dargs: list of ref Dispatcher->Arg;
	for(a := args; a != nil; a = tl a) {
		pa := hd a;
		case pa.atype {
		"i32" =>
			dargs = dispatcher->argi32(pa.ival) :: dargs;
		"i64" =>
			dargs = dispatcher->argi64(pa.bval) :: dargs;
		"f32" =>
			dargs = dispatcher->argf32(pa.rval) :: dargs;
		"f64" =>
			dargs = dispatcher->argf64(pa.rval) :: dargs;
		}
	}
	# Reverse to preserve order
	rdargs: list of ref Dispatcher->Arg;
	for(; dargs != nil; dargs = tl dargs)
		rdargs = hd dargs :: rdargs;
	return rdargs;
}

callfunc(funcname: string, args: list of ref ParsedArg, expected: list of ref ParsedArg)
{
	if(dispatcher == nil) {
		sys->print("SKIP %s: no dispatcher loaded\n", funcname);
		skipped++;
		return;
	}

	# Convert args to Dispatcher format
	dargs := toDispatcherArgs(args);

	# Call via dispatcher
	sname := sanitizename(funcname);
	result := dispatcher->dispatch(sname, dargs);

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
		sys->print("FAIL %s: expected %s, got %s\n", funcname, expstr(exp), argstr(result));
		failed++;
	}
}

comparearg(a: ref Dispatcher->Arg, b: ref ParsedArg): int
{
	pick aa := a {
	I32 =>
		if(b.atype == "i32") {
			# Compare as 32-bit values (mask to lower 32 bits)
			mask := big 16rFFFFFFFF;
			av := big aa.v & mask;
			bv := big b.ival & mask;
			# sys->print("DEBUG: aa.v=%bd, b.ival=%bd, av=%bd, bv=%bd\n", big aa.v, big b.ival, av, bv);
			return av == bv;
		}
	I64 =>
		if(b.atype == "i64")
			return aa.v == b.bval;
	F32 =>
		if(b.atype == "f32")
			return math->realbits32(aa.v) == math->realbits32(b.rval);
		if(b.atype == "f64")
			return math->realbits32(aa.v) == math->realbits32(b.rval);
	F64 =>
		if(b.atype == "f32")
			return math->realbits64(aa.v) == math->realbits64(b.rval);
		if(b.atype == "f64")
			return math->realbits64(aa.v) == math->realbits64(b.rval);
	}
	return 0;
}

argstr(a: ref Dispatcher->Arg): string
{
	pick aa := a {
	I32 => return sprint("i32:%d", aa.v);
	I64 => return sprint("i64:%bd", aa.v);
	F32 => return sprint("f32:%g", aa.v);
	F64 => return sprint("f64:%g", aa.v);
	}
	return "?";
}

expstr(a: ref ParsedArg): string
{
	case a.atype {
	"i32" => return sprint("i32:%d", a.ival);
	"i64" => return sprint("i64:%bd", a.bval);
	"f32" => return sprint("f32:%g", a.rval);
	"f64" => return sprint("f64:%g", a.rval);
	}
	return "?";
}

fatal(msg: string)
{
	sys->print("spectest: %s\n", msg);
	raise "fail:error";
}
