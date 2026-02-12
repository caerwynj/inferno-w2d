implement Specgen;

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

include "string.m";
	str: String;

include "wasm.m";
	wasm: Wasm;
	Mod, FuncType, Export: import wasm;

Specgen: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

ofile: string;

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

	str = load String String->PATH;
	if(str == nil)
		fatal("can't load string");

	wasm = load Wasm Wasm->PATH;
	if(wasm == nil)
		fatal("can't load wasm: " + Wasm->PATH + ": " + sprint("%r"));
	wasm->init();

	if(len argv < 2) {
		sys->print("usage: specgen [-o output.b] test.json\n");
		raise "fail:usage";
	}

	# Parse arguments
	argv = tl argv;
	while(argv != nil && len hd argv > 0 && (hd argv)[0] == '-') {
		arg := hd argv;
		argv = tl argv;
		if(arg == "-o" && argv != nil) {
			ofile = hd argv;
			argv = tl argv;
		} else {
			sys->print("usage: specgen [-o output.b] test.json\n");
			raise "fail:usage";
		}
	}

	if(argv == nil) {
		sys->print("usage: specgen [-o output.b] test.json\n");
		raise "fail:usage";
	}

	testfile := hd argv;
	generate(testfile);
}

generate(testfile: string)
{
	# Parse JSON to find module filename
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

	# Find first module command to get WASM filename
	wasmfile: string;
	pick ca := commands {
	Array =>
		for(i := 0; i < len ca.a; i++) {
			cmd := ca.a[i];
			if(!cmd.isobject())
				continue;
			typev := cmd.get("type");
			if(typev == nil || !typev.isstring())
				continue;
			pick tv := typev {
			String =>
				if(tv.s == "module") {
					filenamev := cmd.get("filename");
					if(filenamev != nil && filenamev.isstring()) {
						pick fv := filenamev {
						String =>
							wasmfile = fv.s;
						}
					}
					break;
				}
			}
		}
	}

	if(wasmfile == nil)
		fatal("no module command found in JSON");

	# Derive basename from WASM filename (not JSON filename)
	basename := wasmfile;
	# Strip directory from wasmfile if any
	for(i := len wasmfile - 1; i >= 0; i--) {
		if(wasmfile[i] == '/') {
			basename = wasmfile[i+1:];
			break;
		}
	}
	# Strip .wasm extension
	if(len basename > 5 && basename[len basename - 5:] == ".wasm")
		basename = basename[:len basename - 5];

	# Construct path to wasm file (same directory as JSON)
	wasmpath := wasmfile;
	for(i = len testfile - 1; i >= 0; i--) {
		if(testfile[i] == '/') {
			wasmpath = testfile[:i+1] + wasmfile;
			break;
		}
	}

	# Load WASM module to get exports
	m: ref Mod;
	werr: string;
	{
		(m, werr) = wasm->loadobj(wasmpath);
	} exception e {
		"*" =>
			# wasm parser may crash on code section but exports are already parsed
			sys->print("warning: wasm parsing raised exception: %s\n", e);
	}
	if(m == nil)
		fatal("can't load WASM: " + wasmpath + ": " + werr);

	# Determine output filename
	outfile := ofile;
	if(outfile == nil) {
		# Same directory as testfile
		outfile = basename + "_dispatch.b";
		for(i = len testfile - 1; i >= 0; i--) {
			if(testfile[i] == '/') {
				outfile = testfile[:i+1] + basename + "_dispatch.b";
				break;
			}
		}
	}

	# Generate dispatch module
	genDispatch(m, basename, outfile);
	sys->print("Generated %s\n", outfile);
}

genDispatch(m: ref Mod, basename: string, outfile: string)
{
	fd := sys->create(outfile, Sys->OWRITE, 8r644);
	if(fd == nil)
		fatal("can't create " + outfile);

	# Module name: capitalize first letter and add _dispatch
	# Also sanitize to make valid Limbo identifier (replace dots with underscores)
	safename := sanitizename(basename);
	modname := capitalize(safename) + "_dispatch";
	wasmmodname := capitalize(safename);

	# Write module header
	sys->fprint(fd, "implement %s;\n\n", modname);
	sys->fprint(fd, "include \"sys.m\";\n");
	sys->fprint(fd, "\tsys: Sys;\n\n");
	sys->fprint(fd, "include \"draw.m\";\n\n");
	sys->fprint(fd, "include \"dispatcher.m\";\n");
	sys->fprint(fd, "\tArg: import Dispatcher;\n\n");

	# Write module definition
	sys->fprint(fd, "%s: module {\n", modname);
	sys->fprint(fd, "\tinit: fn();\n");
	sys->fprint(fd, "\tloadmod: fn(path: string): string;\n");
	sys->fprint(fd, "\tdispatch: fn(funcname: string, args: list of ref Arg): ref Arg;\n");
	sys->fprint(fd, "\targi32: fn(v: int): ref Arg;\n");
	sys->fprint(fd, "\targi64: fn(v: big): ref Arg;\n");
	sys->fprint(fd, "\targf32: fn(v: real): ref Arg;\n");
	sys->fprint(fd, "\targf64: fn(v: real): ref Arg;\n");
	sys->fprint(fd, "};\n\n");

	# Write WASM module interface
	sys->fprint(fd, "# WASM module interface\n");
	sys->fprint(fd, "%s: module {\n", wasmmodname);

	# Add init if module has memory (w2d generates init for memory setup)
	hasmem := m.memorysection != nil && len m.memorysection.memories > 0;
	if(hasmem)
		sys->fprint(fd, "\tinit: fn();\n");

	if(m.exportsection != nil) {
		for(i := 0; i < len m.exportsection.exports; i++) {
			exp := m.exportsection.exports[i];
			if(exp.kind != 0)	# only functions
				continue;

			ft := getfunctype(m, exp.idx);
			if(ft == nil)
				continue;

			fname := sanitizename(exp.name);
			sys->fprint(fd, "%s", wfuncdecl(fname, ft));
		}
	}
	sys->fprint(fd, "};\n\n");

	# Write module variable
	sys->fprint(fd, "wmod: %s;\n\n", wasmmodname);

	# Write init function
	sys->fprint(fd, "init()\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tsys = load Sys Sys->PATH;\n");
	sys->fprint(fd, "}\n\n");

	# Write loadmod function
	sys->fprint(fd, "loadmod(path: string): string\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\twmod = load %s path;\n", wasmmodname);
	sys->fprint(fd, "\tif(wmod == nil)\n");
	sys->fprint(fd, "\t\treturn sys->sprint(\"%%r\");\n");
	if(hasmem)
		sys->fprint(fd, "\twmod->init();\n");
	sys->fprint(fd, "\treturn nil;\n");
	sys->fprint(fd, "}\n\n");

	# Write dispatch function
	sys->fprint(fd, "dispatch(funcname: string, args: list of ref Arg): ref Arg\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tcase funcname {\n");

	if(m.exportsection != nil) {
		for(i := 0; i < len m.exportsection.exports; i++) {
			exp := m.exportsection.exports[i];
			if(exp.kind != 0)
				continue;

			ft := getfunctype(m, exp.idx);
			if(ft == nil)
				continue;

			fname := sanitizename(exp.name);
			sys->fprint(fd, "\t\"%s\" =>\n", fname);  # Use sanitized name to match what spectest sends
			genCall(fd, fname, ft);  # Use sanitized name for Limbo call
		}
	}

	sys->fprint(fd, "\t}\n");
	sys->fprint(fd, "\treturn nil;\n");
	sys->fprint(fd, "}\n\n");

	# Write helper functions
	genHelpers(fd);
}

genCall(fd: ref Sys->FD, fname: string, ft: ref FuncType)
{
	# Generate argument extraction
	nargs := len ft.args;
	for(i := 0; i < nargs; i++) {
		argtype := ft.args[i];
		sys->fprint(fd, "\t\ta%d := get%s(args);\n", i, typename(argtype));
		if(i < nargs - 1)
			sys->fprint(fd, "\t\targs = tl args;\n");
	}

	# Generate call
	if(len ft.rets > 0) {
		sys->fprint(fd, "\t\tr := wmod->%s(", fname);
	} else {
		sys->fprint(fd, "\t\twmod->%s(", fname);
	}

	for(i = 0; i < nargs; i++) {
		if(i > 0)
			sys->fprint(fd, ", ");
		sys->fprint(fd, "a%d", i);
	}
	sys->fprint(fd, ");\n");

	# Generate return
	if(len ft.rets > 0) {
		rettype := ft.rets[0];
		sys->fprint(fd, "\t\treturn ref Arg.%s(r);\n", pickname(rettype));
	}
}

genHelpers(fd: ref Sys->FD)
{
	sys->fprint(fd, "geti32(args: list of ref Arg): int\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tif(args == nil)\n");
	sys->fprint(fd, "\t\treturn 0;\n");
	sys->fprint(fd, "\tpick a := hd args {\n");
	sys->fprint(fd, "\tI32 => return a.v;\n");
	sys->fprint(fd, "\t}\n");
	sys->fprint(fd, "\treturn 0;\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "geti64(args: list of ref Arg): big\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tif(args == nil)\n");
	sys->fprint(fd, "\t\treturn big 0;\n");
	sys->fprint(fd, "\tpick a := hd args {\n");
	sys->fprint(fd, "\tI64 => return a.v;\n");
	sys->fprint(fd, "\t}\n");
	sys->fprint(fd, "\treturn big 0;\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "getf32(args: list of ref Arg): real\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tif(args == nil)\n");
	sys->fprint(fd, "\t\treturn 0.0;\n");
	sys->fprint(fd, "\tpick a := hd args {\n");
	sys->fprint(fd, "\tF32 => return a.v;\n");
	sys->fprint(fd, "\tF64 => return a.v;\n");
	sys->fprint(fd, "\t}\n");
	sys->fprint(fd, "\treturn 0.0;\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "getf64(args: list of ref Arg): real\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\tif(args == nil)\n");
	sys->fprint(fd, "\t\treturn 0.0;\n");
	sys->fprint(fd, "\tpick a := hd args {\n");
	sys->fprint(fd, "\tF32 => return a.v;\n");
	sys->fprint(fd, "\tF64 => return a.v;\n");
	sys->fprint(fd, "\t}\n");
	sys->fprint(fd, "\treturn 0.0;\n");
	sys->fprint(fd, "}\n\n");

	# Arg constructors
	sys->fprint(fd, "argi32(v: int): ref Arg\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\treturn ref Arg.I32(v);\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "argi64(v: big): ref Arg\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\treturn ref Arg.I64(v);\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "argf32(v: real): ref Arg\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\treturn ref Arg.F32(v);\n");
	sys->fprint(fd, "}\n\n");

	sys->fprint(fd, "argf64(v: real): ref Arg\n");
	sys->fprint(fd, "{\n");
	sys->fprint(fd, "\treturn ref Arg.F64(v);\n");
	sys->fprint(fd, "}\n");
}

getfunctype(m: ref Mod, funcidx: int): ref FuncType
{
	# Account for imports
	nimports := 0;
	if(m.importsection != nil) {
		for(j := 0; j < len m.importsection.imports; j++) {
			pick imp := m.importsection.imports[j] {
			Func =>
				nimports++;
			}
		}
	}

	typeidx: int;
	if(funcidx < nimports) {
		# Imported function
		impidx := 0;
		for(j := 0; j < len m.importsection.imports; j++) {
			pick imp := m.importsection.imports[j] {
			Func =>
				if(impidx == funcidx) {
					typeidx = imp.typeidx;
					break;
				}
				impidx++;
			}
		}
	} else {
		# Module function
		localidx := funcidx - nimports;
		if(m.funcsection == nil || localidx >= len m.funcsection.funcs)
			return nil;
		typeidx = m.funcsection.funcs[localidx];
	}

	if(m.typesection == nil || typeidx >= len m.typesection.types)
		return nil;

	return m.typesection.types[typeidx];
}

sanitizename(name: string): string
{
	s := "";
	for(i := 0; i < len name; i++) {
		c := name[i];
		if(c == '-' || c == '.')
			s += "_";
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

capitalize(s: string): string
{
	if(len s == 0)
		return s;
	r := s;
	if(r[0] >= 'a' && r[0] <= 'z')
		r[0] = r[0] - 'a' + 'A';
	return r;
}

# WASM type constants (from wasm.m)
I32: con 16r7f;
I64: con 16r7e;
F32: con 16r7d;
F64: con 16r7c;

wtype2limbo(wtype: int): string
{
	case wtype {
	I32 =>
		return "int";
	I64 =>
		return "big";
	F32 or F64 =>
		return "real";
	}
	return "int";
}

typename(wtype: int): string
{
	case wtype {
	I32 =>
		return "i32";
	I64 =>
		return "i64";
	F32 =>
		return "f32";
	F64 =>
		return "f64";
	}
	return "i32";
}

pickname(wtype: int): string
{
	case wtype {
	I32 =>
		return "I32";
	I64 =>
		return "I64";
	F32 =>
		return "F32";
	F64 =>
		return "F64";
	}
	return "I32";
}

wfuncdecl(name: string, ft: ref FuncType): string
{
	s := "\t" + name + ": fn(";
	for(i := 0; i < len ft.args; i++) {
		if(i > 0)
			s += ", ";
		s += sprint("arg%d: %s", i, wtype2limbo(ft.args[i]));
	}
	s += ")";
	if(len ft.rets > 0)
		s += ": " + wtype2limbo(ft.rets[0]);
	s += ";\n";
	return s;
}

fatal(msg: string)
{
	sys->print("specgen: %s\n", msg);
	raise "fail:error";
}
