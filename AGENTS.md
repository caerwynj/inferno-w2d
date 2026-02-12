# Generating WASM
```
. ~/github/emsdk/emsdk_env.sh   # setup emsdk environment
emcc -c -g b1.c         # compile C language to WASM
wasm-objdump -hd b1.o   # dump wasm object file
```

# project commands
```
limbo src.b     # compile limbo .b file
limbo -S src.b  # generate assembly .s file
asm src.s       # assemble a dis assembly .s file
inferno src.dis # execute a dis object .dis file
mk install      # build the project
```

# Execute inferno commands
When running Inferno OS shell run `inferno` in the base folder of the project, which mounts the current working directory `/n/local` in the inferno namespace.
```
inferno ls   # run ls inside the inferno VM
inferno wasm/w2d -m testfile.wasm    # convert wasm to dis. the -m flag generates a .m limbo module.
inferno wasm/w2d -S testfile.was    # convert a .wasm to .s dis assembly
inferno disdump file.dis            # dump a .dis file to dis assembly
inferno spectest test/local_get.json # Run a single test suite
```

# Run the complete test suite
```
cd test; mk test
```

# Docs
Read doc/dis.ms for a description of the Dis VM instruction set architecture.
Read module/isa.m contains the Dis ISA.
See $ROOT/appl/cmd/limbo/ for the limbo compiler and more details on how it outputs Dis instructions.

# Debug limbo source files with source level debugger
```
echo -e "run\nnext\nprint bufio\nquit" |inferno debug /dis/ls.dis
echo help | inferno debug   # Get help on debuggerg
```
