# setup emsdk environment
```
. ~/github/emsdk/emsdk_env.sh
```

# compile C language to WASM
```
emcc -c -g b1.c
```

# dump wasm object file
```
wasm-objdump -hd b1.o
```

# compile limbo .b file
```
limbo src.b
```

# build the project
```
mk install
```

# execute inferno commands
To execute Inferno OS shell run `inferno` in the root folder of the project so that mounts the current working directory `/n/local` in the inferno namespace.
```
inferno ls   # run ls inside the inferno VM
inferno wasm/w2d -m testfile.wasm    # convert wasm to dis. the -m flag generates a .m limbo module.
```

# convert a .wasm to .s dis assembly
```
inferno wasm/w2d -S testfile.wasm
```

# dump a .dis file to dis assembly
```
inferno disdump file.dis
```

# Run a single test suite
```
inferno spectest test/local_get.json
```

# Run the complete test suite
```
cd test; mk test
```

# Dis ISA
Read doc/dis.ms for a description of the Dis VM instruction set architecture.
Read module/isa.m contains the Dis ISA.
See $ROOT/appl/cmd/limbo/ for the limbo compiler and more details on how it outputs Dis instructions.
