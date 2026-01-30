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
The Inferno OS shell supports most typical UNIX command line utilities like cat, ls, cd, wc, pwd, uniq, echo. `inferno` should be run in the root folder of the project so that it sees the current working directory mounted on `/n/local`
```
inferno ls   # run ls inside the inferno VM
inferno wasm/w2d -m testfile.wasm    # convert wasm to dis. the -m flag generates a .m limbo module.
```

# convert a .wasm to .dis assembly
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
