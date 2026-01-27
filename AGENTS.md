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

# execute a .dis file
The Inferno OS shell supports most typical UNIX command line utilities like cat, ls, cd, wc, pwd, uniq, echo. `emu` should be run in the root folder of the project so that it sees the current working directory mounted on `/n/local`
```
emu sh -lc "wasm/w2d testfile.wasm"
```

# convert a .wasm to .dis assembly
```
emu sh -lc "wasm/w2d -S testfile.wasm"
```

# dump a .dis file to dis assembly
```
emu sh -lc "disdump file.dis"
```

