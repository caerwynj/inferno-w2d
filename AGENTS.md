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
limbo file.b
```

# run inferno os .dis file
mash is a shell like Plan 9 rc but runs in the Inferno OS and supports most typical UNIX command line utilities like cat, ls, cd, wc, pwd, uniq, echo.
```
mash file.dis
```

