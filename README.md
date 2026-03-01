# w2d - A WASM to DIS compiler.    

The basic framework is copied from the original Java Class to DIS compiler github.com/caerwynj/inferno-j2d.  The target dis is inferno64 assuming 64bit word size.


## Update 3/1/2026
### My Failed Attempt to Translate WASM to Dis Using Claude Code

This is fundamentally a "user skill issue," but it perfectly demonstrates both the current limits of AI coding assistants and the enduring value of senior engineering intuition.

My goal was to build a compiler that translates WebAssembly (WASM) to Dis, the virtual machine ISA used by the Inferno operating system. Inferno OS was invented in 1995 around the same time as Java. Dis is a register-based VM. Like Java, it is memory-safe, garbage-collected, and features strong type safety. WASM and Java, by contrast, are stack-based.

In the 90s, Lucent implemented a Java-to-Dis compiler. Naively, I assumed that if Java to Dis was possible, there was no foundational engineering reason why WASM to Dis wouldn't work just as well.

I was wrong. There is a massive impedance mismatch between the two ISAs, specifically regarding their memory models.

#### The Core Problem: The Memory Model Mismatch

WASM assumes a flat, untyped linear memory space. Dis operates on a higher-level, typed, and garbage-collected memory model.

To effectively implement WASM's linear memory and `load`/`store` operations within Dis, I had to emulate that linear memory using a massive byte array. Because WASM operates on raw bytes, every single memory access required manually packing and unpacking multibyte types in little-endian order.

Just to implement a basic `load` or `store`, the generated Dis code had to:

* Perform masking and bit-shifting.
* Index into the byte array.
* Move bytes around individually to reconstruct basic int types.

This translation strategy is wildly inefficient. It explodes the instruction count and entirely kills the performance I was aiming for.

#### The "Yes Man" AI

Ignorant of this fundamental architectural flaw, I spent over a month guiding Claude through the entire process of implementing this WASM-to-Dis compiler.

When it implemented the linear memory abstraction, I didn't heavily scrutinize the code. It wasn't until Claude finished the basics of WASI (the system interface) and I tried compiling a simple "Hello World" program that the problem clearly manifested. The generated Dis object file size was 15x the size of the original WASM file.

I am embarrassed. I wish a better engineer had whispered in my ear on day one that I was on a fool's errand.

Claude was not that engineer. Like an overly eager junior developer, it simply went and did exactly what it was told by its foolish master. It wasn't until I explicitly prompted the AI with a specific question—*“What are the performance implications of implementing the WASM memory model in Dis?”*—that it suddenly outlined the exact bottlenecks that doomed the project.

I have since abandoned the project.

#### Takeaways and Final Thoughts

* **AI accelerates execution, not architecture:** LLMs are fantastic at writing the boilerplate and implementing the logic you ask for, but they will happily help you build a bridge out of paper if you tell them to. They accelerate bad ideas just as efficiently as good ones.
* **The danger of compliance:** Current AI coding tools default to compliance rather than critical pushback. A senior engineer would have flagged the memory model impedance mismatch during the design phase. AI won't tap the brakes unless you explicitly ask it to evaluate the road ahead.
* **Domain expertise remains the bottleneck:** Knowing *how* to write code is becoming commoditized; knowing *what* to build (and what is physically or practically feasible to build) is where the actual value lies.
---
