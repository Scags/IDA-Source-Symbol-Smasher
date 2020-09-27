# [IDA] Source Symbol Smasher
Seeks strings and succinctly sends symbols to Windows.

# Running the Script #

Running the script presents 2 options: you can read and export data from the current database, or you can import and write data into it.

Requires PyYAML so you'll need to `pip install pyyaml`.

If you're on a symbol library, you should run it in read mode and export it to a file. This file is what is used to import back into a stripped binary.

When on Windows, run the script in write mode and select the file you exported earlier. A solid amount of functions should be typed within a few seconds.

This works well with the [Signature Smasher](https://github.com/Scags/IDA-Scripts#sigsmasherpy). However to save you an hour or so, I publicly host dumps of most Source games [here](https://brewcrew.tf/sigdump/).

# How it Works #

Currently, writing function data opts for 2 methods, both of which revolve around strings.

The first is a unique string comparison. If a string has a unique xref(s) to a single function on Linux, then the same string on Windows should have the same reference and thus the Windows function can be typed. 

The second is unique string xref sequences. In the script this is called "Simple Comparisons". If a symboled `Foo::Bar()` references "FizzBuzz" twice and "Foo_Foo" once and is the only function to have those exact references, then a function on Windows with that exact behavior can be typed. "FizzBuzz" and "Foo_Foo" can be used elsewhere, but only `Foo::Bar()` has that kind of sequence.

#### Planned Typing Methods ####

1. VTable Orientation
	- Finding and reading VTables is simple on Linux, however finding them on Windows is a bit more difficult. It should be straightforward, though.
2. Function XRef Sequencing
	- Similar to the second string method, this can compare xref sequences within functions. This will rely on as many functions as possible being typed, so it should be done last.
	- In addition to it being last, it can be run again and again to find more unique sequences based on previously typed functions.
	- This can be as complex as I want it to be. I can recursively go forwards and backwards through function xrefs and get a solid tree system of each function.

# Caveats #

- Typed functions are not guaranteed to be correct! It is unpredictable how Linux functionality translates over to Windows. Various functions can be inlined and produce incorrect typing. Although this scenario is rare, it can and will happen. In terms of confidence rate, unique comparisons I'll give a 99% and simple comparisons are more of a 95%.