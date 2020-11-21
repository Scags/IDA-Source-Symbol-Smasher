# [IDA] Source Symbol Smasher
Seeks strings and succinctly sends symbols to Windows.

# Running the Script #

Running the script presents 2 options: you can read and export data from the current database, or you can import and write data into it.

~~Requires PyYAML so you'll need to pip install pyyaml~~

No longer uses PyYAML. It instead uses JSON for importing/exporting.

If you're on a symbol library, you should run it in read mode and export it to a file. This file is what is used to import back into a stripped binary.

When on Windows, run the script in write mode and select the file you exported earlier. A solid amount of functions should be typed within a few seconds.

This works well with the [Signature Smasher](https://github.com/Scags/IDA-Scripts#sigsmasherpy). However to save you an hour or so, I publicly host dumps of most Source games [here](https://brewcrew.tf/sigdump/).

# How it Works #

Currently, writing function data opts for simple comparison methods that revolve around strings.

The first is exact string comparison. If a function has a unique set of strings within it's scope on Linux, then if a function on Windows has the same set of strings, then the unnamed Windows function should be the same as the Linux one.

The second is unique string xref sequences. In the script this is called "Simple Comparisons". This method checks both directions since inlining can change across both Windows and Linux. A function has a set of strings, and another function can have a subset of those strings. If that subset function is the only function that has a subset of strings contained within the first function, then those functions should be the same. 

#### Planned Typing Methods ####

1. ~~VTable Orientation~~ [Done with this script](https://github.com/Scags/IDA-Scripts#vtable_iopy)
	- ~~Finding and reading VTables is simple on Linux, however finding them on Windows is a bit more difficult. It should be straightforward, though.~~ 
2. Function XRef Sequencing
	- Similar to the second string method, this can compare xref sequences within functions. This will rely on as many functions as possible being typed, so it should be done last.
	- In addition to it being last, it can be run again and again to find more unique sequences based on previously typed functions.
	- This can be as complex as I want it to be. I can recursively go forwards and backwards through function xrefs and get a solid tree system of each function.

# Caveats #

- Typed functions are not guaranteed to be correct! It is unpredictable how Linux functionality translates over to Windows and vice versa. Various functions can be inlined and produce incorrect typing. Although this is uncommon, it can and will happen.
