# [IDA] Source Symbol Smasher
 Seeks strings and succinctly sends symbols to Windows

# How it Do #

1. Open up a symbol library (Linux bin) in IDA
2. Alt + F7
3. Run 'ida_reader.py'
4. Open up a Windows bin
5. Alt + F7
6. Run 'ida_writer.py'
7. ???
8. Profit

In order for this to work, you must have your projects in the same folder. (Or move data.json to your Windows project directory before running ida_writer.py)

Note that signatures are not guaranteed to be correct! It is unpredictable how Linux functionality (mainly inlining) translates to Windows.

You will be prompted to choose to dump all possible signatures into a dump.json, but this will take a long time (took ~40 minutes for me). I've already provided a TF2 dump.