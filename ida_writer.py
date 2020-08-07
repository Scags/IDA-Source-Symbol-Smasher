import idautils
import ida_xref
import ida_funcs
import idc
import json
import ida_kernwin
import ida_ua
import ida_fixup
from math import floor

MAX_SIG_LENGTH = 512

def get_dt_size(dtype):
	if dtype == idc.dt_byte:
		return 1
	elif dtype == idc.dt_word:
		return 2
	elif dtype == idc.dt_dword:
		return 4
	elif dtype == idc.dt_float:
		return 4
	elif dtype == idc.dt_double:
		return 8
	else:
		print("Unknown type size (%d)" % dtype)
		return -1

def print_wildcards(count):
	i = 0
	string = ""
	for i in xrange(count):
		string = string + "? "

	return string

def is_good_sig(sig):
	count = 0
	addr = 0
	addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)
	while count <= 2 and addr != idc.BADADDR:
		count = count + 1
		addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)

	return count == 1

def makesig(func):
	sig = ""
	found = 0
	funcstart = func.start_ea
	funcend = func.end_ea
	done = 0
	global MAX_SIG_LENGTH

	addr = funcstart
	while addr != idc.BADADDR:
		info = idautils.DecodeInstruction(addr)		# What is the 7.0 version of this func?
		if info is None:
			return None

		done = 0
		if len(info.ops) == 1:
			if info.ops[0].type == ida_ua.o_near or info.ops[0].type == ida_ua.o_far:
				if hex(idc.get_wide_byte(addr)) == 0x0F: 	# Two-byte instruction
					sig = sig + ("0F %02X " % idc.get_wide_byte(addr + 1)) + print_wildcards(get_dt_size(info.ops[0].dtype))
				else:
					sig = sig + ("%02X " % idc.get_wide_byte(addr)) + print_wildcards(get_dt_size(info.ops[0].dtype))
				done = 1

		if not done: 	# Unknown, just wildcard addresses
			i = 0
			size = idc.get_item_size(addr)
			while 1:	# Screw u python
				loc = addr + i
				if ((idc.get_fixup_target_type(loc) & 0x0F) == ida_fixup.FIXUP_OFF32):
					sig = sig + print_wildcards(4)
					i = i + 3
				else:
					sig = sig + ("%02X " % idc.get_wide_byte(loc))

				i = i + 1

				if i >= size:
					break

		# Escape the evil functions that break everything
		if len(sig) > MAX_SIG_LENGTH:
			return "Signature is too long!"
		# Save milliseconds and only check for good sigs after a fewish bytes
		# Trust me, it matters
		elif len(sig) > 8 and is_good_sig(sig):
			found = 1
			break

		addr = idc.next_head(addr, funcend)

	if found is 0:
		return "Ran out of bytes!"

	l = len(sig) - 1
	smsig = r"\x"
	for i in xrange(l):
		c = sig[i]
		if c == " ":
			smsig = smsig + r"\x"
		elif c == "?":
			smsig = smsig + "2A"
		else:
			smsig = smsig + c

	return smsig

def main():
	f = open("data.json", "r")
	if f is None:
		ida_kerwin.warning("I don't have a data folder! Run ida_reader.py within a linux project first")
		return

	root = json.load(f)
	f.close()

	# The output data, for fun
	dump = {}

	if root is None:
		print("???")
		return

	ida_kernwin.show_wait_box("Iterating Strings")
	for s in idautils.Strings():
		node = root.get(str(s), None)
		if node is None:
			continue

		# If we have 1 xref, it's a given what it is
		# Maybe 1 day I'll make it smarter...
		refs = idautils.XrefsTo(s.ea)
		lrefs = list(refs)
		if len(lrefs) is 1 and len(node.items()) is 1:
			xref = lrefs[0]
			if xref is None:
				continue

			func = ida_funcs.get_func(xref.frm)
			funcname = ida_funcs.get_func_name(xref.frm)

			# Can have into multiple run-ins with the same function, might see a lot of Precache copies
			# Can uncomment that if you want, it's mainly there so u can dump without having to analyze a Windows bin
			# all over again
			if funcname is None:# or not funcname.startswith("sub_"):
				continue

			# Gotta love python 2
			key, mangled = node.items()[0]
			dump[key] = {}
#			dump[key]["sub"] = funcname		# Don't need me do we?
			dump[key]["mangled"] = mangled
			dump[key]["func"] = func		# Nuke me later

			funcstart = func.start_ea
			idc.set_name(funcstart, str(mangled), idaapi.SN_FORCE)
#			print("Setting {} to {}".format(funcname, key))

	if len(dump.items()):
		yn = ida_kernwin.ask_yn(0, "Do you wish to generate signatures from the found functions? (VERY LOOONG) ")
		if yn:
			try:
				sigcount = 0
				count = 0
				numitems = len(dump.items())
				starttime = time.time()
				for key, value in dump.iteritems():
					func = value["func"]
					sig = makesig(func)
					value["signature"] = sig

					sigcount += (0 if "!" in sig else 1)

					count = count + 1
					ida_kernwin.replace_wait_box("Evaluated {} out of {} ({}%)".format(count, numitems, floor(count / float(numitems) * 100.0 * 10.0) / 10.0))
				print("Successfully evaluated {} signatures from {} functions".format(sigcount, len(dump.items())))
			except KeyboardInterrupt:	# Eh, this doesn't do anything. Once you start, there's no going back
				print("Abandoning everything and dumping current data")

		ida_kernwin.hide_wait_box()
		for key, value in dump.iteritems():
			try:
				del value["func"]
			except:
				pass

		with open("dump.json", "w") as f:
			json.dump(dump, f, ensure_ascii = False, indent = 4, separators = (",", ":"))


if __name__ == "__main__":
	main()