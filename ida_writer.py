import idautils
import ida_xref
import ida_funcs
import idc
import json

def main():
	f = open("data.json", "r")
	if f is None:
		print("I don't have a data folder! Run ida_reader.py within a linux project first")
		return

	root = json.load(f)
	f.close()

	# The output data, for fun
	dump = {}

	if root is None:
		print("???")
		return

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

			if funcname is None or not funcname.startswith("sub_"):
				continue

			# Gotta love python 2
			key, mangled = node.items()[0]
			dump[key] = funcname

			funcstart = func.start_ea
			idc.set_name(funcstart, str(mangled), idaapi.SN_FORCE)
#			print("Setting {} to {}".format(funcname, key))

	if len(dump.items()):
		with open("dump.json", "w") as f:
			json.dump(dump, f, ensure_ascii = False, indent = 4, separators = (",", ":"))


if __name__ == "__main__":
	main()