import idautils
import ida_xref
import ida_funcs
import idc
import json

def main():
	root = {}

	for s in idautils.Strings():
		root[str(s)] = {}

		for xref in idautils.XrefsTo(s.ea):
			funcname = ida_funcs.get_func_name(xref.frm)
			if (funcname is None):
				continue

			demangled = idc.demangle_name(funcname, idc.get_inf_attr(idc.INF_SHORT_DN))
			if demangled is None:
				demangled = funcname

			root[str(s)][demangled] = funcname

	with open("data.json", "w") as f:
		json.dump(root, f, ensure_ascii = False, indent = 4, separators = (",", ":"))

if __name__ == "__main__":
	main()