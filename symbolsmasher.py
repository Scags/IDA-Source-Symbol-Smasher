import idc
import idautils
import idaapi
import yaml

from time import time
from sys import version_info

# Are we reading this DB or writing to it. Not to be confused with reading from/writing to the work file
Mode_Invalid = -1
Mode_Write = 0
Mode_Read = 1

def get_action():
	return ida_kernwin.ask_buttons("Reading from", "Writing to", "", 0, "What action are we performing on this database?")

def get_file(action):
	global Mode_Read
	forsaving = 1 if action == Mode_Read else 0
	rw = "w" if action == Mode_Read else "r"
	s = "write to" if action == Mode_Read else "read from"
	fname = "*.yml"
	f = ida_kernwin.ask_file(forsaving, fname, "Choose a file to {}".format(s))

	return open(f, rw) if f else None

# Show how many functions we've found
FOUND_FUNCS = {}
# Don't update asap as that throttles script speed, split sec is fine ig
UPDATE_TIME = time()
def update_window(activity, hidefuncs = False):
	global FOUND_FUNCS, UPDATE_TIME
	if not hidefuncs:
		currtime = time()
		if currtime - UPDATE_TIME > 0.2:
			activity += "\nFunctions found: {}".format(len(FOUND_FUNCS))
			UPDATE_TIME = currtime
		else:
			return

	ida_kernwin.replace_wait_box(activity)

# idautils.Strings() regenerates the string list. This isn't optimal and can take a while,
# so let's use what already exists and make a list from that 
# Same tuple as Strings(): (ea, name)
# NOTE: ONLY SEEMS TO WORK IF YOU HAVE THE STRINGS SUBVIEW OPEN
def get_strs():
	strinfo = idaapi.string_info_t()
	strs = []
	for i in range(idaapi.get_strlist_qty()):
		ida_strlist.get_strlist_item(strinfo, i)
		strs.append((strinfo.ea, idaapi.get_ascii_contents(strinfo.ea, strinfo.length, strinfo.type)))
	return strs

# Format:
# "String Name":
# {
# 	"_ZN8Function5Name",
# 	"_ZN8Function6Name2",
# 	etc...
# }
def build_xref_dict(strings):
	xrefs = {}
	for s in strings:
		xrefs[str(s)] = []
#		if addr:
#			xrefs[str(s)].append = s.ea

		for xref in idautils.XrefsTo(s.ea):
			funcname = ida_funcs.get_func_name(xref.frm)
			if funcname is None:
				continue

			node = xrefs[str(s)]
			node.append(funcname)
			xrefs[str(s)] = node

		# Empty, trash, we don't want it
		if not len(xrefs[str(s)]):
			del xrefs[str(s)]

	return xrefs

# Format:
# "_ZN8Function5Name":
# {
# 	"str1",
# 	"str2",
# 	"str1",
# }
def build_data_dict(strdict):
	funcs = {}
	for s, value in get_bcompat_iter(strdict):
		for funcname in value:
			node = funcs.get(funcname, [])
			node.append(s)
			funcs[funcname] = node
	return funcs

def read_strs(strings, file):
	update_window("Reading strings", True)
	# Build an organized dictionary of the string data we can get
	strdict = build_xref_dict(strings)
	# Then reorient it around functions, then dump it
	funcdict = build_data_dict(strdict)
	update_window("Dumping to file", True)
	# Running the script in write mode will build a similar dict then compare the two through functions
	yaml.safe_dump(funcdict, file, default_flow_style = False, width = 999999, encoding = "utf-8")

def get_func_direct_name(ea):
	funcname = ida_funcs.get_func_name(ea)
	if funcname is None:
		return None

	demangled = idc.demangle_name(funcname, idc.get_inf_attr(idc.INF_SHORT_DN))
	if demangled is None:
		demangled = funcname

	return demangled

#def write_uniques(strings, uniques):
#	global FOUND_FUNCS
#
#	strdict = build_xref_dict(strings, True)
#	update_window("Writing unique instances")
#
#	# Keep track of what we write so A: we don't pointlessly overwrite anything and B: don't duplicate anything
#	inserted = {}
#	for key, value in get_bcompat_iter(strdict):
#		if uniques.get(key):
#			if len(value) == 2:		# ea + 1 xref
#				r = list(idautils.XrefsTo(value["ea"]))
#				func = r[0].frm
#				funcname = ida_funcs.get_func_name(func)
#
#				# No repeats
#				if funcname is None or not funcname.startswith("sub_") or FOUND_FUNCS.has_key(uniques[key]):
#					continue
#
##				del value["ea"]		# Not an ordered dict so we dance around that
#				idc.set_name(ida_funcs.get_func(func).start_ea, uniques[key], idaapi.SN_FORCE)
#
#				FOUND_FUNCS[uniques[key]] = 1
#				update_window("Writing unique instances")
#
#	# Build it again so the renamed funcs are updated
#	return build_xref_dict(strings)

def get_bcompat_iter(d):
	return d.items() if version_info[0] >= 3 else d.iteritems()

def get_bcompat_keys(d):
	return d.keys() if version_info[0] >= 3 else d.iterkeys()

def clean_symboled_funcs(subdict):
	return {key: subdict[key] for key in get_bcompat_keys(subdict) if key.startswith("sub_")}

def write_exact_comp(strings, funcdict):
	global FOUND_FUNCS
	update_window("Writing exact comparisons")
	subdict, eadict = build_dicts(strings)
	count = 0

	for strippedname, strippedlist in get_bcompat_iter(subdict):
		possibilities = []
		strippedlist = sorted(strippedlist)
		for symname, symlist in get_bcompat_iter(funcdict):
			if strippedlist == sorted(symlist):
				possibilities.append(symname)
			else:
				continue

			if len(possibilities) >= 2:
				break

		if len(possibilities) != 1:
			continue

		if not FOUND_FUNCS.has_key(possibilities[0]):
			idc.set_name(eadict[strippedname], possibilities[0], idaapi.SN_FORCE)
			count += 1

			FOUND_FUNCS[possibilities[0]] = 1
			update_window("Writing exact comparisons")

	return count

def write_simple_comp_liw(strings, funcdict):
	global FOUND_FUNCS
	update_window("Writing simple comparisons (symboled in stripped)")
	subdict, eadict = build_dicts(strings)
	count = 0

	for strippedname, strippedlist in get_bcompat_iter(subdict):
		possibilities = []
		for symname, symlist in get_bcompat_iter(funcdict):
			if all(val in strippedlist for val in symlist):
				possibilities.append(symname)
			else:
				continue

			if len(possibilities) >= 2:
				break

		if len(possibilities) != 1:
			continue

		if not FOUND_FUNCS.has_key(possibilities[0]):
			idc.set_name(eadict[strippedname], possibilities[0], idaapi.SN_FORCE)
			count += 1

			FOUND_FUNCS[possibilities[0]] = 1
			update_window("Writing simple comparisons (symboled in stripped)")

	return count

def write_simple_comp_wil(strings, funcdict):
	global FOUND_FUNCS
	update_window("Writing simple comparisons (stripped in symboled)")
	subdict, eadict = build_dicts(strings)
	count = 0

	for strippedname, strippedlist in get_bcompat_iter(subdict):
		possibilities = []
		for symname, symlist in get_bcompat_iter(funcdict):
			if all(val in symlist for val in strippedlist):
				possibilities.append(symname)
			else:
				continue

			if len(possibilities) >= 2:
				break

		if len(possibilities) != 1:
			continue

		if not FOUND_FUNCS.has_key(possibilities[0]):
			idc.set_name(eadict[strippedname], possibilities[0], idaapi.SN_FORCE)
			count += 1

			FOUND_FUNCS[possibilities[0]] = 1
			update_window("Writing simple comparisons (stripped in symboled)")

	return count

def build_dicts(strings):
	strdict = build_xref_dict(strings)

	# Build a funcdict for the stripped bin to compare with the symboled one
	strippeddict = build_data_dict(strdict)
	subdict = clean_symboled_funcs(strippeddict)
	eadict = {ida_funcs.get_func_name(ea): ea for ea in idautils.Functions() if ida_funcs.get_func_name(ea).startswith("sub_")}
	return subdict, eadict


def write_symbols(strings, file):
	update_window("Loading file", True)
	funcdict = yaml.safe_load(file)
	if not funcdict:
		ida_kernwin.warning("Could not load function data from file")
		return

	# Writing uniques is much more liable to produce bad typing
	# Unique, one-off strings seem to be inlined much more often, so it's
	# better to use the simple comparison technique
	# This will reduce the amount of types, but the reduced types
	# wouldve been wrong or duplicated anyways
#	strdict = write_uniques(strings, funcdict["Uniques"])

	# A good test is to just simply compare xrefs
	# If a function references "fizzbuzz" 2 times and "foobar" once and its the only function
	# that does anything like that, chances are that we found something to smash
	write_exact_comp(strings, funcdict)

	# Since a lot of functions that have good strings have inlined strings in them, let's just look for containment
	# If "fizz", "buzz", and "foo" exist in Bar::Foo which has "fizz", "buzz", "foo", and "fizzbuzz" for example
	# Obviously we're only checking for 1 instance
	write_simple_comp_liw(strings, funcdict)
	write_simple_comp_wil(strings, funcdict)

	# TODO IDEAS;
	# -	Dance around some function xrefs. By now, a solid chunk of them should have symboled names (a few thousand at least)
	# 	A unique set of named xrefs could guarantee something
	#	Would need a new section in the data file (to and from)
	# -	Abuse the virtual table
	#	Asherkin can do it, so why can't I? Just need to figure out how to find where it is Windows

def main():
	global Mode_Read, Mode_Write, Mode_Invalid
	action = get_action()
	if action == Mode_Invalid:
		return

	file = get_file(action)
	if file is None:
		ida_kernwin.warning("Invalid file specified!")
		return

#	strings = get_strs()
	strings = list(idautils.Strings())
	if action == Mode_Read:
		read_strs(strings, file)
		print("Done!")
	else:
		global FOUND_FUNCS
		write_symbols(strings, file)
		print("Successfully typed {} functions".format(len(FOUND_FUNCS)))

	ida_kernwin.hide_wait_box()
	file.close()

if __name__ == "__main__":
	main()