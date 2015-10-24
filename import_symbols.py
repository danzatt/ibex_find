"""
 *  Copyright 2015, danzatt <twitter.com/danzatt>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 """

#quite a mess

rename_count = 0

#=============================== helpers =======================================

def is_sub_start(addr):
	funct = GetFunctionName(addr) #get parent subroutine
	return addr == LocByName(funct)

def append_comment(ea, name):
	if name != "" or name != None:

		if RptCmt(ea) != None and name in RptCmt(ea):
			return

		cmt = ""

		if RptCmt(ea) != None:
			cmt += RptCmt(ea) + "\n"
		cmt += name
		MakeRptCmt(ea, cmt)

def append_function_comment(ea, name):
	if name != "" or name != None:

		if GetFunctionCmt(ea, 0) != None and name in GetFunctionCmt(ea, 0):
			return

		cmt = ""

		if GetFunctionCmt(ea, 0) != None:
			cmt += GetFunctionCmt(ea, 0) + "\n"
		cmt += name
		SetFunctionCmt(ea, cmt, 0)

def rename(ea, name, optional_prefix):
	if LocByName(name) == ea:
		return

	if LocByName(name) != BADADDR: #name is already used
		name = optional_prefix + "_" + name
		if LocByName(name) != BADADDR: #if even prefixed name is taken
			return

	print "%s -> %s" % (hex(ea), name)
	MakeName(ea, name)
	global rename_count
	rename_count += 1

def resolve(pc):
	if Name(pc).startswith("dword_") or Name(pc).startswith("off_"):
		pc = get_32(pc)
	return pc

def rename_complicated(addr, name, optional_prefix = "", cmt = ""):
	if Name(addr) == name:
		return
	elif (is_sub_start(addr)):
		if GetFunctionName(addr).startswith("sub_"):
			rename(addr, name, optional_prefix)
			append_function_comment(addr, cmt)
		else:
			append_function_comment(addr, name)
			append_function_comment(addr, cmt)
	elif (Name(addr) == "" or Name(addr).startswith("loc_") or Name(addr).startswith("dword_")):
		rename(addr, name, optional_prefix)
		append_comment(addr, cmt)
	else:
		print "%s already has name \"%s\" (should be changed to %s)" % (hex(addr), Name(addr), name)
		append_comment(addr, name)
		append_comment(addr, cmt)

def get_32(addr):

	if addr is BADADDR or type(addr) is not int:
		print "get_32: BADADDR"
		return BADADDR

	ret = 0
	ret |= Byte(addr)
	ret |= Byte(addr+1) << 8
	ret |= Byte(addr+2) << 8*2
	ret |= Byte(addr+3) << 8*3

	return ret

def xref_cnt(ea):
	ret = 0
	for xref in XrefsTo(ea, 0):
		ret += 1
	return ret

def is_valid_reg(reg, getnum = False):
	if reg in ["SP", "LR", "PC"]:
		if getnum:
			return -1
		return True

	if not reg.startswith("R"):
		return False
	if len(reg) > 3:
		return False
	num = reg[1:]
	if not num.isdigit():
		return False
	num = int(num)
	if not num in range(13): #12+ have special names in IDA
		return False
	if len(reg) == 3 and reg[1] == "0":
		return False
	if getnum:
		return num
	return True

#"emulation", not even close but works
def whats_in_reg(pc, reg):
	startaddr = pc
	#print "startaddr", hex(startaddr)
	has_xrefs = xref_cnt(pc) > 1
	insn = DecodeInstruction(pc)

	if not is_valid_reg(reg):
		print "unsupported reg"
		return []

	for idx in xrange(32):
		#print "pc=", hex(pc)
		if insn == None:
			return []

		mnem = GetMnem(pc)

		#print hex(pc), mnem

		if not has_xrefs:

			if mnem in ["LDR", "LDR.W"] and GetOpnd(pc, 0) == reg:
				val = GetOperandValue(pc, 1)
				return [val] if val is not None else []

			elif mnem in ["MOV", "MOVS"] and GetOpnd(pc, 0) == reg:
				src = GetOpnd(pc, 1)
				if is_valid_reg(src):
					reg = src
				else:
					if src.startswith("#"):
						src = src[1:]
						if src.startswith("0x"):
							src = src[2:]
						if not src.isdigit():
							return [BADADDR]
						src = int(src, 16)

					if type(src) != int:
						return [BADADDR]
					return [src]

			elif mnem == "BL" and reg:
				if idx == 0:
					insn, has_xrefs = DecodePrecedingInstruction(pc)
					if insn is None:
						return []
					pc = insn.ip
					continue #if it's our first insn we determine the reg value before BL
				if is_valid_reg(reg, True) in range(0,3) or reg == "LR": #R0-R3 may be affected by BL
					#print hex(pc), "cannot go back due to BL. startaddr =", hex(startaddr)
					return []

		else:
			#print hex(pc),"xrefs=", xref_cnt(pc)
			ret = []
			for xref in XrefsTo(pc, 0):
				res = whats_in_reg(xref.frm, reg)
				if res is not None:
					ret.extend(res)
			return ret

		insn, has_xrefs = DecodePrecedingInstruction(pc)
		if insn is None:
			return []
		pc = insn.ip
	return []

#========================== rename from file ===================================

path = AskFile(0, "*", "Choose file exported by ibex_find")

cmt = ""

print path
if path != None:
	lines = [line.rstrip('\n') for line in open(path)]

	for line in lines:
		a =  line.split(";")

		if len(a) != 2:
			continue

		if a[0] == "setcmt":
			cmt = a[1]
			print cmt
			continue

		(name, addr) = a

		#print "name %s addr %s" % (name, addr)

		addr = int(addr, 16)

		if addr == 0:
			continue

		is_thumb = GetReg(addr, "T")
		insn_size = 2 if is_thumb else 4
		addr -= addr % insn_size #align

		#change "symbol found by ibex" into just "ibex"
		optional_prefix = cmt.split(" ")[-1]

		rename_complicated(addr, name, optional_prefix, cmt)

#========================= rename exception vector =============================

pc = Segments().next() #Segments() returns generator, we grab the 1st element
vector_table = [
	{
		"name": "Reset",
		"comment": "Processor is reset or started"
	},
	{
		"name": "Undef",
		"comment": "An undefined instruction is encountered. Usually this is from an erroneous branch or corruption of code, but can also be used for emulating instruction sets on processors which do not support them."
	},
	{
		"name": "Swi",
		"comment": "A \"Software Interrupt\" is generated, by the SWI/SVC command. This is most often used to perform system calls: Code in user mode invokes the instruction, and the processor shifts to supervisor mode, to a predefined system call handler"
	},
	{
		"name": "PrefAbt",
		"comment": "Instruction Prefetch abort"
	},
	{
		"name": "DataAbt",
		"comment": "Data Abort"
	},
	{
		"name": "AddrExc",
		"comment": "An Address Exception (invalid address) is encountered"
	},
	{
		"name": "IRQ",
		"comment": "An Interrupt Request is singaled: The CPU stops everything and transfers control to the interrupt handler."
	},
	{
		"name": "FIQ",
		"comment": "A Fast Interrupt Request is singaled: The CPU stops everything and transfers control to the interrupt handler. Other interrupts are blocked during the time."
	}
]

reset = BADADDR
im_not_that_dumb = True

for a in vector_table:
	#print hex(pc), a["name"], a["comment"]
	handler_addr = 0
	if GetMnem(pc) == "LDR" and GetOpnd(pc, 0) == "PC":
		off = GetOperandValue(pc, 1) #this actually isn't offset because IDA has resolved it for us

		#string_addr = GetManyBytes(off, 4)
		#print string_addr.encode("hex")

		handler_addr = get_32(off)

	if GetMnem(pc) == "B":
		handler_addr = GetOperandValue(pc, 0)

	#print hex(handler_addr)
	rename_complicated(handler_addr, a["name"] + "_handler", cmt = "" if im_not_that_dumb else a["comment"])

	if a["name"] == "Reset":
		reset = handler_addr # pedanticness, always is at BASE + 0x40

	pc += DecodeInstruction(pc).size

#======================= add mode names to comment =============================

"""
User	All	0b10000
FIQ - Fast Interrupt Request	All	0b10001
IRQ - Interrupt Request	All	0b10010
Supervisor	All	0b10011
Abort	All	0b10111
Undefined	All	0b11011
System	ARMv4 and above	0b11111
Monitor	Security Extensions only	0b10110
"""

modes = {
	0b10000: "User",
	0b10001: "FIQ",
	0b10010: "IRQ",
	0b10011: "Supervisor",
	0b10111: "Abort",
	0b11011: "Undefined",
	0b11111: "System",
	0b10110: "Monitor"
}

insns_eaten = 0
pc = reset

while insns_eaten < 60:
	#print hex(pc), "eating,",GetMnem(pc)

	size = DecodeInstruction(pc).size

	if GetMnem(pc) == "ORR" and GetMnem(pc + size) == "MSR":
		mode = GetOperandValue(pc, 2)
		#print hex(mode)
		if mode != -1:
			append_comment(pc, modes[mode])

	pc += size
	insns_eaten += 1

"""
iBoot contains calls to panic with R0 pointing to the function name. We find
"panic" function, follow every xref and go back at most 15 instructions while
looking for "LDR R0, xxx". Due to ARM xxx is offset to nearby 32bit address.
That adress is the actual absolute address to the string. We read the string
(which is the function name) and rename the parent subroutine (if any)
or the location of panic call accordingly.
"""

print "===============renaming panics================"

panic = LocByName("panic")
if panic != BADADDR:
	for xref in XrefsTo(panic, 0):

		#print xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to)

		pc = xref.frm
		function_name = None
		pc -= DecodePreviousInstruction(pc).size
		#print "calling whats_in_reg", hex(pc)
		r1 = whats_in_reg(pc, "R0")

		for val in r1:
			if val == BADADDR:
				continue

			#print "val = ", hex(val), " => ", hex(get_32(val))
			name = GetString(get_32(val))

			if name is not None:
				#print hex(pc), "->", name

				funct = GetFunctionName(pc)

				if funct != "": # if location belongs to subroutine
					rename_complicated(LocByName(funct), name, cmt="discovered by looking for [XREF]")
				else:
					rename_complicated(pc, name, cmt="discovered by looking for [XREF]")


		"""
		for _ in xrange(15):
			pc -= DecodePreviousInstruction(pc).size
			if GetMnem(pc) == "LDR" and GetOpnd(pc, 0) == "R0":
				off = GetOperandValue(pc, 1) #this actually isn't offset because IDA has resolved it for us

				#string_addr = GetManyBytes(off, 4)
				#print string_addr.encode("hex")

				string_addr = 0

				string_addr = get_32(off)

				#print hex(string_addr)
				function_name = GetString(string_addr)

				#if LocByName(function_name) == BADADDR:

				funct = GetFunctionName(xref.frm)

				if funct != "": # if location belongs to subroutine
					rename_complicated(LocByName(funct), function_name)
				else:
					rename_complicated(xref.frm, function_name)

				break

		if function_name != None:
			#print "resolved name", function_name
			pass
		else:
			print "couldn't resolve name at ", xref.frm
		"""
else:
	print "couldn't find panic when you find it re-run this plugin"


"""
Calls to task_create pass the task name in R0. We do the very same thing as above.
"""
print "================renaming tasks================"

task_create = LocByName("task_create")
if task_create != BADADDR:
	for xref in XrefsTo(task_create, 0):

		pc = xref.frm

		task_handler 	= resolve(whats_in_reg(pc, "R1")[0])
		task_name 		= resolve(whats_in_reg(pc, "R0")[0])
		task_name = GetString(task_name)

		#print hex(task_handler), "->", GetString(task_name), hex(task_name)

		funct = GetFunctionName(task_handler)

		if funct != "": # if location belongs to subroutine
			rename_complicated(LocByName(funct), "task_" + task_name.replace(" ", "_").replace("-", "_"), cmt=task_name)
		else:
			rename_complicated(task_handler, "task_" + task_name.replace(" ", "_").replace("-", "_"), cmt=task_name)


"""
		function_name = None

		for _ in xrange(15):
			pc -= DecodePreviousInstruction(pc).size
			if GetMnem(pc) == "LDR" and GetOpnd(pc, 0) == "R0":
				off = GetOperandValue(pc, 1) #this actually isn't offset because IDA has resolved it for us

				#string_addr = GetManyBytes(off, 4)
				#print string_addr.encode("hex")

				string_addr = 0

				string_addr = get_32(off)

				#print hex(string_addr)
				function_name = GetString(string_addr)

				#if LocByName(function_name) == BADADDR:

				funct = GetFunctionName(xref.frm)

				if funct != "": # if location belongs to subroutine
					rename_complicated(LocByName(funct), function_name.replace(" ", "_") + "_task", cmt=function_name)
				else:
					rename_complicated(xref.frm, function_name.replace(" ", "_") + "_task", cmt=function_name)

				break

		if function_name != None:
			#print "resolved name", function_name
			pass
		else:
			print "couldn't resolve name at ", xref.frm
"""
print "================[NAND] strings================"

base = Segments().next() #Segments() returns generator, we grab the 1st element
#base = BADADDR # <---------------------- NOTICE ME

nand_panic = BADADDR

for string in Strings():
	if str(string).startswith("[NAND] "):
		absolute_addr = FindBinary(base, SEARCH_DOWN, hex(string.ea)[2:])
		#print "absolute_addr=", hex(absolute_addr)

		for a in XrefsTo(absolute_addr, 0):
			#print hex(a.frm), "\t", GetDisasm(a.frm)

			pc = a.frm

			#look for BL downwards
			while GetMnem(pc) != "BL":
				if GetMnem(pc) == "B":
					pc = GetOperandValue(pc, 0) #follow unconditional branch
					continue
				#print "pc=", hex(pc)
				pc += DecodeInstruction(pc).size

			if GetOperandValue(pc, 0) != nand_panic and nand_panic != BADADDR:
				print "[W]: Different nand_panic's"

			nand_panic = GetOperandValue(pc, 0)

			r1 = whats_in_reg(pc, "R1")

			for val in r1:
				if val == BADADDR:
					continue

				#print "val = ", hex(val), " => ", hex(get_32(val))
				name = GetString(get_32(val))

				if name is not None:
					# print hex(pc), "->", name

					funct = GetFunctionName(pc)

					if funct != "": # if location belongs to subroutine
						rename_complicated(LocByName(funct), name, cmt="discovered by looking for [NAND]")
					else:
						rename_complicated(pc, name, cmt="discovered by looking for [NAND]")

print "=====================XREF====================="

rename_complicated(nand_panic, "nand_panic")

for a in XrefsTo(nand_panic):
	pc = a.frm

	#look for BL downwards
	while GetMnem(pc) != "BL":
		if GetMnem(pc) == "B":
			pc = GetOperandValue(pc, 0) #follow unconditional branch
			continue
		#print "pc=", hex(pc)
		pc += DecodeInstruction(pc).size

	r1 = whats_in_reg(pc, "R1")

	for val in r1:
		if val == BADADDR:
			continue

		#print "val = ", hex(val), " => ", hex(get_32(val))
		name = GetString(get_32(val))

		if name is not None:
			#print hex(pc), "->", name

			funct = GetFunctionName(pc)

			if funct != "": # if location belongs to subroutine
				rename_complicated(LocByName(funct), name, cmt="discovered by looking for [XREF]")
			else:
				rename_complicated(pc, name, cmt="discovered by looking for [XREF]")
"""
for string in Strings():
	absolute_addr = FindBinary(base, SEARCH_DOWN, hex(string.ea)[2:])
	#print "absolute_addr=", hex(absolute_addr)

	for a in XrefsTo(absolute_addr, 0):
		print string, "used at", hex(a.frm)
"""
print "Renamed total of %i functions for you. Have fun :)" % rename_count



"""
#TODO: complete this

#terribly broken
def whats_in_regs(pc, regs, lvl=0, alias = {}):
	lvl+=1
	orig_regs = regs

	print "looking for", regs

	ret = {}
	#alias = {}

	def add_alias(alias, orig, aliases):
		if alias in aliases:
			aliases[alias].extend([orig])
		else:
			aliases[alias] = [orig]

	has_xrefs = xref_cnt(pc) > 1
	insn = DecodeInstruction(pc)

	for reg in regs:
		if not is_valid_reg(reg):
			print "unsupported reg", reg
			return [BADADDR]

	for idx in xrange(256):

		if len(ret) >= len(orig_regs):
			return [ret]

		if insn == None:
			return [ret]

		mnem = GetMnem(pc)

		#print hex(pc), mnem

		if not has_xrefs:

			if mnem in ["LDR", "LDR.W"]:

				dst = GetOpnd(pc, 0)
				val = GetOperandValue(pc, 1)

				#LDR R6, [SP,#0xXX+var_XX]
				if GetOpnd(pc, 1).startswith("["):
					val = BADADDR

				if dst in regs:
					ret[dst] = val
					regs.remove(dst)

				if dst in alias:
					original_names = alias[dst]
					for name in original_names:
						print "alias=", alias
						print "name", name
						print "original_names", original_names
						print "alias[dst]=", alias[dst]
						print "pc=", hex(pc)
						print lvl*"\t", "ret=", ret
						print lvl*"\t", "ret[", name,"] =", val
						ret[name] = val
					alias.remove(dst)

			elif mnem in ["MOV", "MOVS"]:
				src = GetOpnd(pc, 1)
				dst = GetOpnd(pc, 0)

				if is_valid_reg(dst):
					if dst in regs:
						add_alias(dst, regs, alias)
						regs.remove(dst)

					if dst in alias:
						if src in alias:
							alias[src].extend(alias[dst])
						else:
							alias[src] = alias[dst]
						del alias[dst]

			elif mnem == "BL" and reg:
				if idx == 0:
					pc -= insn.size
					continue #if it's our first insn we determine the reg value before BL

				if is_valid_reg(reg, True) in range(0,3) or reg == "LR": #R0-R3 may be affected by BL
					print hex(pc), "cannot go back due to BL"
					return [BADADDR]

		else:

			print hex(pc),"xrefs=", xref_cnt(pc)

			missing_regs = []

			for reg in orig_regs:
				if reg not in ret:
					missing_regs.append(reg)
			print lvl*"\t", "missing_regs", missing_regs


			for xref in XrefsTo(pc, 0):
				aa = whats_in_regs(xref.frm, missing_regs, lvl=lvl)
				print lvl*"\t", "recursion returned",

				#ret.extend(whats_in_reg(xref.frm, reg))
			return ret

		pc -= insn.size
		insn, has_xrefs = DecodePrecedingInstruction(pc)

print whats_in_regs(here(), AskStr("R0", "What regs ?").split(" "))
"""
