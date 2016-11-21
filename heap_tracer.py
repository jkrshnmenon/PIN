import pin

in_use={}
free_list={}
size=0
f=open("output","w")

def check_write(addr,n_bytes):
	if free_list.has_key(addr):
		print "\n[+][+]Writing data to freed memory at {}".format(hex(addr))
	if in_use.has_key(addr) and in_use[addr] < n_bytes:
		print "\n[+][+]Overflow while writing to {}".format(hex(addr))
	for key in in_use.keys():
		size=in_use[key]
		if addr > key and addr <= key + size:
			if n_bytes > (key+size-addr):
				print "\n[+][+]Overflow while writing to chunk {} at offset {}".format(hex(key),addr-key)
				return 1
	return 0

def fgets(everything):
	target = everything['arg_0']
	n_bytes = everything['arg_1']
	f.write("fgets({},{},stdin)\n".format(hex(target),n_bytes))
	check_write(target,n_bytes)

def read_call(everything):
	target = everything['arg_1']
	n_bytes = everything['arg_2']
	f.write("read(0,{},{})\n".format(hex(target),n_bytes))
	check_write(target,n_bytes)

def strncpy(everything):
	target = everything['arg_0']
	n_bytes = everything['arg_2']
	f.write("strncpy({},{},{})".format(hex(target),hex(everything['arg_1']),n_bytes))
	check_write(target,n_bytes)

def memcpy(everything):
	target = everything['arg_0']
	n_bytes = everything['arg_1']
	f.write("memcpy({},{},{})".format(hex(target),hex(everything['arg_1']),n_bytes))
	check_write(target,n_bytes)

def calloc_before(everything):
	global size
	size = pin.get_pointer(everything['reg_gdi'])

def calloc_after(everything):
	global size
	addr = pin.get_pointer(everything['reg_gax'])
	f.write("calloc({}) returns {}\n".format(size,hex(addr)))
	if in_use.has_key(addr):
		print "\n[+][+]Chunk {} allocated more than once".format(hex(addr))
        if free_list.has_key(addr):
                del free_list[addr]
        in_use[addr]=size

def malloc_before(everything):
	global size
	size=pin.get_pointer(everything['reg_gdi'])

def malloc_after(everything):
	global size
	addr=pin.get_pointer(everything['reg_gax'])
	f.write("malloc({}) returns {}\n".format(size,hex(addr)))
	if in_use.has_key(addr):
		print "\n[+][+]Chunk {} allocated more than once".format(hex(addr))
	if free_list.has_key(addr):
		del free_list[addr]
	in_use[addr]=size

def free(everything):
	rdi=pin.get_pointer(everything['reg_gdi'])
	f.write("free({})\n".format(hex(rdi)))
	if free_list.has_key(rdi):
		print "\n[+][+]Chunk {} freed more than once".format(hex(rdi))
	if in_use.has_key(rdi):
		size=in_use[rdi]
		del in_use[rdi]
		free_list[rdi]=size

def img_handler(img):
	rtn=pin.RTN_FindByName(img,'malloc')
	if pin.RTN_Valid(rtn):
		pin.RTN_Open(rtn)
		pin.RTN_InsertCall(pin.IPOINT_BEFORE,'malloc',rtn,1,malloc_before)
		pin.RTN_InsertCall(pin.IPOINT_AFTER,'malloc',rtn,1,malloc_after)
		pin.RTN_Close(rtn)
	
	rtn = pin.RTN_FindByName(img,'calloc')
	if pin.RTN_Valid(rtn):
		pin.RTN_Open(rtn)
		pin.RTN_InsertCall(pin.IPOINT_BEFORE,'calloc',rtn,1,calloc_before)
		pin.RTN_InsertCall(pin.IPOINT_AFTER,'calloc',rtn,1,calloc_after)
		pin.RTN_Close(rtn)

	rtn = pin.RTN_FindByName(img, "free")
    	if pin.RTN_Valid(rtn):
        	pin.RTN_Open(rtn)
        	pin.RTN_InsertCall(pin.IPOINT_BEFORE, "free", rtn, 1, free)
        	pin.RTN_Close(rtn)
	
	rtn = pin.RTN_FindByName(img,'fgets')
	if pin.RTN_Valid(rtn):
		pin.RTN_Open(rtn)
		pin.RTN_InsertCall(pin.IPOINT_BEFORE,'fgets',rtn,1,fgets)
		pin.RTN_Close(rtn)

	rtn = pin.RTN_FindByName(img,'read')
	if pin.RTN_Valid(rtn):
		pin.RTN_Open(rtn)
		pin.RTN_InsertCall(pin.IPOINT_BEFORE,'read',rtn,1,read_call)
		pin.RTN_Close(rtn)

	rtn = pin.RTN_FindByName(img, 'strncpy')
	if pin.RTN_Valid(rtn):
		pin.RTN_Open(rtn)
		pin.RTN_InsertCall(pin.IPOINT_BEFORE,'strncpy',rtn,2,strncpy)
		pin.RTN_Close(rtn)

	rtn = pin.RTN_FindByName(img, 'memcpy')
        if pin.RTN_Valid(rtn):
                pin.RTN_Open(rtn)
                pin.RTN_InsertCall(pin.IPOINT_BEFORE,'memcpy',rtn,1,memcpy)
                pin.RTN_Close(rtn)

def exiting():
	f.close()
	print "In use chunks"
	if len(in_use.keys()) < 1:
		print "\n[+]Empty list"
	else:
		for keys in in_use.keys():
			print "{} : {}".format(hex(keys),in_use[keys])
	print "Freed chunks"
	if len(free_list.keys()) < 1:
		print "\n[+]Empty list"
	else:
		for keys in free_list.keys():
			print "{} : {}".format(hex(keys),free_list[keys])

if __name__ =="__main__":
	try:
		pin.IMG_AddInstrumentFunction(img_handler)
		pin.AddFiniFunction(exiting)
	except KeyboardInterrupt:
		exiting()
