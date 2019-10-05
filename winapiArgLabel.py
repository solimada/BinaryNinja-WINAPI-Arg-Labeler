#WINAPI argument Labeling

from binaryninja.log import log_error
from binaryninja.log import log_debug
import xml.etree.ElementTree as ET
import re, binaryninja, os

def lookupAPI(apiname):
	#functions
	ftree = ET.parse(os.getenv('APPDATA')+'\Binary Ninja\plugins\winapidb_func.xml') #range 0 to 6519
	froot = ftree.getroot()
	#parameters
	ptree = ET.parse(os.getenv('APPDATA')+'\Binary Ninja\plugins\winapidb_param.xml') #range 0 to 27312
	proot = ptree.getroot()
#	log_error(apiname)
	keyForParams=''
	for i in range(0,6519):
		if apiname[0].lower() in froot[i][0].text.lower():
			keyForParams = froot[i][1].text
			output = 'found function at' + 'createmutex' + ' in ' + str(i) + ':0'
#			print output
#			log_error(output)
			break
		if i == 6518:
			log_error('Could not locate call')
#	output = 'found argument '
	params = []
	for j in range(0,27312):
		if str(keyForParams) == proot[j][0].text:
			params.append(proot[j][1].text)
#			log_error(params)
	return params

def labelArgs(bv, callAddr, argList):
	
	#returns array of block ranges that contains call in format [<block: x86_64@0x#########-0x#########>]
	basicBlocksContainingCall = bv.get_basic_blocks_at(callAddr)
	
	#find block that callAddr is within range of
	for i in range(0,len(basicBlocksContainingCall)):
		basicBlockRange = re.findall(r'(0x[0-9a-fA-F]+)(?:--)?',str(basicBlocksContainingCall[i]))
		blockStartAddress = int(basicBlockRange[0],16)
		blockEndAddress = int(basicBlockRange[1],16)
		if (blockStartAddress < callAddr and callAddr < blockEndAddress):
			#currentBasicBlockDisassemblyLength = basicBlocksContainingCall[i].length
			currentBasicBlockDisassembly = basicBlocksContainingCall[i].get_disassembly_text()#returns the BasicBlock as array
			break
	
	#find index of winapicall in currentBasicBlockDisassembly
	for i in range(0,len(currentBasicBlockDisassembly)):
		if (currentBasicBlockDisassembly[i].address == callAddr):
			indexOfCall = i
			break
	
	#Get current_function for comments
	for i in range(0,len(bv.functions)):
		if(i == len(bv.functions)-1) and (int(bv.functions[i].start,16) <= callAddr):
			current_function = bv.functions[i]
			break
		if (bv.functions[i].start <= callAddr) and (callAddr <= bv.functions[i+1].start):
			current_function = bv.functions[i]
			break
	
	argCounter = 0
	#travel up assembly and edit args
	for i in range(indexOfCall-1,-1,-1):
		instruction = currentBasicBlockDisassembly[i].tokens
		currentAddr = currentBasicBlockDisassembly[i].address
		opCode = str(instruction[0])
		opArg = str(instruction[2])
		#first argument is rcx ecx cx cl
		if ((argCounter == 0) and (opArg == 'rcx' or opArg == 'ecx' or opArg == 'cx' or opArg == 'cl')):
			current_function.set_comment(currentAddr,argList[0])
			argCounter = argCounter + 1
		#second argument is rdx edx dx dl
		elif ((argCounter == 1) and (opArg == 'rdx' or opArg == 'edx' or opArg == 'dx' or opArg == 'dl')):
			current_function.set_comment(currentAddr,argList[1])
			argCounter = argCounter + 1
		#third argument is r8 r8d r8w r8b
		elif ((argCounter == 2) and (opArg == 'r8' or opArg == 'r8d' or opArg == 'r8w' or opArg == 'r8b')):
			current_function.set_comment(currentAddr,argList[2])
			argCounter = argCounter + 1
		#fouth argument is r9 r9d r9w r9b
		elif ((argCounter == 3) and (opArg == 'r9' or opArg == 'r9d' or opArg == 'r9w' or opArg == 'r9b')):
			current_function.set_comment(currentAddr,argList[3])
			argCounter = argCounter + 1
		#rest of arguments are on stack rsp+0x###
		elif (argCounter > 3) and ('mov' in opCode) and (opArg == 'qword ' or opArg == 'dword '):
			current_function.set_comment(currentAddr,argList[argCounter])
			argCounter = argCounter + 1
		
		if argCounter == len(argList):
			break
	
	

def winapiArgLabel64(bv, addr, length):
	pattern = r'(0x[0-9a-fA-F]+)(?:--)?'
	search = re.findall(pattern, bv.get_disassembly(addr)) #extract second address
	if search:
		symbol = bv.get_symbol_at(int(search[0], 16))
		pattern = r'!(\w+)@'
		name = re.findall(pattern, symbol.name) #finds name of winapi call
		parametersList = lookupAPI(name)
	
	if not parametersList:
		log_error('No arguments for API call')
	else:
#		log_error(parametersList)
		labelArgs(bv, addr, parametersList)
		
#print output
binaryninja.PluginCommand.register_for_range("Label WINAPI Arguments", "Label WINAPI Arguments", winapiArgLabel64)