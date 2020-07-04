import re

# tup[0] is type of event	
# constants used to identify log message types
# Errors have a value >= 100

operationCreate = 0
operationUpdate = 1
operationDelete = 2

operationCreateFail = 100
operationUpdateFail = 101
operationDeleteFail = 102 

handoverMacNameOperation = 0
oltMacNameOperation = 3
vplsOperation = 6
bSiteOperation = 9
meshSdpBindingOperation = 12
staticMacOperation = 15

codeHandoverMacNameCreate = handoverMacNameOperation + operationCreate
codeHandoverMacNameUpdate = handoverMacNameOperation + operationUpdate
codeHandoverMacNameDelete = handoverMacNameOperation + operationDelete
codeHandoverMacNameCreateFail = handoverMacNameOperation + operationCreateFail
codeHandoverMacNameUpdateFail = handoverMacNameOperation + operationUpdateFail
codeHandoverMacNameDeleteFail = handoverMacNameOperation + operationDeleteFail

codeOltMacNameCreate = oltMacNameOperation + operationCreate
codeOltMacNameUpdate = oltMacNameOperation + operationUpdate
codeOltMacNameDelete = oltMacNameOperation + operationDelete
codeOltMacNameCreateFail = oltMacNameOperation + operationCreateFail
codeOltMacNameUpdateFail = oltMacNameOperation + operationUpdateFail
codeOltMacNameDeleteFail = oltMacNameOperation + operationDeleteFail

codeVplsCreate = vplsOperation + operationCreate
codeVplsDelete = vplsOperation + operationDelete
codeVplsCreateFail = vplsOperation + operationCreateFail
codeVplsDeleteFail = vplsOperation + operationDeleteFail

codeBSiteCreate = bSiteOperation + operationCreate
codeBSiteDelete = bSiteOperation + operationDelete
codeBSiteCreateFail = bSiteOperation + operationCreateFail
codeBSiteDeleteFail = bSiteOperation + operationDeleteFail

codeMeshSdpBindingCreate = meshSdpBindingOperation + operationCreate
codeMeshSdpBindingDelete = meshSdpBindingOperation + operationDelete
codeMeshSdpBindingCreateFail = meshSdpBindingOperation + operationCreateFail
codeMeshSdpBindingDeleteFail = meshSdpBindingOperation + operationDeleteFail

codeStaticMacCreate = staticMacOperation + operationCreate
codeStaticMacDelete = staticMacOperation + operationDelete
codeStaticMacCreateFail = staticMacOperation + operationCreateFail
codeStaticMacDeleteFail = staticMacOperation + operationDeleteFail

def processLog(logIn):
	
	# r=re.compile(r'\[ok]\s+(?:(\S+) : (?:created vpls\.BSite (\S+)|created svt\.meshSdpBinding from (\S+) to (\S+)|created static MAC ([-0-9A-F]+) to (\S+) \(([0-9\.]+)\))|create MacName (\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\))')
	# r=re.compile(r'\[ok]\s+(?:(\S+) : (?:created vpls\.BSite (\S+)|created svt\.meshSdpBinding from (\S+) to (\S+)|created static MAC ([-0-9A-F]+) to (\S+) \(([0-9\.]+)\))|create MacName (\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\)|deleted handover mac name (\S+) from (\S+) \(([0-9\.]+)\)|(\S+) : (?:deleted vpls\.BSite (\S+))|(\S+) : attempt to remove unneeded svt\.MeshSdpBinding from (\S+) to (\S+) already deleted|deleted OLT mac name (\S+) from (\S+) \(([0-9\.]+)\)|(\S+) : removed unneeded vpls\.Vpls for OLT)')	
		
	r=re.compile(r'\[(\S+)]  .*(?:mac ?name (?:(\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\)|(\S+) from (\S+) \(([0-9\.]+)\))|vpls.Vpls.* for olt|vpls.Bsite.* (\S+)|meshSdpBinding from (\S+) to (\S+).*|created static MAC (\S+) on (\S+) \(([0-9\.]+)\) to (\S+) \(([0-9\.]+)\))', re.IGNORECASE)

	# 0 = ok or not ok
	# 1 = added macname
	# 2 = added macname address
	# 3 = added switch that macname added on
	# 4 = added to switch address
	# 5 = deleted macname
	# 6 = switch deleted from
	# 7 = deleted from switch address
	# 8 = add/remove bsite location
	# 9 = add/remove meshSdpBinding from
	# 10 = switch mesh SDP add/removed from/to
	# 11 = add static mac address
	# 12 = switch static mac added to
	# 13 = switch static mac added to address
	# 14 = static mac going to
	# 15 = static mac going to address
	
	logsOut = []
	
	log = logIn
	logEmpty = False	
	count = 0
#####################################################################################################################
	# olt adding searching
	
	# look for OLTS added:
	oltAddNames = []
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeVplsCreate or tup[0] == codeVplsCreateFail:
					oltAddNames.append(olt)
	
	# cycle through olts added
	for oltName in oltAddNames:
		pdict = log.get(oltName)
		highestCount = 0
		oltAddedTo = []
		sdpSwitches = []
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
					groups = r.match(tup[1]).groups()
					sdpSwitches.append(groups[9])
					sdpSwitches.append(groups[10])
		
		for name in sdpSwitches:
			if sdpSwitches.count(name) > highestCount:
				highestCount = sdpSwitches.count(name)
		
		
		for name in sdpSwitches:
			if sdpSwitches.count(name) == highestCount and name not in oltAddedTo:
				oltAddedTo.append(name)
		
		for name in oltAddedTo:
			logsOut.append(["addOLT", str(oltName + " on " + name)])
		
		# ensure everything is correct in the add olt log, no extra lines, errors
		# get list of switches BSite made to and store for getting static mac addresses
		bSiteSwitches = []
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
					groups = r.match(tup[1]).groups()
					if groups[8] not in oltAddedTo:
						bSiteSwitches.append(groups[8])
		
		# remove self from sdpBinding switches
		sdpSwitches = list(set(sdpSwitches)) # remove dupes
		for name in oltAddedTo:
			sdpSwitches.remove(name)
		
		# check sdpSwitches and bSite switches match
		if set(sdpSwitches) != set(bSiteSwitches):
			print 'invalid: sdp switches and bsite switches dont match'
			if set(sdpSwitches) <= set(bSiteSwitches):
				print 'extra bSite add'
				# find line with extra add as a log
			elif set(bSiteSwitches) <= set(sdpSwitches):
				print 'extra sdp add'
				# find line with extra add as a log
			else:
				print 'idk man'
		
		# check static mac match sdp bindings and bsites
		staticMacsMade = []
		oltAddedToAddress = ''
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				groups = r.match(tup[1]).groups()
				if groups[0] == 'NOK':
					logsOut.append(['error', tup[1]])
				if tup[0] == codeStaticMacCreate or tup[0] == codeStaticMacCreateFail:
					# print groups[4], groups[6], oltAddedTo
					if groups[12] in oltAddedTo and groups[14] in sdpSwitches and groups[14] in bSiteSwitches:
						# valid
						staticMacsMade.append(groups[11])
						oltAddedToAddress = groups[12]
						logList.pop(i)
						i -= 1
						#print 'valid static mac create'
					elif groups[14] in oltAddedTo and groups[12] in sdpSwitches and groups[12] in bSiteSwitches:
						# valid
						logList.pop(i)
						i -= 1
						#print 'valid static mac create'
						
					else:
						# invalid
						print 'invalid static mac create'
				elif tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
					# print groups[4], groups[6], oltAddedTo
					if groups[8] in sdpSwitches or groups[8] in oltAddedTo:
						# valid
						logList.pop(i)
						i -= 1
						#print 'valid bsite create'
					else:
						# invalid
						print 'invalid bsite create'
				elif tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
					if groups[9] in oltAddedTo and groups[10] in sdpSwitches and groups[10] in bSiteSwitches:
						# valid
						logList.pop(i)
						i -= 1
						#print 'valid sdp binding create'
					elif groups[10] in oltAddedTo and groups[9] in sdpSwitches and groups[9] in bSiteSwitches:
						# valid
						logList.pop(i)
						i -= 1
						#print 'valid sdp binding create'
					else:
						# invalid
						print 'invalid sdp binding create'
				elif tup[0] == codeOltMacNameCreate or tup[0] == codeOltMacNameCreate:
					if groups[3] in sdpSwitches and groups[3] in bSiteSwitches:
						logList.pop(i)
						i -= 1
						#print 'valid macname create' 
					else:
						print 'invalid macname create' 
				elif tup[0] == codeVplsCreate:
					logList.pop(i)
					i -= 1
				i += 1
				
						
		#print staticMacsMade
		
		pdict = log.get('All')
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				groups = r.match(tup[1]).groups()
				if groups[0] == 'NOK':
					logsOut.append(['error', tup[1]])
				if groups[2] in staticMacsMade and groups[3] in oltAddedTo:
					logList.pop(i)
					i -= 1
				i += 1
		
	#print log

	
#####################################################################################################################
	# Handover adding searching:
	handoversMade = []
	# check 'All' for new handovers made
	pdict = log.get('All')
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == codeHandoverMacNameCreate or tup[0] == codeHandoverMacNameCreateFail:
				groups = r.match(tup[1]).groups()
				handoversMade.append(groups[1])
	
	handoversMade = list(set(handoversMade))
	#print handoversMade
	for handover in handoversMade:
		#print handover
		handoverAddress = ''
		switchesMacMadeOn = []
		pdict = log.get('All')
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				if tup[0] == codeHandoverMacNameCreate or tup[0] == codeHandoverMacNameCreate:
					groups = r.match(tup[1]).groups()
					#print groups[8], handover
					if groups[1] == handover:
						handoverAddress = groups[2]
						switchesMacMadeOn.append(groups[3])
						logList.pop(i)
						i -= 1
						#print 'remove', tup[1]
				i += 1
		for olt,pdict in log.iteritems():
			if olt != 'All':
				for priority, logList in pdict.iteritems():
					i = 0
					while i < len(logList):
						tup = logList[i]
						#print tup[0]
						groups = r.match(tup[1]).groups()
						if groups[0] == 'NOK':
							logsOut.append(['error', tup[1]])
						if tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
							if groups[8] not in switchesMacMadeOn:
								logList.pop(i)
								i -= 1
						elif tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
							#print groups[0], groups[1], switchesMacMadeOn, tup[1]
							if groups[9] not in switchesMacMadeOn and groups[10] in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid sdp binding create'
							elif groups[9] in switchesMacMadeOn and groups[10] not in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid sdp binding create'
							else:
								# invalid
								print 'invalid sdp binding create for HandOver'
								#print groups[0], groups[1], switchesMacMadeOn, tup[1]
						elif tup[0] == codeStaticMacCreate or tup[0] == codeStaticMacCreateFail:
							#print groups[12], groups[14], switchesMacMadeOn
							if groups[12] not in switchesMacMadeOn and groups[14] in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid static mac create'
							elif groups[12] in switchesMacMadeOn and groups[14] not in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid static mac create'
							else:
								# invalid
								print 'invalid static mac create'
						elif tup[0] == codeOltMacNameCreate or tup[0] == codeOltMacNameCreateFail:
							if groups[3] not in switchesMacMadeOn:
								logList.pop(i)
								i -= 1
								#print 'valid macname create' 
							else:
								print 'invalid macname create' 
						i += 1
		#print handover
		logsOut.append(["addHO", handover])

#####################################################################################################################
	# olt removing searching
	
	# look for OLTS added:
	oltsRemoved = []
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeVplsDelete:
					oltsRemoved.append(olt)
	
	for oltName in oltsRemoved:
		pdict = log.get(oltName)
		switchesMacRemovedFrom = []
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				groups = r.match(tup[1]).groups()
				if groups[0] == 'NOK':
					logsOut.append(['error', tup[1]])
				if tup[0] == codeOltMacNameDelete or tup[0] == codeOltMacNameDeleteFail:
					switchesMacRemovedFrom.append(groups[6])
					logList.pop(i)
					i -= 1
				elif tup[0] == codeVplsDelete or tup[0] == codeOltMacNameDeleteFail:
					logList.pop(i)
					i -= 1
				i += 1
		
		logsOut.append(["remOLT", oltName])
		
		pdict = log.get('All')
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				groups = r.match(tup[1]).groups()
				if groups[0] == 'NOK':
					logsOut.append(['error', tup[1]])
				if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
					if groups[6] not in switchesMacRemovedFrom:
						logList.pop(i)
						i -= 1
				i += 1
	#print log

	
#####################################################################################################################
	# Handover removing searching:
	handoversMade = []
	# check 'All' for new handovers made
	pdict = log.get('All')
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
				groups = r.match(tup[1]).groups()
				handoversMade.append(groups[5])
	
	handoversMade = list(set(handoversMade))
	#print handoversMade
	for handover in handoversMade:
		#print handover
		handoverAddress = ''
		switchesMacMadeOn = []
		pdict = log.get('All')
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				groups = r.match(tup[1]).groups()
				if groups[0] == 'NOK':
					logsOut.append(['error', tup[1]])
				if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
					#print groups[8], handover
					if groups[5] == handover:
						handoverAddress = groups[2]
						switchesMacMadeOn.append(groups[6])
						logList.pop(i)
						i -= 1
						#print 'remove', tup[1]
				i += 1
		for olt,pdict in log.iteritems():
			if olt != 'All':
				for priority, logList in pdict.iteritems():
					i = 0
					while i < len(logList):
						tup = logList[i]
						#print tup[0]
						groups = r.match(tup[1]).groups()
						if groups[0] == 'NOK':
							logsOut.append(['error', tup[1]])
						if tup[0] == codeBSiteDelete or tup[0] == codeBSiteDeleteFail:
							if groups[8] not in switchesMacMadeOn:
								logList.pop(i)
								i -= 1
						elif tup[0] == codeMeshSdpBindingDelete:
							#print groups[0], groups[1], switchesMacMadeOn, tup[1]
							if groups[9] not in switchesMacMadeOn and groups[10] in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid sdp binding create'
							elif groups[9] in switchesMacMadeOn and groups[10] not in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid sdp binding create'
							else:
								# invalid
								print 'invalid sdp binding Delete for HandOver'
								#print groups[0], groups[1], switchesMacMadeOn, tup[1]
						elif tup[0] == codeStaticMacDelete or tup[0] == codeStaticMacDeleteFail:
							#print groups[12], groups[14], switchesMacMadeOn
							if groups[12] not in switchesMacMadeOn and groups[14] in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid static mac create'
							elif groups[12] in switchesMacMadeOn and groups[14] not in switchesMacMadeOn:
								# valid
								logList.pop(i)
								i -= 1
								#print 'valid static mac create'
							else:
								# invalid
								print 'invalid static mac Delete'
						elif tup[0] == codeOltMacNameDelete or tup[0] == codeOltMacNameDeleteFail:
							if groups[6] not in switchesMacMadeOn:
								logList.pop(i)
								i -= 1
								#print 'valid macname create' 
							else:
								print 'invalid macname Delete' 
						i += 1
		#print handover
		logsOut.append(["remHO", handover])
	
#####################################################################################################################
	#add extras to unknown section
	
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			i = 0
			#print logList
			while i < len(logList):
				#print i
				tup = logList[i]
				logsOut.append(["unknown", str('Extra line: ' + tup[1])])
				logList.pop(i)

		
#####################################################################################################################

	print log
	print '\n'
	"""	
	if 1 == 1:
		logsOut.append(["Test", "Test"])
		logEmpty = True
		
	"""
	return logsOut
			
#####################################################################################################################

addedHO = []
removeHO = []
addOLT = []
removeOLT = []
errored = []
unknown = []

# used for testing when reading from files
logs = ["MultipleEvents.byolt"]
#logs = ["RemovelastOLTfromswitch.exec-del.byolt"]

for logStruct in logs:
	# also used for reading from files
	with open("oltinator-logs/"+logStruct,'r') as infile:
		filedata = infile.read()
		log = eval(filedata[filedata.index('\n{')+1:])
		
	logsOut = processLog(log)
	for processed in logsOut:
		if processed[0] == "addHO":
			addedHO.append(processed[1])
		elif processed[0] == "remHO":
			removeHO.append(processed[1])
		elif processed[0] == "addOLT":
			addOLT.append(processed[1])
		elif processed[0] == "remOLT":
			removeOLT.append(processed[1])
		elif processed[0] == "error":
			errored.append(processed[1])
		else:
			unknown.append(processed[1])

f = open("Simplifed.txt","w+")

print "Handovers added:"
f.write("Handovers added:\n")
for item in addedHO:
	print "	" + item
	f.write("	" + item + "\n")
	
print "Handovers removed:"
f.write("Handovers removed:\n")
for item in removeHO:
	print "	" + item
	f.write("	" + item + "\n")
	
print "OLTs added:"
f.write("OLTs added:\n")
for item in addOLT:
	print "	" + item
	f.write("	" + item + "\n")
	
print "OLTs removed:"
f.write("OLTs removed:\n")
for item in removeOLT:
	print "	" + item
	f.write("	" + item + "\n")
	
print "Errored Logs:"
f.write("Errored Logs:\n")
for item in errored:
	print "	" + item
	f.write("	" + item + "\n")
	
print "Unknown Logs:"
f.write("Unknown Logs:\n")
for item in unknown:
	print "	" + item
	f.write("	" + item + "\n")

print "\nWrote out to Simplifed.txt"
