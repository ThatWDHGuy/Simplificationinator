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

r=re.compile(r'\[(\S+)] .*(?:mac ?name (?:(\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\)|(\S+) from (\S+) \(([0-9\.]+)\))|vpls.Vpls.*|vpls.Bsite.* (\S+)|meshSdpBinding from (\S+) to (\S+).*|created static MAC (\S+) on (\S+) \(([0-9\.]+)\) to (\S+) \(([0-9\.]+)\))', re.IGNORECASE)
e=re.compile(r'.+\[ app: (.+) ].+\[ class: (.+) ].+\[ instance: (.+) ].+\[ descr: (.+) ].*', re.IGNORECASE)

addHO = []
remHO = []
addOLT = []
remOLT = []
errored = []
unknown = []

def tee(f, fmt):
	print fmt
	print >>f, fmt
	
def doError(groups,tup, logList, i):
	if groups[0] == 'NOK':
		error = tup[1]
		errorNo = tup[0]
		
		errorTup = logList[i+1]
		errorStat = e.match(errorTup[1]).groups()
		error += '\n		app: ' + errorStat[0]
		error += '\n		class: ' + errorStat[1]
		error += '\n		instance: ' + errorStat[2]
		error += '\n		description: ' + errorStat[3]
		return error

def contains(pdict, number1):
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == number1:
				return True
	return False
	
def contains(pdict, number1, number2):
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == number1 or tup[0] == number2:
				return True
	return False

def processLog(logIn):   	
	addHO = []
	remHO = []
	addOLT = []
	remOLT = []
	errored = []
	unknown = []

	#  0 = ok or not ok
	#  1 = add macname : macname
	#  2 = add macname : mac address
	#  3 = add macname : on switch name
	#  4 = add macname : on switch IP address
	#  5 = delete macname : macname
	#  6 = delete macname : from switch name
	#  7 = delete macname : from switch IP address
	#  8 = add/remove bsite : switch name
	#  9 = add/remove meshSdpBinding : from switch name
	# 10 = add/remove meshSdpBinding : to switch name
	# 11 = add static mac : mac address
	# 12 = add static mac : on switch name
	# 13 = add static mac : on switch IP address
	# 14 = add static mac : destination switch
	# 15 = add static mac : destination switch IP

	logsOut = []
	log = logIn

#####################################################################################################################

	# olt adding searching
	# look for OLTS added:
	oltAddNames = []
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeVplsCreate or tup[0] == codeVplsCreateFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						oltAddNames.append(olt)  
	
	# cycle through olts added
	for oltName in oltAddNames:
		didError = False
		pdict = log.get(oltName, {})
		sdpSwitches = []		
		highestCount = 0
		oltAddedTo = []
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						sdpSwitches.append(groups[9])
						sdpSwitches.append(groups[10])
						
						
		for name in sdpSwitches:
			if sdpSwitches.count(name) > highestCount:
				highestCount = sdpSwitches.count(name)
				
		for name in sdpSwitches:			
			if sdpSwitches.count(name) == highestCount and name not in oltAddedTo:				
				oltAddedTo.append(name)
				
		

		# ensure everything is correct in the add olt log, no extra lines, errors
		# get list of switches BSite made to and store for getting static mac addresses

		bSiteSwitches = []
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						if groups[8] != oltAddedTo:
							bSiteSwitches.append(groups[8])

		# remove self from sdpBinding and bSiteSwitches switches
		sdpSwitches = list(set(sdpSwitches)) # remove dupes
		bSiteSwitches = list(set(sdpSwitches)) # remove dupes

		# check static mac match sdp bindings and bsites
		
		for switchName in oltAddedTo:
			pdict = log.get(oltName, {})
			staticMacsMade = []
			oltAddedToAddress = ''
			for priority, logList in pdict.iteritems():
				i = 0
				while i < len(logList):
					tup = logList[i]
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						if tup[0] == codeStaticMacCreate or tup[0] == codeStaticMacCreateFail:
							if groups[12] == switchName and groups[14] in sdpSwitches and groups[14] in bSiteSwitches:
								# valid
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								staticMacsMade.append(groups[11])
								oltAddedToAddress = groups[12]
								logList.pop(i)
								i -= 1
							elif groups[14] == switchName and groups[12] in sdpSwitches and groups[12] in bSiteSwitches:
								# valid
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								logList.pop(i)
								i -= 1
	
						elif tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
							if groups[8] in sdpSwitches or groups[8] == switchName:
								# valid
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								logList.pop(i)
								i -= 1
	
						elif tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
							if groups[9] == switchName and groups[10] in sdpSwitches and groups[10] in bSiteSwitches:
								# valid
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								logList.pop(i)
								i -= 1
							elif groups[10] == switchName and groups[9] in sdpSwitches and groups[9] in bSiteSwitches:
								# valid
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								logList.pop(i)
								i -= 1
	
						elif tup[0] == codeOltMacNameCreate or tup[0] == codeOltMacNameCreate:
							if groups[3] in sdpSwitches and groups[3] in bSiteSwitches:
								if tup[0] >= 100:
									errored.append(doError(groups,tup, logList, i))
									logList.pop(i+1)
									didError = True
								logList.pop(i)
								i -= 1
								
						elif tup[0] == codeVplsCreate or tup[0] == codeVplsCreateFail:
							if tup[0] >= 100:
								errored.append(doError(groups,tup, logList, i))
								logList.pop(i+1)
								didError = True
							logList.pop(i)
							i -= 1
					i += 1

			pdict = log.get('All', {})
			for priority, logList in pdict.iteritems():
				i = 0
				while i < len(logList):
					tup = logList[i]
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						if groups[2] in staticMacsMade and groups[3] == switchName:
							if tup[0] >= 100:
								errored.append(doError(groups,tup, logList, i))
								logList.pop(i+1)
								didError = True
							logList.pop(i)
							i -= 1
					i += 1
		
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
		
		for name in oltAddedTo:	
			addOLT.append(str(oltName + " on " + name + errTxt))
	
#####################################################################################################################
	# Handover adding searching:
	handoversMade = []
	# check 'All' for new handovers made
	pdict = log.get('All', {})
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == codeHandoverMacNameCreate or tup[0] == codeHandoverMacNameCreateFail:
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					handoversMade.append(groups[1])
	handoversMade = list(set(handoversMade))
	for handover in handoversMade:
		didError = False
		handoverAddress = ''
		switchesMacMadeOn = []
		pdict = log.get('All', {})
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				if tup[0] == codeHandoverMacNameCreate or tup[0] == codeHandoverMacNameCreateFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						if groups[1] == handover:
							handoverAddress = groups[2]
							switchesMacMadeOn.append(groups[3])
							if tup[0] >= 100:
								errored.append(doError(groups,tup, logList, i))
								logList.pop(i+1)
								didError = True
							logList.pop(i)
							i -= 1
				i += 1
		for olt,pdict in log.iteritems():
			if olt != 'All':
				for priority, logList in pdict.iteritems():
					i = 0
					while i < len(logList):
						tup = logList[i]
						try:
							groups = r.match(tup[1]).groups()
						except:
							groups = []
						if groups != []:
							if tup[0] == codeBSiteCreate or tup[0] == codeBSiteCreateFail:
								if groups[8] not in switchesMacMadeOn:
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
								if groups[9] not in switchesMacMadeOn and groups[10] in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
								elif groups[9] in switchesMacMadeOn and groups[10] not in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeStaticMacCreate or tup[0] == codeStaticMacCreateFail:
								if groups[12] not in switchesMacMadeOn and groups[14] in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
								elif groups[12] in switchesMacMadeOn and groups[14] not in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeOltMacNameCreate or tup[0] == codeOltMacNameCreateFail:
								if groups[3] not in switchesMacMadeOn:
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
						i += 1
		
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
		addHO.append(handover + errTxt)
 
#####################################################################################################################
	# olt removing searching
	# look for OLTS added:
	oltsRemoved = []
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeVplsDelete or tup[0] == codeVplsDeleteFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						oltsRemoved.append(olt)

   
	for oltName in oltsRemoved:
		didError = False
		pdict = log.get(oltName, {})
		switchesMacRemovedFrom = []
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					if tup[0] == codeOltMacNameDelete or tup[0] == codeOltMacNameDeleteFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						switchesMacRemovedFrom.append(groups[6])
						logList.pop(i)
						i -= 1
					elif tup[0] == codeVplsDelete or tup[0] == codeVplsDeleteFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
				i += 1

		
	   
		pdict = log.get('All', {})
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
						if groups[6] not in switchesMacRemovedFrom:
							if tup[0] >= 100:
								errored.append(doError(groups,tup, logList, i))
								logList.pop(i+1)
								didError = True
							logList.pop(i)
							i -= 1
				i += 1
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
		
		remOLT.append(oltName + errTxt)
	
#####################################################################################################################
	# Handover removing searching:
	handoversMade = []
	# check 'All' for new handovers made
	pdict = log.get('All', {})
	for priority, logList in pdict.iteritems():
		for tup in logList:
			if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					handoversMade.append(groups[5])
	handoversMade = list(set(handoversMade))
	for handover in handoversMade:
		didError = False
		handoverAddress = ''
		switchesMacMadeOn = []
		pdict = log.get('All', {})
		for priority, logList in pdict.iteritems():
			i = 0
			
			while i < len(logList):
				tup = logList[i]
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					if tup[0] == codeHandoverMacNameDelete or tup[0] == codeHandoverMacNameDeleteFail:
						if groups[5] == handover:
							handoverAddress = groups[2]
							switchesMacMadeOn.append(groups[6])
							if tup[0] >= 100:
								errored.append(doError(groups,tup, logList, i))
								logList.pop(i+1)
								didError = True
							logList.pop(i)
							i -= 1
				i += 1
		for olt,pdict in log.iteritems():
			if olt != 'All':
				for priority, logList in pdict.iteritems():
					i = 0
					while i < len(logList):
						tup = logList[i]
						try:
							groups = r.match(tup[1]).groups()
						except:
							groups = []
						if groups != []:
							if tup[0] == codeBSiteDelete or tup[0] == codeBSiteDeleteFail:
								if groups[8] not in switchesMacMadeOn:
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeMeshSdpBindingDelete:
								if groups[9] not in switchesMacMadeOn and groups[10] in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
								elif groups[9] in switchesMacMadeOn and groups[10] not in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeStaticMacDelete or tup[0] == codeStaticMacDeleteFail:
								if groups[12] not in switchesMacMadeOn and groups[14] in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
								elif groups[12] in switchesMacMadeOn and groups[14] not in switchesMacMadeOn:
									# valid
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
							elif tup[0] == codeOltMacNameDelete or tup[0] == codeOltMacNameDeleteFail:
								if groups[6] not in switchesMacMadeOn:
									if tup[0] >= 100:
										errored.append(doError(groups,tup, logList, i))
										logList.pop(i+1)
										didError = True
									logList.pop(i)
									i -= 1
						i += 1
						
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
		remHO.append(handover + errTxt)
   


#####################################################################################################################
	#add 2nd lag search
	olts2ndlag = []
	for olt,pdict in log.iteritems():
			if contains(pdict, codeMeshSdpBindingCreate, codeMeshSdpBindingCreateFail) and contains(pdict, codeStaticMacCreate, codeStaticMacCreateFail) and contains(pdict, codeOltMacNameUpdate, codeOltMacNameUpdateFail):
				olts2ndlag.append(olt)
	
	for olt in olts2ndlag:
		didError = False
		sdpSwitches = []		
		highestCount = 0
		oltAddedTo = []
		pdict = log.get(olt, {})
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						sdpSwitches.append(groups[9])
						sdpSwitches.append(groups[10])
						
						
		for name in sdpSwitches:
			if sdpSwitches.count(name) > highestCount:
				highestCount = sdpSwitches.count(name)
				
		for name in sdpSwitches:			
			if sdpSwitches.count(name) == highestCount and name not in oltAddedTo:				
				oltAddedTo.append(name)
				
		
			
		pdict = log.get(olt, {})
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					if tup[0] == codeMeshSdpBindingCreate or tup[0] == codeMeshSdpBindingCreateFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
					elif tup[0] == codeStaticMacCreate or tup[0] == codeStaticMacCreateFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
					elif tup[0] == codeOltMacNameUpdate or tup[0] == codeOltMacNameUpdateFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
				i += 1
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
			
		for name in oltAddedTo:	
			addOLT.append(str(olt + " on " + name + "(as 2nd lag)" + errTxt))
				
#####################################################################################################################
	#convert to single lag search
	oltMCtoSigle = []
	for olt,pdict in log.iteritems():
			if contains(pdict, codeMeshSdpBindingDelete, codeMeshSdpBindingDeleteFail) and contains(pdict, codeOltMacNameUpdate, codeOltMacNameUpdateFail):
				oltMCtoSigle.append(olt)
	
	for olt in oltMCtoSigle	:
		didError = False
		sdpSwitches = []		
		highestCount = 0
		oltAddedTo = []
		pdict = log.get(olt, {})
		for priority, logList in pdict.iteritems():
			for tup in logList:
				if tup[0] == codeMeshSdpBindingDelete or tup[0] == codeMeshSdpBindingDeleteFail:
					try:
						groups = r.match(tup[1]).groups()
					except:
						groups = []
					if groups != []:
						sdpSwitches.append(groups[9])
						sdpSwitches.append(groups[10])
						
						
		for name in sdpSwitches:
			if sdpSwitches.count(name) > highestCount:
				highestCount = sdpSwitches.count(name)
				
		for name in sdpSwitches:			
			if sdpSwitches.count(name) == highestCount and name not in oltAddedTo:				
				oltAddedTo.append(name)
				
		
			
		pdict = log.get(olt, {})
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				try:
					groups = r.match(tup[1]).groups()
				except:
					groups = []
				if groups != []:
					if tup[0] == codeMeshSdpBindingDelete or tup[0] == codeMeshSdpBindingDeleteFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
					elif tup[0] == codeOltMacNameUpdate or tup[0] == codeOltMacNameUpdateFail:
						if tup[0] >= 100:
							errored.append(doError(groups,tup, logList, i))
							logList.pop(i+1)
							didError = True
						logList.pop(i)
						i -= 1
				i += 1
				
		errTxt = ""
		if didError:
			errTxt = " (Errored)"
			
		for name in oltAddedTo:	
			remOLT.append(str(olt + " on " + name + " (Changing from MC to single)" + errTxt))
			
#####################################################################################################################

	#add extras to unknown section
	for olt,pdict in log.iteritems():
		for priority, logList in pdict.iteritems():
			i = 0
			while i < len(logList):
				tup = logList[i]
				unknown.append(str('Extra line: ' + tup[1]))
				logList.pop(i)   
#####################################################################################################################
	#Summary Stuff
	f = open("summary.txt","w+")
	tee(f, '\nLog Analysis Summary:\n')	
	tee(f, 'Handovers added:')
	if addHO:
		for item in addHO:
			tee(f, '	' + item)
	else:
		tee(f, '	none')

	tee(f, '\nHandovers removed:')
	if remHO:
		for item in remHO:
			tee(f, '	' + item)
	else:
		tee(f, '	none')

	tee(f, '\nOLTs added:')
	if addOLT:
		for item in addOLT:
			tee(f, '	' + item)
	else:
		tee(f, '	none')

	tee(f, '\nOLTs removed:')
	if remOLT:
		for item in remOLT:
			tee(f, '	' + item)
	else:
		tee(f, '	none')
 
	tee(f, '\nErrored changes:')
	if errored:
		for item in errored:
			tee(f, '	' + item)
	else:
		tee(f, '	none')
		
	tee(f, '\nUnattributed changes:')

	if unknown:
		for item in unknown:
			tee(f, '	' + item)
	else:
		tee(f, '	none')
"""
###Debugging with individual files

logs = ["Add first handover to switch.exec.byolt", 
		"Add first OLT to switch.exec.byolt", 
		"Add subsequent handover to switch.exec.byolt", 
		"Add subsequent OLT to switch.exec.byolt", 
		"Remove last handover from switch.exec-del.byolt", 
		"Remove last OLT from switch.exec-del.byolt", 
		"Remove subsequent handover from switch.exec-del.byolt", 
		"Remove subsequent OLT from switch.exec-del.byolt",
		"Add new MC lag OLT.txt",
		"Remove MC lag OLT.txt",
		"Add 1st lag of MC lag.txt",
		"Removing second lag (same as removing an OLT).txt",
		"Delete MC lag olt Fail + stuff.txt",
		"Add 2nd lag of MC lag.txt",
		"Convert lag to single.txt"]
		
print "#####################################################################################################################"
for logStruct in logs:
	# also used for reading from files
	with open("oltinator-logs-full/"+logStruct,'r') as infile:
		filedata = infile.read()
		log = eval(filedata[filedata.index('\n{')+1:])
		print logStruct
		processLog(log)
		print "\n#####################################################################################################################"

"""
