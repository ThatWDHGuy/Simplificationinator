import re

# old one
#r=re.compile(r'(?i)\[(\S+)]\s{2}(?:(?:.*mac.*name (?:(?:(\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\))|(?:(\S+) from (\S+) \(([0-9\.]+)\))))|(?:.* vpls.Vpls.* for olt)|(?:.* vpls.Bsite.* (\S+))|(?:.* (?:svt\.|.*)meshSdpBinding from (\S+) to (\S+).*)|(?:.*: created static MAC (\S+) on (\S+) \(([0-9\.]+)\) to (\S+) \(([0-9\.]+)\)))')
# better one
r=re.compile(r'\[(\S+)]  .*(?:mac ?name (?:(\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\)|(\S+) from (\S+) \(([0-9\.]+)\))|vpls.Vpls.* for olt|vpls.Bsite.* (\S+)|meshSdpBinding from (\S+) to (\S+).*|created static MAC (\S+) on (\S+) \(([0-9\.]+)\) to (\S+) \(([0-9\.]+)\))', re.IGNORECASE)

logTypes = [
#(?i)\[(\S+)](?:.*mac.*name (?:(?:(\S+) = ([-0-9A-F]+) on (\S+) \(([0-9\.]+)\))|(?:(\S+) from (\S+) \(([0-9\.]+)\))))
'[ok]  create MacName IDA300003001 = 02-00-00-00-00-08 on NPE-ETH260 (10.70.253.137)',
'[ok]  deleted handover mac name IDA100010002 from NPE-ETH260 (10.70.253.137)',
'[ok]  suppressed delete handover mac name IDA477999999 from NPE-ETH201 (11.0.1.7)',
#(?i)\[(\S+)](?:.* vpls.Vpls.* for olt)
'[ok]  NEW-POLT01 : vpls.Vpls created for olt',
'[ok]  NEW-POLT02 : removed unneeded vpls.Vpls for OLT',
'[ok]  NEW-POLT02 : removal suppressed of unneeded vpls.Vpls for OLT',
#(?i)\[(\S+)](?:.* vpls.Bsite.* (\S+))
'[ok]  NEW-POLT01 : created vpls.BSite on NPE-ETH210',
'[ok]  NIL-POLT03 : deleted vpls.BSite NPE-ETH260',
'[ok]  NIL-POLT02 : delete suppressed for vpls.BSite NPE-ETH260',
#(?i)\[(\S+)](?:.* (?:svt\.|.*)meshSdpBinding from (\S+) to (\S+).*)
'[ok]  NEW-POLT01 : created svt.meshSdpBinding from NPE-ETH210 to NPE-ETH260',
'[ok]  NIL-POLT02 : attempt to remove unneeded svt.MeshSdpBinding from NPE-ETH203 to NPE-ETH260 already deleted',
'[ok]  NAE-POLT02 : delete suppressed for unneeded MeshSdpBinding from NPE-ETH210 to NPE-ETH260 (10.70.253.137)',
#(?i)\[(\S+)](?:.*: created static MAC (\S+) on (\S+) \(([0-9\.]+)\) to (\S+) \(([0-9\.]+)\))
'[ok]  NEW-POLT01 : created static MAC 02-00-00-00-01-89 on NPE-ETH210 (11.0.1.17) to NPE-ETH260 (10.70.253.137)',
#same as first
'[ok]  create MacName NEW-POLT01 = 02-00-00-00-01-89 on NPE-ETH210 (11.0.1.17)',
'[ok]  deleted OLT mac name NEW-POLT02 from NPE-ETH204 (11.0.1.8)',
'[ok]  suppressed delete OLT mac name NAE-POLT02 from NPE-ETH260 (10.70.253.137)']

for log in logTypes:
	groups = r.match(log).groups()
	
	####################################
	extracted = []
	i = 0
	while i < len(groups):
		g = groups[i]
		if g != None:
			extracted.append(str(str(i) + ' - ' + g))
		i += 1
	print log
	print extracted
	####################################
