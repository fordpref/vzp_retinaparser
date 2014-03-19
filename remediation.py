
#Parsing Remediation MHT report

#modules to import
import sys

#Global Variables
cfile = sys.argv[1]
cfile_obj = ""
remediation = []
exploits = {}



#Functions
#Evaluate command line arguments first
def evalsysargv():
	"""
	Function to evaluate the command line arguments and 
	read the remediation report MHT file called
	remediation[].
	"""

	global cfile, cfile_obj, remediation

	i = 0
	line = ""

	if len(sys.argv) < 2:
		cfile = raw_input("Enter remediation MHT file path and name: ");
	cfile_obj = open(cfile,'r')
	for line in cfile_obj:
		remediation.append(line)
	return


def printfile():
	"""
	Just a test function, can be removed
	"""

	global remediation
	for line in remediation:
		print line
	return

def printstuff(obj):
	"""
	Just a test function, can be removed
	"""

	print obj,"\ntest print\n\n"
	return

def parse_exploits():
	"""
	If a line starts with Exploits:<space><tab> then we want to flag this and grab the
	following lines and determine which CVEs have Core or Metasploit exploits.
	Then we want to print this to a CSV and HTM file for use onsite and post
	phase two processing.
	The variable exploits is where we store the results.
	exploits['<CVE>']['Core Impact'] = stores whether Core has exploit
	exploits['<CVE>']['Metasploit'] = stores whether Metasploit has exploit
	"""
	global remediation, exploits	
	flag = 0
	i = 0
	splitline = 0
	splitsploit = ""
	coreflag = ""
	impact = 0
	cve = []
	machines = 0
	ips = []
	ip = []

	for line in remediation:
		if line.startswith("Exploits: \t") == 1:
			flag = 1
			machines = 0
		elif splitline == 1:
			splitline = 0
			parse = line.split("\t")
			if parse[1] == "Yes" and coreflag == "No":
				cve.append(splitsploit)
				exploits[splitsploit] = {}
				exploits[splitsploit]['Metasploit'] = parse[1]
				exploits[splitsploit]['Core Impact'] = coreflag
				exploits[splitsploit]['machines'] = []
			elif coreflag == "Yes":
				exploits[splitsploit]['Metasploit'] = parse[1]
				exploits[splitsploit]['Core Impact'] = coreflag
				exploits[splitsploit]['machines'] = []
				cve.append(splitsploit)
			coreflag = ""
		elif splitline == 2:
			splitline = 0
			parse = line.split("\t")
			if parse[0] == "Yes" or parse[2] == "Yes":
				cve.append(splitsploit)
				exploits[splitsploit] = {}
				exploits[splitsploit]['Core Impact'] = parse[0]
				exploits[splitsploit]['Metasploit'] = parse[2]
				exploits[splitsploit]['machines'] = []
			coreflag = ""
		elif line.startswith("Metasploit") == 1:
			continue
		elif flag == 1 and line.startswith("CVE") == 1:
			parse  = line.split("\t")
			splitsploit = parse[0]
			if len(parse) < 3:
				splitline = 2
				splitsploit = parse[0]
				
			elif parse[1].startswith("Yes") == 1:
				splitline = 1
				splitsploit = parse[0]
				if parse[2] == "Yes":
					exploits[splitsploit] = {}
					coreflag = "Yes"
				else:
					coreflag = "No"
			elif parse[2] == "Yes" or parse[4] == "Yes":
				exploits[parse[0]] = {}
				cve.append(parse[0])
				exploits[parse[0]]['Core Impact'] = parse[2]
				exploits[parse[0]]['Metasploit'] = parse[4]
				exploits[parse[0]]['Total'] = ""
				exploits[parse[0]]['machines'] = []
		elif flag == 1 and line.startswith("Total Machines Affected") == 1:
			flag = 0
			parse = line.split("\t")
			if len(cve) >= 1:
				machines = 1
				for i in cve:
					exploits[i]['Total'] = parse[1]
			else:
				cve = []
				machines = 0
		elif flag == 1:
			flag = 0
		elif machines == 1 and line.startswith("Checkbox"):
			parse = line.split("\t")
			ip = parse[0].split(" ")
			ips.append(ip[1])
		elif machines == 1 and line.startswith("Affected Items"):
			machines = 0
			for i in cve:
				exploits[i]['machines'] = ips
			splitsploit = ""
			ips = []
			cve = []	
	return

def report():
	"""
	Now we want to take the exploits variable and print a CSV and HTM table with results.
	"""
	global exploits
	

	reports = raw_input("\n\nReport Name: ")
	htmfile = open(reports + ".htm",'w')
	csvfile = open(reports + ".csv",'w')

	htmfile.write("<!DOCTYPE html>\n<html>\n<body>\n<p>\n")
	
	#Write out Header for report
	htmfile.write("<p><font size=""20""><b>"+reports+"</b></font><br><br></p>\n")


	htmfile.write('<font size="5"><p><table border="1"><b><tr><td> CVE </td><td> Core Impact </td><td> Metasploit </td><td> # Afflicted </td><td> Machines Affected </td></b></tr>\n')

	for key in sorted(exploits.iterkeys()):
		htmfile.write('<tr><td>' + key + '</td><td>' + exploits[key]['Core Impact'] + '</td><td>' + exploits[key]['Metasploit'] + '</td><td>' + exploits[key]['Total'] + '</td><td>' + (",".join(exploits[key]['machines'])) + '</td</tr>\n')
		csvfile.write(key + "," + exploits[key]['Core Impact'] + "," + exploits[key]['Metasploit'] + "," + exploits[key]['Total'] + (",".join(exploits[key]['machines'])) + "\n")
	
	htmfile.write("</table></p></font></body>")
	

#
#Main Program
#
evalsysargv()
parse_exploits()
report()
