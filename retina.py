###
# Reads in Retina Remediation Report in single file .mht format
# and provides html and csv tables showing all the CVEs that have
# Core and Metasploit Exploits.  Also lists vulnerable systems
##

##
# Usage:  remediation.py <path/retina report>
##

##
# Import modules
##
import sys, msvcrt

##
# Global Variables
##
cfile = "" #command line argument
cfile_obj = ""      #Retina MHT file
remediation = []    #variable to hold retina report 
exploit = {}       #Hash list dictionary to hold exploits

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
    else:
        cfile = sys.argv[1]
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




def parse_for_exploits():
    global remediation, exploit
    flagexploits = 0
    flagcves = 0
    flagips = 0
    exploitdb = []
    header = []
    cve = []
    ip = []
    cveloop = []
    cvecount = 0
    vulnname = ''


    for line in remediation:
        """
        The first line helps to normalize part of the file...since inexplicably there are tabs starting some lines.
        The other lines just help to move things along.
        """
        if line.startswith('\t') == True:
            line = line[1:]
        if line.startswith(' \t \n') == True:
            continue
        elif line.startswith(' \t ') == True:
            line = line[3:-1]
            vulnname=line
            continue
        if line.startswith('CVE-ID') == True:
            continue
        if line.startswith('Total') == True:
            continue
        if line.startswith('Affected') == True:
            continue
        if line.startswith('\n') == True:
            continue
        if line.startswith('Exploits:') == True:
            line = line[:-1]
            flagexploits = 1
            continue

        """
        Once the start of an exploit section is flagged, time to parse in earnest
        """
        if flagexploits == 1 and line.startswith('CVE-'):
            line = line[:-1]
            cve = line.split('\t')

            """
            Now begins the ugliness.
            The lines in exploits: that start with CVE-<year>-<number> are what we want.
            However they vary in length from 2 to 7 tab separated fields and are not always on one line.
            """

            ##
            # Since we allow compiling multiple reports, this sections checks to see whether the dict variable
            # key cve[0] exists.  if not, it creates it.  If it does, it leaves it be to be appeneded to.
            ##
            if exploit.get(cve[0]) == None:
                exploit[cve[0]] = {}
                exploit[cve[0]]['CVE Assignment'] = cve[0]
                exploit[cve[0]]['IP'] = []
                exploit[cve[0]]['VulnName'] = vulnname
                exploit[cve[0]]['Vector'] = ""
            
            ##
            # Since there can be multiple CVEs in each report section, we track the keys to append IPs later
            ##
            cveloop.append(cve[0])

            ##
            # now we need to count the fields on this line to determine what fields are here and what are on the next line
            ##
            cvecount = len(cve)
            
            ##
            # If there are 3 or fewer fields, the the rest are wrapped
            ##
            if len(cve) <= 3:
                flagcves = 1

            ##
            # If ExploitDB is Yes, the retina puts the URL with it, separated by a space.
            # We don't want the URL right now, so we need to strip it off to just get the YES
            ##
            if cve[1] != 'No':
                exploitdb = cve[1].split(' ')
                exploit[cve[0]]['ExploitDB'] = exploitdb[0]
            else:
                exploit[cve[0]]['ExploitDB'] = cve[1]
            
            
            ##
            # if the number of fields is 3 then CoreImpact is on this line.
            # if the number of fields is > 3 then all the fields are on this line.
            ##
            if len(cve) == 3:
                flagcves = 1
                exploit[cve[0]]['CoreImpact'] = cve[2]
            elif len(cve) > 3:
                exploit[cve[0]]['CoreImpact'] = cve[2]
                exploit[cve[0]]['Metasploit'] = cve[4]
        elif flagcves == 1:
            line = line[:-1]
            line = line.split('\t')

            ##
            # if only 2 fields previously, then coreimpact and metasploit are here.
            # if there were 3 then only metasploit is here
            ##
            if cvecount == 2:
                exploit[cve[0]]['CoreImpact'] = line[0]
                exploit[cve[0]]['Metasploit'] = line[2]
            elif cvecount == 3:
                exploit[cve[0]]['Metasploit'] = line[1]
            
            # reset the flags
            flagcves = 0
            cvecount = 0
        elif line.startswith('Checkbox') == True and flagexploits == 1:
            """
            The lines with IP addresses we need to capture for this group of CVEs all start with 'Checkbox'
            so we look for that, split it, then append the IP to the dict variable exploit in an array.
            """

            ip = line.split(' ')
            ip = ip[1].split('\t')
            if len(cveloop) != 0:
                for x in cveloop:
                    if ip[0] in exploit[x]['IP']:
                    	next
                    else:
                    	exploit[x]['IP'].append(ip[0])
            else:
                next
        elif line.startswith('Notes:') == True and flagexploits == 1:
            """
            'Notes:' is a unique entry that signals the last of the retina information
            for that vulnerability set.  So when we see it, we reset all variables
            """
            flagips = 0
            flagcves = 0
            flagexploits = 0
            cve = []
            ip = []
            exploitdb = []
            cveloop = []

def report():
    """
    Now we want to take the exploit dict variable and print a CSV and HTM table with results.
    """
    global exploit
    keyboard = 0

    reports = raw_input("\n\nReport Name: ")
    csvfile = open(reports + ".csv",'w')

    print '\n\n\nWe need some input from you to make this whole thing easier.\n'
    print 'We are going to print each vulnerability name'
    print 'then ask you to hit "c" for client side vulnerability'
    print 'or "n" for network vulnerability.'
    print 'Just give your best guess:\n\n'
    

    csvfile.write('CVE-Assignment,VulnName,Vector,SuccessfulExploit,ExploitDB,CoreImpact,Metasploit,IPAddreses\n')

    for key in sorted(exploit.iterkeys()):
        if exploit[key]['ExploitDB'] == 'Yes' or exploit[key]['CoreImpact'] == 'Yes' or exploit[key]['Metasploit'] == 'Yes':
            print key + '\t' + exploit[key]['VulnName']
            print 'Hit "c" for client or "n" for network or "q" to quit\n'
            while True:
            #    if msvcrt.kbhit():
                keyboard = ord(msvcrt.getch())
                if keyboard == 99:
                    exploit[key]['Vector'] = 'Client'
                    break
                elif keyboard == 110:
                    exploit[key]['Vector'] = 'Network'
                    break
                elif keyboard == 113:
                    exit()
                        
            csvfile.write(exploit[key]['CVE Assignment'] + "," + exploit[key]['VulnName'] + "," +exploit[key]['Vector'] + "," + "," + exploit[key]['ExploitDB'] + "," + exploit[key]['CoreImpact'] + "," + exploit[key]['Metasploit'] + "," + (",".join(exploit[key]['IP'])) + "\n")



#
#Main Program
#
evalsysargv()
parse_for_exploits()
report()


# print the exploit hash table
#for key in exploit:
#    if exploit[key]['ExploitDB'] == 'Yes' or exploit[key]['CoreImpact'] == 'Yes' or exploit[key]['Metasploit'] == 'Yes':
#        print exploit[key]['CVE Assignment'] + " " + exploit[key]['ExploitDB'] + " " + exploit[key]['CoreImpact'] + " " + exploit[key]['Metasploit'] + " " + str(exploit[key]['IP']) + "\n"
