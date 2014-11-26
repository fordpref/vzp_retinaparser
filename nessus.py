"""
Program to parse .nessus files and output a .csv that lists CVEs, Nessus plugin name, exploit,
core impact, canvas, or metasploit exploits, and IP addresses affected.
"""

"""
Import modules
"""

import xml.etree.ElementTree as ET
from subprocess import *
import sys, os, platform
from operator import itemgetter, attrgetter

if platform.system() == 'Windows':
    import msvcrt
else:
    import tty, termios

"""
Global Variables
"""
tree = {}
root = []
xmldir = ""
files = []
repfile = ""
writefile = ""
opsys = platform.system()
vuln = {}
iprep = {}
clear = ''




def evalargs():
    """
    Function to just parse command line arguments
    """
    
    global xmldir, files, repfile, opsys, clear
    f = {}

    if opsys == 'Windows':
        clear = 'cls'
    else:
        clear = 'clear'
    

    #If 2 arguments are not present, path and report file, get them
    if len(sys.argv) < 2 or len(sys.argv) < 3 or len(sys.argv) > 3:
        print "This script takes 2 command line arguments, path to the Nessus directory and name of the output report file.\n"
        xmldir = get_check_path()
        repfile = get_check_rep()
    #makes sure that the 2 arguments are correctly formatted and correct
    else:
        xmldir = sys.argv[1]
        if opsys == 'Windows':
            if xmldir[-1:] != '\\':
                xmldir += '\\'
        else:
            if xmldir[-1:] != '/':
                xmldir += '/'
        if os.path.exists(xmldir) == False:
            xmldir = get_check_path()
        repfile = sys.argv[2]

        # adds .csv to the end of the report file name if not there.
        if repfile[-4:] != '.csv':
            repfile += '.csv'

        # if the report file exists already, ask again
        if os.path.isfile(xmldir + repfile):
            repfile = get_check_rep()

    # Make repfile = the path + the file name
    repfile = xmldir + repfile
    # If windows, search the specified directory for .nessus files
    if opsys == 'Windows':
        f = Popen('dir /b "' + xmldir + '*.nessus"', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')
    # if unix search the directory for .nessus files
    else:
        f = Popen('ls ' + xmldir + ' |grep "\.nessus"', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')



def get_check_path():
    """
    ask for the correct path, and make sure it exists
    """
    
    global opsys
    path = ''


    path = raw_input('The path to the .nessus file is not valid, enter path: ')
    if opsys == 'Windows':
        if path[-1:] != '\\':
            path += '\\'
    else:
        if path[-1:] != '/':
            path += '/'
    if os.path.exists(path):
        return path
    else:
        path = get_check_path()
        return path


def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch 


def get_check_rep():
    """
    ask for the output file name
    make sure it ends in .csv
    """
    
    global xmldir
    outfile = ''

    outfile = raw_input('Name of report file: ')
    if outfile[-4:] != '.csv':
        outfile += '.csv'
    return outfile
       

def loop_files():
    """
    This loops through the .nessus files found and sends them through the parser
    """
    
    global tree, root, files
    x = ""

    for x in files:
        if x[-1:] == '\n':
            x = x[:-1]
        if x[-1:] == '\r':
            x = x[:-1]
        if len(x) > 4:
            tree = ET.parse(xmldir + x)
            root = tree.getroot()
            parse()


def parse():
    """
    The parser looks for the tags in the xml to find vulnerabilities with exploits, determines if core, canvas, or metasploit exploits exist too
    Setups up the vuln{} to capture the data and do the reporting
    """
    
    global root, vuln, iprep

    report = {}
    rephost =  {}
    name = ''
    hostprop = {}
    tag = {}
    ip = ''
    vector = ''
    expstate = ''
    repitemnames = ['Microsoft Windows AutoRuns Unique Entries', 'Patch Report',
                    'Authentication Failure - Local Checks Not Run', 'Nessus SYN scanner',
                    'Microsoft Windows Process Unique Process Name']
    loccheck = ['.NET', 'Flash Player', 'Internet Explorer', 'OLE', 'Event System',  'Kernel-Mode',
                'Drivers', 'Windows Kernel', 'Elevation of Privilege', 'VBScript', 'Driver', 'Icon',
                'DirectShow', 'Windows Components', 'sudo', 'linux-source', 'Windows Shell', 'ActiveX',
                'bash', 'wget', 'xulrunner', 'Windows Theme', 'Fax Cover', 'Windows Movie', 'Windows Media',
                'Service Path', 'Windows Image', 'dbus', 'glibc', 'firefox', 'GDI+', 'Codec', 'linux-',
                'Library', 'XML', 'Wordpad', 'Help', 'avahi', 'perl', 'python', 'Address Book', 'jdk',
                'Windows Object', 'MPEG', 'libxfont', 'Microsoft Office']

    remcheck = ['RPC', 'DNS', 'dhcp', 'openssl', 'apache',  'samba', 'SMB', 'php', 'Print Spooler',
                'Networking Components', 'tomcat', 'mysql', 'OpenSSL', 'Remote Desktop', 'postgres',
                'Telnet', 'SSL', 'Active Directory', 'NFS', 'HTTP Services', 'TCP', 'openssh', 'openldap'] 

    #Now lets parse the xml and get the fields we need.
    report = root.find('Report')    #basically the start of the report
    
    #Nessus creates a tag for each host it scans, called ReportHost.
    #We are going to for-loop through each one looking for child tags we need
    for rephost in report.findall('ReportHost'):

        #in each ReportHost, there is a HostProperties tag.
        #There is good information here, but we really just want the host-ip tag for now.
        #We find the tag, then loop through the tags until we get it.
        hostprop = rephost.find('HostProperties')
        for tag in hostprop.findall('tag'):
            hostip = tag.attrib
            if hostip['name'] == 'host-ip':
                ip = tag.text

        #Now we loop through the ReportItems for the ReportHost to look for exploits
        for reportitem in rephost.findall('ReportItem'):
            repitem = reportitem.attrib
            name = repitem['pluginName']

            # since we are making a CSV for easy input into a spreadsheet, remove commas from names when we find them.
            name = name.replace(',', '-')

            # Patch Report doesn't have exploit fields, so we skip that
            if name in repitemnames:
                next
            # Now we parse the  ReportItem
            else:
                if name in vuln:        #if the name is a key already, check to see if we need to add the IP address, then skip if not.
                    if ip in vuln[name]['IP']:
                        next
                    else:
                        vuln[name]['IP'].append(ip)
                        if ip in iprep:
                            pass
                        else:
                            iprep[ip] = []
                        iprep[ip].append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name']))
                        next
                        
                #Now we try to find if the exploit_available tag is present, and if yes, fill out the rest of the fields
                #try:
                try:
                    expstate = reportitem.find('exploit_available')
                except:
                    next
                if expstate is None:
                    next
                elif expstate.text != 'true':
                    next
                else:
                    print repitem['pluginName'] + ' is exploitable.'    #Makes sure you know the program is working and gives you quick view of exploits
                expstate = ''
                for x in loccheck:
                    if x.lower() in name.lower():
                        vector = 'Local'
                        break
                for x in remcheck:
                    if x.lower() in name.lower():
                        if vector == 'Local':
                            vector == 'Conflict'
                            break
                        vector = 'Remote'
                        break
                # If we are here, then it should be the first time we have seen this vulnerability, so setup vuln dictionary
                vuln[name]= {}      # name is the pluginName from earlier
                vuln[name]['id'] = str(repitem['pluginID'])     #store pluginID
                vuln[name]['CVE'] = []      #put the CVEs in an array
                vuln[name]['Vector'] = vector
                vuln[name]['Successful'] = ''
                vuln[name]['IP'] = []       #put the IP addresses in an array
                vuln[name]['IP'].append(ip) #if first time through append current IP to the array
                vuln[name]['exploit'] = True        # If you get here, then there is at least an exploit
                vuln[name]['core'] = False          # setup core field
                vuln[name]['canvas'] = False        # Setup canvas field
                vuln[name]['metasploit'] = {}       # setup metasploit fields
                vuln[name]['metasploit']['avail'] = False
                vuln[name]['metasploit']['name'] = ''

                # checks for core impact exploit
                try:
                    core = reportitem.find('exploit_framework_core').text
                    vuln[name]['core'] = True
                except:
                    vuln[name]['core'] = False

                # checks for metasploit exploit
                try:
                    meta = reportitem.find('exploit_framework_metasploit').text
                    vuln[name]['metasploit']['avail'] = True
                    vuln[name]['metasploit']['name'] = reportitem.find('metasploit_name').text
                except:
                    vuln[name]['metasploit']['avail'] = False
                    vuln[name]['metasploit']['name'] = 'n/a'

                # checks for cnavas exploit
                try:
                    canv = reportitem.find('exploit_framework_canvas').text
                    vuln[name]['canvas'] = True
                except:
                    vuln[name]['canvas'] = False

                # Loop through CVE tags and collect the CVEs.  We don't know which is actually responsible and Nessus doesn't tell us.
                cve = []
                for x in reportitem.findall('cve'):
                    cve.append(x.text)
                cve.sort()
                vuln[name]['CVE']= ':'.join(cve)
                if vuln[name]['canvas'] == True or vuln[name]['metasploit']['avail'] == True or vuln[name]['core'] == True:
                    if ip in iprep:
                        iprep[ip].append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name']))
                    else:
                        iprep[ip] = []
                        iprep[ip].append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name']))
                cve = []
                vector = ''
                #else:
                #    next
                #except:
                #    vector = ''
                #    print '\n\n****\nError with ' + ip + '\n****\n\n'
                #    next
            vector = ''                            
        vector = ''


def report():
    """
    Report just parses the vuln dictionary and outputs to a csv file
    """
    
    global vuln, repfile, xmldir

    report = ''
    sortrep = []
    canvas = []
    metasploit = []
    core = []
    exploit = []
    
    writefile = open(repfile, 'w')
    writefile2 = open(repfile[:-3] + 'sorted.csv', 'w')

    # write the field headers to the file
    writefile.write('CVEs,Name,Local-Remote,Successful,exploit,Core,Canvas,Metasploit,MetasploitName,IPs\n')

    # Now, join arrays together, comma separate things, write the file
    print '\n\n\n\n\n\n'
    for name in vuln:
        #cve = ':'.join(vuln[name]['CVE'])
        #vuln[name]['CVE'] = cve
        ip = ','.join(vuln[name]['IP'])
        vuln[name]['IP'] = ip
        
        if vuln[name]['Vector'] == '':
            if vuln[name]['core'] == True or vuln[name]['canvas'] == True or vuln[name]['metasploit']['avail'] == True:
                print name + '\t' + 'Local or Remote?'
                print 'Hit "l" for local or "r" for remote or "q" to quit\n'
                if opsys == 'Windows':
                    while True:
                        keyboard = ord(msvcrt.getch())
                        if keyboard == 108:
                            vuln[name]['Vector'] = 'Local'
                            break
                        elif keyboard == 114:
                            vuln[name]['Vector'] = 'Remote'
                            break
                        elif keyboard == 113:
                            exit()
                    report = vuln[name]['CVE'] + ',' + name + ',' + vuln[name]['Vector'] + ',' + vuln[name]['Successful'] + ',' + str(vuln[name]['exploit']) + ',' + str(vuln[name]['core']) + ',' + str(vuln[name]['canvas']) + ',' + str(vuln[name]['metasploit']['avail']) + ',' + vuln[name]['metasploit']['name'] + ',' + vuln[name]['IP'] + '\n' 
                    writefile.write(report)
                else:
                    while True:
                        keyboard = getch()
                        print keyboard
                        if keyboard == 'l':
                            vuln[name]['Vector'] = 'Local'
                            break
                        elif keyboard == 'r':
                            vuln[name]['Vector'] = 'Remote'
                            break
                        elif keyboard == 'q':
                            exit()
                    report = vuln[name]['CVE'] + ',' + name + ',' + vuln[name]['Vector'] + ',' + vuln[name]['Successful'] + ',' + str(vuln[name]['exploit']) + ',' + str(vuln[name]['core']) + ',' + str(vuln[name]['canvas']) + ',' + str(vuln[name]['metasploit']['avail']) + ',' + vuln[name]['metasploit']['name'] + ',' + vuln[name]['IP'] + '\n'
                    writefile.write(report)
            else:
                report = vuln[name]['CVE'] + ',' + name + ',' + vuln[name]['Vector'] + ',' + vuln[name]['Successful'] + ',' + str(vuln[name]['exploit']) + ',' + str(vuln[name]['core']) + ',' + str(vuln[name]['canvas']) + ',' + str(vuln[name]['metasploit']['avail']) + ',' + vuln[name]['metasploit']['name'] + ',' + vuln[name]['IP'] + '\n'
                writefile.write(report)
        else:
            report = vuln[name]['CVE'] + ',' + name + ',' + vuln[name]['Vector'] + ',' + vuln[name]['Successful'] + ',' + str(vuln[name]['exploit']) + ',' + str(vuln[name]['core']) + ',' + str(vuln[name]['canvas']) + ',' + str(vuln[name]['metasploit']['avail']) + ',' + vuln[name]['metasploit']['name'] + ',' + vuln[name]['IP'] + '\n'
            writefile.write(report)
        
    
        #Now that the raw output is done, we need to break out some lists to do some sorting, save in other formats
        if vuln[name]['canvas'] == True:
            canvas.append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name'], vuln[name]['IP']))
        elif vuln[name]['metasploit']['avail'] == True:
            metasploit.append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name'], vuln[name]['IP']))
        elif vuln[name]['core'] == True:
            core.append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name'], vuln[name]['IP']))
        elif vuln[name]['exploit'] == True:
            exploit.append((vuln[name]['CVE'], name, vuln[name]['Vector'], vuln[name]['Successful'], str(vuln[name]['exploit']), str(vuln[name]['core']), str(vuln[name]['canvas']), str(vuln[name]['metasploit']['avail']), vuln[name]['metasploit']['name'], vuln[name]['IP']))
    writefile.close()    
    #sorted(student_objects, key=attrgetter('grade', 'age'))
    #sortrep = sorted(sortrep, key=itemgetter(6,2,7,2,5,2), reverse=True)
    canvas = sorted(canvas, key=itemgetter(6,2,1), reverse=True)
    metasploit = sorted(metasploit, key=itemgetter(7,2,1), reverse=True)
    core = sorted(core, key=itemgetter(5,2,1), reverse=True)
    exploit = sorted(exploit, key=itemgetter(2,0))

    writefile2.write('CVEs,Name,Local-Remote,Successful,exploit,Core,Canvas,Metasploit,MetasploitName,IPs\n')
    for x in canvas:
        x = ','.join(x) + '\n'
        writefile2.write(x)
    for x in metasploit:
        x = ','.join(x) + '\n'
        writefile2.write(x)
    for x in core:
        x = ','.join(x) + '\n'
        writefile2.write(x)
    for x in exploit:
        x = ','.join(x) + '\n'
        writefile2.write(x)
    writefile2.close()

    #now we write out the reports for individual hosts
    for ip in iprep:
        canvas = []
        metasploit = []
        core = []
        exploit = []

        writefile = open(xmldir + ip + '-nessus-vulns.csv', 'w')
        writefile.write('CVEs,Name,Local-Remote,Successful,exploit,Core,Canvas,Metasploit,MetasploitName\n')
        
        for x in iprep[ip]:

            if x[6] == 'True':
                canvas.append(x)
            elif x[7] == 'True':
                metasploit.append(x)                
            elif x[5] == 'True':
                core.append(x)
            elif x[4] == 'True':
                exploit.append(x)
                
        #iprep[ip] = sorted(iprep[ip], key=itemgetter(2, 0), reverse=True)

        canvas = sorted(canvas, key=itemgetter(6,2,1), reverse=True)
        metasploit = sorted(metasploit, key=itemgetter(7,2,1), reverse=True)
        core = sorted(core, key=itemgetter(5,2,1), reverse=True)
        exploit = sorted(exploit, key=itemgetter(2,0))

        
        for x in canvas:
            x = ','.join(x) + '\n'
            writefile.write(x)
        for x in metasploit:
            x = ','.join(x) + '\n'
            writefile.write(x)
        for x in core:
            x = ','.join(x) + '\n'
            writefile.write(x)
        for x in exploit:
            x = ','.join(x) + '\n'
            writefile.write(x)

        writefile.close()


        
"""
Begin main program
"""

evalargs()
loop_files()
report()
