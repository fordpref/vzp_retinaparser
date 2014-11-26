vzp_vulnscan_parsers
====================

I work with a few different reports from Retina and Nessus.  In their default state, neither are really immediately useful for penetration testing.  So I've tried to put together a few things that help me reformat the output and get to what is most important to me, what can I exploit, and how do I help the customer prioritize their remediation efforts?

retinamacro.bas - Just an Excel macro to reformat Retina's Vulnerability Export report .xml file.

retina.py/.exe -    Python script for pentesters to take Retina's Remediation report to .mht and show CVE's with exploits and what frameworks have working exploits.

nessus.py/.exe -    Python script for pentesters to take Nessus .nessus xml and show CVE's with exploits and what frameworks have working exploits.



nessus.py
Usage:
Linux:
python nessus.py
Windows:
nessus.exe

It asks for the directory, and then a report name.  It will output a CSV file
that you can open in libreoffice or excel.  Right now it sorts by canvas then remote/local,
metasploit then remote/local, Core Impact then remote/local, then just exploits remote/local.
Working on asking for sort order and a way to update keywords to disposition the vulnerabilities
as local or remote.  Should be coming soon.  Going to try to do the same with the retina reports.





retinamacro.bas


If you go to the report tab in retina, choose vulnerability export, and save the retina scans out to xml, you can import those xml files into Excel.  the vzp-vulnexp-macro.bas is an Excel macro to auto color, format, and sort using 4 different fields and making 4 different worksheets to help get solid data output, analysis, and numbers.
  -Just import the bas file into Excel with the vulnerability export report xml loaded.
  -outputs are then sorted first by category of finding, then by findings per IP address, then by exploit available/cat, then by IAVA.
 
1.  in retina open reports tab.
2.  select vulnerability export report
3.  export to an xml file
4.  open xml in excel
5.  import vzp-vulnexp-macro.bas in as a macro
6.  run the macro on the sheet
7.  save as xlsx file
8.  creates four worksheets sorted and color coded to make analysis easier
 
  




retina.py

Usage:
python retina.py inputfilename.mht
remediation.exe inputfilename.mht
asks for a report name and outputs to csv.

1.  in Retina, go to remediation tab
2.  generate the report for each job you want to parse
3.  save each job as a single file html document (.mht)
4.  if you need to save out multiple mht files (and why not?) no worries.

    a.  open a command prompt, go to the directory your mht files are in.

    b.  cat *.mht >> lumpedfilename  (don't give it an extension unless you want to learn about recursion)

    c.  give the new lump file an mht extension

5.  run remediation.exe lumpedfilename.mht
6.  This will produce a .csv you open with excel, it asks for a file name and saves it.
7.  I recommend that you add two columns, one for client/network exploit, and another for product.  Update it manually.




Using the remediation tab in Retina, you can export a remediation report on each scan out to an MHT file.  The retina.py script is a python script that will parse the data and produce a table in html (poorly) and csv that lists the CVEs found that have an exploit in Core Impact or Metasploit, which of  Core Impact or Metasploit have an exploit module for it (or both), how many systems are potentially affected, and what the IP addresses of those systems are.  This is useful for showing the accuracy or Retina and the protection capability of your AV/HIPS/etc.  Once the exploitation is done, go back through to see how many vulnerabilities retina reported that were not actually exploitable (false positives) and how many vulnerabilities that were successfully exploited that retina didn't report on (false negatives).  The results are pleasing, exciting, and surprising.

I have to output many remediation reports, which leads to a lot of .mht files.  The script is setup that it doesn't care about the html formatting, so I cat the files into one with:  'cat *.mht >> output'.  I then rename the output file to a .mht and use it for parsing.  This way I can take all the scans and get one report file that is useful for my needs.

I take the csv output and open with a spreadsheet editor.  I'll sort the data first by core exploit and then by metasploit exploit and color code those 'yes' lines.  I'll add a column so I can disposition each vulnerablity as client or network.  Then I'll add another column to show whether the exploit was successful or not.  I use this as a checksheet for my workflow to document where I am and to remember what worked.




nessus.py/exe readme
====================

Usage:

python nessus.py \<path-to-nessus-reports\> \<report output name\>.csv
nessus.exe \<path-to-nessus-reports\> \<report output name\>.csv


It will check the path and report name, then parse all the .nessus files in the directory you specify and output a .csv file.

It will ask you to evaluate each exploitable finding on whether it is a network facing exploit (ie, service, no user interaction) or whether it is a client side/local exploit (ie must already be on the system or have user go to website or open file).

the CSV file lists the CVEs from the nessus report file that have exploits available, what exploit frameworks have them, and what IPs are affected.  The output also includes a column for you to track whether you successfully exploited the finding or not.
