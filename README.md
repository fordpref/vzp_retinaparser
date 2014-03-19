vzp_retinaparser
================

Retina produces two reports that are brutally useful for analysts but could use some reformatting and hefty occam's razor to get useful info from.

vzp-vulnexp-macro.bas
If you go to the report tab in retina, choose vulnerability export, and save the retina scans out to xml, you can import those xml files into Excel.  the vzp-vulnexp-macro.bas is an Excel macro to auto color, format, and sort using 4 different fields and making 4 different worksheets to help get solid data output, analysis, and numbers.
  -Just import the bas file into Excel with the vulnerability export report xml loaded.
  -outputs are then sorted first by category of finding, then by findings per IP address, then by exploit available/cat, then by IAVA.
  

remediation.py
Using the remediation tab in Retina, you can export a remediation report on each scan out to an MHT file.  The remediation.py script is a python script that will parse the data and produce a table in html (poorly) and csv that lists the CVEs found that have an exploit in Core Impact or Metasploit, which of  Core Impact or Metasploit have an exploit module for it (or both), how many systems are potentially affected, and what the IP addresses of those systems are.  This is useful for showing the accuracy or Retina and the protection capability of your AV/HIPS/etc.  Once the exploitation is done, go back through to see how many vulnerabilities retina reported that were not actually exploitable (false positives) and how many vulnerabilities that were successfully exploited that retina didn't report on (false negatives).  The results are pleasing, exciting, and surprising.
