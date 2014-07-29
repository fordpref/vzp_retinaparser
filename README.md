vzp_retinaparser
================

Retina produces two reports that are brutally useful for analysts but could use some reformatting and hefty occam's razor to get useful info from.

vzp-vulnexp-macro.bas


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
 
  

remediation.py

Usage:
python remediation.py <input.mht filename>
remediation.exe <input.mht filename>
asks for a report name and outputs to csv.

1.  in Retina, go to remediation tab
2.  generate the report for each job you want to parse
3.  save each job as a single file html document (.mht)
4.  if you need to save out multiple mht files (and why not?) no worries.

    a.  open a command prompt, go to the directory your mht files are in.

    b.  cat *.mht >> <lumped file name>  (don't give it an extension unless you want to learn about recursion)

    c.  give the new lump file an mht extension

5.  run remediation.exe <lumped file name>.mht
6.  This will produce a .csv you open with excel, it asks for a file name and saves it.
7.  I recommend that you add two columns, one for client/network exploit, and another for product.  Update it manually.




Using the remediation tab in Retina, you can export a remediation report on each scan out to an MHT file.  The remediation.py script is a python script that will parse the data and produce a table in html (poorly) and csv that lists the CVEs found that have an exploit in Core Impact or Metasploit, which of  Core Impact or Metasploit have an exploit module for it (or both), how many systems are potentially affected, and what the IP addresses of those systems are.  This is useful for showing the accuracy or Retina and the protection capability of your AV/HIPS/etc.  Once the exploitation is done, go back through to see how many vulnerabilities retina reported that were not actually exploitable (false positives) and how many vulnerabilities that were successfully exploited that retina didn't report on (false negatives).  The results are pleasing, exciting, and surprising.

I have to output many remediation reports, which leads to a lot of .mht files.  The script is setup that it doesn't care about the html formatting, so I cat the files into one with:  'cat *.mht >> output'.  I then rename the output file to a .mht and use it for parsing.  This way I can take all the scans and get one report file that is useful for my needs.

I take the csv output and open with a spreadsheet editor.  I'll sort the data first by core exploit and then by metasploit exploit and color code those 'yes' lines.  I'll add a column so I can disposition each vulnerablity as client or network.  Then I'll add another column to show whether the exploit was successful or not.  I use this as a checksheet for my workflow to document where I am and to remember what worked.
