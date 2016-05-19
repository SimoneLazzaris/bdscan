# dbscan
## A simple backdoor scanner for php sites

I have to deal often (well, more often that I'd like) with php sites infected with malicious software,
mostly of the "backdoor" style.

I've noted that there are repeating patterns in the malware that is injected in the php files, so
I decided to write a simple scanner. The first version, in python, only scanned for a list of
regulare expression. In order to achieve more speed, I've decided to recode the scanner in C
and to put a pre-filter in front of the time-consuming (and CPU intensive) regex scan, searching for
a simple static keyword that will trigger the more detailed regex scan.

So this scanner simply process recursively a directory searching for .php files. For every line
in those file, a list of keyword is searched. If any those keyword matches, the scanner run the matching
regex scan and, eventually, record the match printing out the "name" of the rule triggered, the file name and
the line number.

In order to easly update the list of rules, I decided to fetch via HTTP the list from a central server.


