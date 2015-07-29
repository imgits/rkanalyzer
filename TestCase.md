# Testcases #

Here I offer two testcases which can represent some popular techniques used in rootkits today. RKAnalyzer can detect these actions and show them to analyzers as understandable representations.

**Make sure you HAD Already set up the [Probe](http://code.google.com/p/rkanalyzer/wiki/Probes) before test with rootkits**

### Case 1: SSDT Hooking ###

Sample code is here: http://code.google.com/p/rkanalyzer/source/browse/testcase/TestAccessSSDT/Main.cpp

Checkout the TestAccessSSDT Directory and build under DDK. Load the driver, and you will see the following in serial Terminal:
![http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-SSDT.png](http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-SSDT.png)

Ignore other debug informations, just notice the area with red rectangle. The rookit's attempt to write the SSDT is intercepted and reported. RKAnalyzer can even show which entry of SSDT is being written, and the exact value the rootkit is going to assign.

### Case 2: MDL Attacking ###

Sample code is here: http://code.google.com/p/rkanalyzer/source/browse/testcase/SSDTMDL/Main.cpp

MDL attack is much more dangerous than directly SSDT hooking, as the rootkit use another VA instead of the SSDT pointer exported by windows kernel, so it's hard to detect. RKAnalyzer can detect it.

Checkout the SSDTMDL Directory and build under DDK. Load the driver, and you will see the following in serial Terminal:
![http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-MDL.png](http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-MDL.png)

The information in the red rectangle shows the rootkit's attempt to map the SSDT's physical page to a new VA. The information in the blue rectangle shows that RKAnalyzer intercepted the write attempt even if the rootkit used MDL attacking method.