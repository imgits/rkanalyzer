# RKAnalyzer #
RKAnalyzer is a kernel level rootkit analyzer and defender using Hardware Virtualization Techniques, based on the BitVisor Project(A VMM developed by Tsukuba University and open-sourced under BSD License).

It tries to monitor kernel level rootkits' actions and log them. What differs RKAnalyzer with tranditional detection softwares(i.e. [Rootkit Revealer](http://technet.microsoft.com/en-us/sysinternals/bb897445.aspx), [IceSword](http://www.antirootkit.com/software/IceSword.htm)) is that RKAnalyzer actively intercepts rootkit actions, rather than reacting to rootkit after already infected. Also, RKAnalyzer support analysis mode, which differs from defend mode by presenting a much more transparent environment, in which rootkit would consider itself running without being monitored.

# Updates #
  * **2009.12.22** Realtime protection against DKOM added!!! Now FuTo will fail under RKAnalyzer, huh:)

# How To Use #
  * [Installation and Bootup Guide](http://code.google.com/p/rkanalyzer/wiki/HowToUse)
  * [Build and Load Probes](http://code.google.com/p/rkanalyzer/wiki/Probes)
  * [Test with practical rootkits!](http://code.google.com/p/rkanalyzer/wiki/TestCase)

# SOLVED issues #
  * Critical Static Data Area Protection(Optimized to work under MP Systems)
  * Kernel Symbol Parsing
  * Memory Mapping Attacks(MDL attacks in Windows)

# TODO issues #
  * Improve DKOM Protections
  * Better method to identify malicious memory access from normal memory access