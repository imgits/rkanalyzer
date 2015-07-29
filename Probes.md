To obtain guest OS information which is crucial to rootkit analysis, a probe is needed. Probe is usually a kernel module or kernel driver.

Currently the following probe is supplied:

### Probe For Windows(2K, XP, 2003) ###

  * Checkout the probe code from svn: http://rkanalyzer.googlecode.com/svn/probes/win32
  * Build it with DDK environment
  * Use tools(InstDrv or something alike) to load the probe module into the kernel, and you will see the following in the serial terminal:
> ![http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-rka-probe-win32.png](http://rkanalyzer.googlecode.com/svn/wiki/Screenshot-rka-probe-win32.png)
  * Now the probe has done its work. You can [test with your rootkit](http://code.google.com/p/rkanalyzer/wiki/TestCase) now!