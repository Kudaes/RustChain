# Description

This tool is a simple PoC of how to hide memory artifacts using a ROP chain in combination with hardware breakpoints. The ROP chain will change the main module memory page's protections to N/A while sleeping (i.e. when the function Sleep is called). For more detailed information about this memory scanning evasion technique check out the original project [Gargoyle](https://github.com/JLospinoso/gargoyle). **x64 only**.

The idea is to set up a hardware breakpoint in kernel32!Sleep and a new top-level filter to handle the exception. When Sleep is called, the exception filter function set before is triggered, allowing us to call the ROP chain without the need of using classic function hooks. This way, we avoid leaving weird and unusual private memory regions in the process related to well known dlls.

The ROP chain simply calls VirtualProtect() to set the current memory page to N/A, then calls SleepEx and finally restores the RX memory protection. 

The overview of the process is as follows:
* We use SetUnhandledExceptionFilter to set a new exception filter function.
* SetThreadContext is used in order to set a hardware breakpoint on kernel32!Sleep.
* We call Sleep, triggering the hardware breakpoint and driving the execution flow towards our exception filter function.
* The ROP chain is called from the exception filter function, allowing to change the current memory page protection to N/A. Then SleepEx is called. Finally, the ROP chain restores the RX memory protection and the normal execution continues.

This process repeats indefinitely.

As it can be seen in the image, the main module's memory protection is changed to N/A while sleeping, which avoids memory scans looking for pages with execution permission. 

![N/A memory protection is set while sleeping](/images/NA.png "N/A memory protection is set while sleeping")

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\RustChain> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and run the tool:

	C:\Users\User\Desktop\RustChain> cargo build
	C:\Users\User\Desktop\RustChain\target\debug> rustchain.exe

# Limitations

This tool is just a PoC and some extra features should be implemented in order to be fully functional. The main purpose of the project was to learn how to implement a ROP chain and integrate it within Rust. Because of that, this tool will only work if you use it as it is, and failures are expected if you try to use it in other ways (for example, compiling it to a dll and trying to reflectively load and execute it).

# Credits

* [@thefLinkk](https://twitter.com/thefLinkk) for his [DeepSleep](https://github.com/thefLink/DeepSleep) project that inspired me to create this tool.
