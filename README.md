# Description

This tool is a simple PoC of how to hide memory artifacts using a ROP chain in combination with hardware breakpoints. The ROP chain will change the memory page's protections to N/A while sleeping (i.e. when the function Sleep is called). **x64 only**.

The idea is to set up a hardware breakpoint in kernel32!Sleep and a new top-level filter to handle the exception. When Sleep is called, the exception filter function set before takes control, allowing us to call the ROP chain without the need of using classic function hooks. This way, we avoid leaving weird and unusual private memory regions in the process related to well known dlls.

The ROP chain simply calls VirtualProtect() to set the current memory page to N/A, then calls SleepEx and finally restores the RX memory protection. This process repeats indefinitely.

![N/A memory protection is set while sleeping](/images/NA.png)

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\RustChain> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and run the tool:

	C:\Users\User\Desktop\RustChain> cargo build
	C:\Users\User\Desktop\RustChain\target\debug> rustchain.exe

# Limitations

This tool is just a PoC and some extra features should be implemented in order to be fully functional. The main purpose of the project was to learn how to implement a ROP chain and integrate it within Rust. Because of that, this tool will only work if you use it as it is, and failures are expected if you try to use it in other ways (for example, compiling it to a dll and trying to reflectively load and execute it).

