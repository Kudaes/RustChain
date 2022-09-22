#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::{ptr::copy_nonoverlapping, mem::size_of, ffi::c_void};

use bindings::Windows::Win32::{System::{Diagnostics::Debug::{IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER}, Memory::MEMORY_BASIC_INFORMATION, SystemInformation::SYSTEM_INFO, Threading::GetCurrentProcess}};
use data::{IMAGE_FILE_HEADER, PeMetadata, IMAGE_OPTIONAL_HEADER64, EXCEPTION_POINTERS};

extern "C"
{
    fn PrepareAndRop(address: *const c_void, size: usize, protection: u32, old: *mut u32, virtual_protect: *mut c_void,
                    gag1_addr: *mut c_void, gag2_addr: *mut c_void, gag3_addr: *mut c_void, gag4_addr: *mut c_void, gag5_addr: *mut c_void,
                    sleep_addr: *mut c_void) -> bool;
}

#[no_mangle]
pub extern "Rust" fn start() 
{
    unsafe
    {
        loop 
        {
            let k32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));
            let sleep_addr = dinvoke::get_function_address(k32, &lc!("Sleep")) as *mut c_void;
            let handler = breakpoint_handler as usize;
            dinvoke::set_unhandled_exception_filter(handler);
            dinvoke::set_hardware_breakpoint(sleep_addr as usize);
    
            let f:data::Sleep;
            let _r: Option<()>;
            println!("[ZzZ] Sleeping...");
            dinvoke::dynamic_invoke!(k32,&lc!("Sleep"),f,_r,15000);
            println!("  \\ We are back!");
            println!("--------------------------");
        }
    }
   
}

/// This function acts as an Exception Handler, and should be combined with a hardware breakpoint.
///
/// Whenever the HB gets triggered, this function will be executed. 
pub unsafe extern "system" fn breakpoint_handler (exceptioninfo: *mut EXCEPTION_POINTERS) -> i32
{
    if (*(*(exceptioninfo)).exception_record).ExceptionCode.0 == 0x80000004 // STATUS_SINGLE_STEP
    {
        if ((*(*exceptioninfo).context_record).Dr7 & 1) == 1
        {
            if (*(*exceptioninfo).context_record).Rip == (*(*exceptioninfo).context_record).Dr0
            {
                (*(*exceptioninfo).context_record).Dr0 = 0; // Remove the breakpoint

                let gadget_1: [u8;2] = [0x59, 0xc3]; // pop rcx; ret;
                let gadget_2: [u8;4] = [0x5A, 0x41, 0x5B, 0xc3]; // pop rdx; pop r11; ret;
                let gadget_3: [u8;3] = [0x41, 0x58, 0xc3]; // pop r8; ret;
                let gadget_4: [u8;7] = [0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3]; // pop r9; pop r10; pop r11; ret;
                let gadget_5: [u8;5] = [0x48, 0x83, 0xC4, 0x28, 0xC3]; // add rsp, 0x28; ret;
                let mut gag1_addr = 0usize;
                let mut gag2_addr = 0usize;
                let mut gag3_addr = 0usize;
                let mut gag4_addr = 0usize;
                let mut gag5_addr = 0usize;
                let main_address = start as usize;
                let ntdll = dinvoke::get_module_base_address(&lc!("ntdll.dll"));
                let ba: *const u8 =  std::mem::transmute(ntdll);
                let pe_info = get_pe_metadata(ba).unwrap();

                for section in pe_info.sections
                {   
                    let s = std::str::from_utf8(&section.Name).unwrap();
                    if s.contains(".text")
                    {
                        let dst: Vec<u8> =vec![0;section.Misc.VirtualSize as usize];
                        let dir = ntdll as i64 + section.VirtualAddress as i64;
                        copy_nonoverlapping((dir as isize) as *mut u8, dst.as_ptr() as *mut u8, section.Misc.VirtualSize as usize);
                        
                        gag1_addr = ntdll as usize + section.VirtualAddress as usize + 
                                            get_gadget_offset(
                                                dst.as_ptr() as *const u8, 
                                                section.Misc.VirtualSize, 
                                                gadget_1.as_ptr(), 
                                                gadget_1.len());
                        gag2_addr = ntdll as usize + section.VirtualAddress as usize + 
                                            get_gadget_offset(
                                                dst.as_ptr() as *const u8, 
                                                section.Misc.VirtualSize, 
                                                gadget_2.as_ptr(), 
                                                gadget_2.len());
                        gag3_addr = ntdll as usize + section.VirtualAddress as usize + 
                                            get_gadget_offset(
                                                dst.as_ptr() as *const u8, 
                                                section.Misc.VirtualSize, 
                                                gadget_3.as_ptr(), 
                                                gadget_3.len());
                        gag4_addr = ntdll as usize + section.VirtualAddress as usize + 
                                            get_gadget_offset(
                                                dst.as_ptr() as *const u8, 
                                                section.Misc.VirtualSize, 
                                                gadget_4.as_ptr(), 
                                                gadget_4.len());
                        gag5_addr = ntdll as usize + section.VirtualAddress as usize + 
                                            get_gadget_offset(
                                                dst.as_ptr() as *const u8, 
                                                section.Misc.VirtualSize, 
                                                gadget_5.as_ptr(), 
                                                gadget_5.len());                        
                        
                    }
                }

                if gag1_addr == 0 || gag2_addr == 0 || gag3_addr == 0 || gag4_addr == 0 || gag5_addr == 0
                {
                    println!("{}", &lc!("[x] Gadget not found."));
                    return -1;
                }

                let b = vec![0u8; size_of::<SYSTEM_INFO>()];
                let si: *mut SYSTEM_INFO = std::mem::transmute(b.as_ptr());
                dinvoke::get_system_info(si);
                
                let mut mem = 0usize;
                let max = (*si).lpMaximumApplicationAddress as usize;
                let mut page = 0usize;
                let mut page_length = 0usize;
                while mem < max
                {
                    let buffer = vec![0u8; size_of::<MEMORY_BASIC_INFORMATION>()];
                    let buffer: *mut MEMORY_BASIC_INFORMATION = std::mem::transmute(buffer.as_ptr());
                    let length = size_of::<MEMORY_BASIC_INFORMATION>();
                    let _r = dinvoke::virtual_query_ex(
                        GetCurrentProcess(), 
                        mem as *const c_void, 
                        buffer, 
                        length
                    );
                    
                    if main_address >= ((*buffer).BaseAddress as usize) && main_address <= ((*buffer).BaseAddress as usize + (*buffer).RegionSize )
                    {
                        page = (*buffer).BaseAddress as usize;
                        page_length = (*buffer).RegionSize;
                        break;
                    }

                    mem = (*buffer).BaseAddress as usize + (*buffer).RegionSize;

                }
                
            
                let k32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));
                let virtual_protect_addr = dinvoke::get_function_address(k32, &lc!("VirtualProtect")) as *mut c_void;
                let sleep_addr = dinvoke::get_function_address(k32, &lc!("SleepEx")) as *mut c_void;
                let address = page as *const c_void;
                let protection = 0x1u32; // PAGE_NOACCESS
                let old = 0u32;
                let old_protection: *mut u32 = std::mem::transmute(&old);
                (*(*exceptioninfo).context_record).Rcx = 0; // We replace the original call parameter, avoiding sleeping twice
                
                let _exit = PrepareAndRop(
                    address, 
                    page_length, 
                    protection, 
                    old_protection, 
                    virtual_protect_addr, 
                    gag1_addr as *mut c_void, 
                    gag2_addr as *mut c_void, 
                    gag3_addr as *mut c_void, 
                    gag4_addr as *mut c_void,
                    gag5_addr as *mut c_void,
                    sleep_addr
                ); 
            }
        }
        return -1; // EXCEPTION_CONTINUE_EXECUTION
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}


fn get_gadget_offset(base_address: *const u8, section_size: u32,  gadget: *const u8, gadget_len: usize) -> usize
{   
    unsafe
    {
        let mut found = false;
        let mut ptr = base_address;
        for i in 0..section_size as usize
        { 
            for j in 0..gadget_len
            {
                let t = ptr.add(j); 
                let temp_1 = *(t);
                let t2 = gadget.add(j); 
                let temp_2 = *(t2);
                if temp_1 == temp_2
                {
                    if found && j as i32 == (gadget_len as i32 - 1)
                    {
                        let offset = base_address.add(i) as usize - base_address as usize;
                        return offset;
                    }

                    found = true;
                }
                else 
                {
                    found = false;   
                    break;
                }
            }

            ptr = ptr.add(1);

        }
    }  

    0
}

/// Retrieves PE headers information from the module base address.
///
/// It will return either a data::PeMetada struct containing the PE
/// metadata or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let file_content = fs::read("c:\\windows\\system32\\ntdll.dll").expect("[x] Error opening the specified file.");
/// let file_content_ptr = file_content.as_ptr();
/// let result = manualmap::get_pe_metadata(file_content_ptr);
/// ```
pub fn get_pe_metadata (module_ptr: *const u8) -> Result<PeMetadata,String> {
    
    let mut pe_metadata= PeMetadata::default();

    unsafe {

        let e_lfanew = *((module_ptr as u64 + 0x3C) as *const u32);
        pe_metadata.pe = *((module_ptr as u64 + e_lfanew as u64) as *const u32);

        if pe_metadata.pe != 0x4550 
        {
            return Err(lc!("[x] Invalid PE signature."));
        }

        pe_metadata.image_file_header = *((module_ptr as u64 + e_lfanew as u64 + 0x4) as *mut IMAGE_FILE_HEADER);

        let opt_header: *const u16 = (module_ptr as u64 + e_lfanew as u64 + 0x18) as *const u16; 
        let pe_arch = *(opt_header);

        if pe_arch == 0x010B
        {
            pe_metadata.is_32_bit = true;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER32 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_32 = *opt_header_content;
        }
        else if pe_arch == 0x020B 
        {
            pe_metadata.is_32_bit = false;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER64 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else 
        {
            return Err(lc!("[x] Invalid magic value."));
        }

        let mut sections: Vec<IMAGE_SECTION_HEADER> = vec![];

        for i in 0..pe_metadata.image_file_header.number_of_sections
        {
            let section_ptr = (opt_header as u64 + pe_metadata.image_file_header.size_of_optional_header as u64 + (i * 0x28) as u64) as *const u8;
            let section_ptr: *const IMAGE_SECTION_HEADER = std::mem::transmute(section_ptr);
            sections.push(*section_ptr);
        }

        pe_metadata.sections = sections;

        Ok(pe_metadata)
    }
}
