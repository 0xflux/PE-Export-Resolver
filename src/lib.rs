use std::arch::asm;
use std::ops::Add;
use std::os::windows::ffi::OsStringExt;
use std::slice::from_raw_parts;
use std::ffi::{c_void, OsString};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use std::fmt;

/// A structure containing the module name, function name, and export address for each function loaded
/// into the portable executable on x64 systems only.
struct ExportResolver<'a> {
    module: &'a str,
    function: &'a str,
    address: usize,
}

#[derive(Debug)]
/// A list of module names, function names, and function export addresses of the respective function
/// within the memory space of the process this is called from. 
/// 
/// <section class="warning">
/// *IMPORTANT:* This tool may only be used for ethical, research or legal purposes. There is a massive learning benefit
/// to exploring this tool, or using it as part of a debugging process when reverse engineering malware or other tools.
/// 
/// This tool may also be used for red teamer's and penetration testers where you have the LAWFUL AUTHORITY to use this tool,
/// such as on a red team client engagement. In no way may this be used for illegal activity.
/// 
/// Tool only works on x64 by design.
/// </section>
pub struct ExportList<'a> {
    list: Vec<ExportResolver<'a>>,
}

impl fmt::Debug for ExportResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportResolver {{ module: \"{}\", function: \"{}\", address: {:#x} }}",
            self.module, self.function, self.address
        )
    }
}

#[derive(Debug)]
pub enum ExportError {
    FunctionNotFound { module: String, function: String },
    FunctionNotInList { function: String },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::FunctionNotFound { module, function } => {
                write!(f, "Failed to get function address for {} in {}", function, module)
            },

            ExportError::FunctionNotInList { function } => {
                write!(f, "Function {} could not be found in the list of resolved functions, are you sure it's there?.", function)
            }
        }
    }
}

impl std::error::Error for ExportError {}

impl<'a> ExportList<'a> {

    /// Instantiate a new instance of the export list
    pub fn new() -> ExportList<'a> {
        ExportList {
            list: Vec::new()
        }
    }

    /// Add a new function to the list which will use the module name and function name to
    /// find the memory address of hte function within the export address table.
    /// 
    /// # Returns
    /// 
    /// The function operates on its own instance, but will return a result of the unit type, or an ExportError.
    /// 
    /// <section class="warning">
    /// This will only work for x64, and there is no guarantee the addresses will always be valid.
    /// </section>
    pub fn add(&mut self, module: &'a str, function: &'a str) -> Result<(), ExportError> {

        let fn_address = get_function_from_exports(module, function)
        .ok_or_else(|| ExportError::FunctionNotFound {
            module: module.to_string(),
            function: function.to_string(),
        })?;

        self.list.push(ExportResolver {
            module,
            function,
            address: fn_address as usize,
        });

        Ok(())
    } 

    /// Get the function address of a function you have added to the vector of exports as a usize. This
    /// may be converted to a *const c_void if required to be used as a raw pointer.
    /// 
    /// <section class="warning">
    /// This will only work for x64, and there is no guarantee the addresses will always be valid.
    /// </section>
    pub fn get_function_address(&self, function_name: &str) -> Result<usize, ExportError> {

        self.list
            .iter()
            .find(|f| f.function == function_name)
            .map(|f| f.address)
            .ok_or_else(|| ExportError::FunctionNotInList {
                function: function_name.to_string(),
            })
    }

}

/// Get the base address of a specified module. Obtains the base address by reading from the TEB -> PEB -> 
/// PEB_LDR_DATA -> InMemoryOrderModuleList -> InMemoryOrderLinks -> DllBase 
/// 
/// Returns the DLL base address as a Option<usize> 
#[allow(unused_variables)]
#[allow(unused_assignments)]
fn get_module_base(module_name: &str) -> Option<usize> {

    let mut peb: usize;
    let mut ldr: usize;
    let mut in_memory_order_module_list: usize;
    let mut current_entry: usize;

    unsafe {
        // get the peb and module list
        asm!(
            "mov {peb}, gs:[0x60]",
            "mov {ldr}, [{peb} + 0x18]",
            "mov {in_memory_order_module_list}, [{ldr} + 0x10]", // points to the Flink
            peb = out(reg) peb,
            ldr = out(reg) ldr,
            in_memory_order_module_list = out(reg) in_memory_order_module_list,
        );

        // set the current entry to the head of the list
        current_entry = in_memory_order_module_list;
        
        // iterate the modules searching for 
        loop {
            // get the attributes we are after of the current entry
            let dll_base = *(current_entry.add(0x30) as *const usize);
            let module_name_address = *(current_entry.add(0x60) as *const usize);
            let module_length = *(current_entry.add(0x58) as *const u16);
            
            // check if the module name address is valid and not zero
            if module_name_address != 0 && module_length > 0 {
                // read the module name from memory
                let dll_name_slice = from_raw_parts(module_name_address as *const u16, (module_length / 2) as usize);
                let dll_name = OsString::from_wide(dll_name_slice);

                // do we have a match on the module name?
                if dll_name.to_string_lossy().eq_ignore_ascii_case(module_name) {
                    return Some(dll_base);
                }

            } else {
                println!("Invalid module name address or length.");
            }

            // dereference current_entry which contains the value of the next LDR_DATA_TABLE_ENTRY (specifically a pointer to LIST_ENTRY 
            // within the next LDR_DATA_TABLE_ENTRY)
            current_entry = *(current_entry as *const usize);

            // If we have looped back to the start, break
            if current_entry == in_memory_order_module_list {
                return None;
            }
        }
    }
}

/// Get the function address of a function in a specified DLL from the DLL Base.
/// 
/// # Parameters 
/// * dll_name -> the name of the DLL / module you are wanting to query
/// * needle -> the function name (case sensitive) of the function you are looking for
/// 
/// # Returns
/// Option<*const c_void> -> the function address as a pointer
fn get_function_from_exports(dll_name: &str, needle: &str) -> Option<*const c_void> {

    // get the dll base address
    let dll_base = match get_module_base(dll_name) {
        Some(a) => a,
        None => panic!("Unable to get address"),
    } as *mut c_void;

    // check we match the DOS header, cast as pointer to tell the compiler to treat the memory
    // address as if it were a IMAGE_DOS_HEADER structure
    let dos_header: IMAGE_DOS_HEADER = unsafe { read_memory(dll_base as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    // check the NT headers
    let nt_headers = unsafe { read_memory(dll_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64) };
    if nt_headers.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // get the export directory
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
    // found from first item in the DataDirectory; then we take the structure in memory at dll_base + RVA
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    let export_offset = unsafe {dll_base.add(export_dir_rva as usize) };
    let export_dir: IMAGE_EXPORT_DIRECTORY = unsafe { read_memory(export_offset as *const IMAGE_EXPORT_DIRECTORY) };
    
    // get the addresses we need
    let address_of_functions_rva = export_dir.AddressOfFunctions as usize;
    let address_of_names_rva = export_dir.AddressOfNames as usize;
    let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;

    let functions = unsafe { dll_base.add(address_of_functions_rva as usize) } as *const u32;
    let names = unsafe { dll_base.add(address_of_names_rva as usize) } as *const u32;
    let ordinals = unsafe { dll_base.add(ordinals_rva as usize) } as *const u16;

    // get the amount of names to iterate over
    let number_of_names = export_dir.NumberOfNames;

    for i in 0..number_of_names {
        // calculate the RVA of the function name
        let name_rva = unsafe { *names.offset(i.try_into().unwrap()) as usize };
        // actual memory address of the function name
        let name_addr = unsafe { dll_base.add(name_rva) };
        
        // read the function name
        let function_name = unsafe {
            let char = name_addr as *const u8;
            let mut len = 0;
            // iterate over the memory until a null terminator is found
            while *char.add(len) != 0 {
                len += 1;
            }

            std::slice::from_raw_parts(char, len)
        };

        let function_name = std::str::from_utf8(function_name).unwrap_or("Invalid UTF-8");
        if function_name.eq("Invalid UTF-8") {
            return None;
        }

        // if we have a match on our function name
        if function_name.eq(needle) {

            // calculate the RVA of the function address
            let ordinal = unsafe { *ordinals.offset(i.try_into().unwrap()) as usize };
            let fn_rva = unsafe { *functions.add(ordinal) as usize };
            // actual memory address of the function address
            let fn_addr = unsafe { dll_base.add(fn_rva) } as *const c_void;

            return Some(fn_addr);
        }
    }

    None
}

/// Read memory of any type
unsafe fn read_memory<T>(address: *const T) -> T {
    std::ptr::read(address)
}