extern crate export_resolver;

use export_resolver::ExportList;

fn main() {
    let mut exports = ExportList::new();

    match exports.add("ntdll.dll", "NtOpenProcess") {
        Ok(_) => println!("[+] Added NtOpenProcess"),
        Err(e) => eprintln!("[-] Did not add NtOpenProcess. {e}"),
    }

    match exports.add("ntdll.dll", "NtQuerySystemTime") {
        Ok(_) => println!("[+] Added NtQuerySystemTime"),
        Err(e) => eprintln!("[-] Did not add NtQuerySystemTime. {e}"),
    }

    match exports.get_function_address("NtOpenProcess") {
        Ok(v) => println!("NtOpenProcess address: {:#x}", v),
        Err(e) => eprintln!("Error: {}", e),
    }

    match exports.get_function_address("NtQuerySystemTime") {
        Ok(v) => println!("NtQuerySystemTime address: {:#x}", v),
        Err(e) => eprintln!("Error: {}", e),
    }

    match exports.add("ntdll.dll", "FFFFFFF") {
        Ok(_) => println!("[+] Added FFFFFFF"),
        Err(e) => eprintln!("[-] Error. {e}"),
    }

    match exports.add("fffff.dll", "NtQuerySystemTime") {
        Ok(_) => println!("[+] Found fffff.dll"),
        Err(e) => eprintln!("[-] Error. {e}"),
    }
}