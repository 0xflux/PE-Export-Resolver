# PE Export Resolver

This tool is a cyber security library to resolve function pointers to loaded modules in memory, such as functions provided by Windows DLL's (or any other DLL with exported functions). May only be used where you have legal permission from the system owner to use this. 

# Usage

 - The library is instantiated with `::new()`.
 - When you wish to use a pointer to the required function in your code, you can simply use `.add` to resolve that function at runtime, it will then append the function virtual address to a vector of your resolved exports (all added with the `.add` function)
 - To then get the function pointer, you can use the `get_function_address` function, which will return an Result of a `usize`, where the usize is the memory address.
 - Valid only for x64.

# Example

```Rust
fn main() {
    // Create a new instance of the ExportList
    let mut exports = ExportList::new();
    
    // Add the desired functions to the ExportList structure, this will resolve and save the virtual addresses
    // These calls may cause an Error if the function cannot be found; .add returns Result<(), ExportError>
    let _ = exports.add("ntdll.dll", "NtOpenProcess");
    let _ = exports.add("ntdll.dll", "NtQuerySystemTime");

    // Attempt to get the virtual address; returns returns Result<(), ExportError> - an error will be returned where
    // the input function name cannot be found in the vector of resolved functions (i.e. if the above step failed)
    // or you have a typo.
    let _nt = match exports.get_function_address("NtOpenProcess") {
        Ok(v) => println!("NT: {:x}", v),
        Err(e) => println!("Eeee {}", e),
    };
}
```

# LEGAL DISCLAIMER 

This project, including all associated source code and documentation, is developed and shared solely for educational, research, and defensive purposes in the field of cybersecurity. It is intended to be used exclusively by cybersecurity professionals, researchers, and educators to enhance understanding, develop defensive strategies, and improve security postures.

Under no circumstances shall this project be used for criminal, unethical, or any other unauthorized activities. This is meant to serve as a resource for learning and should not be employed for offensive operations or actions that infringe upon any individual's or organization's rights or privacy.

The author of this project disclaims any responsibility for misuse or illegal application of the material provided herein. By accessing, studying, or using this project, you acknowledge and agree to use the information contained within strictly for lawful purposes and in a manner that is consistent with ethical guidelines and applicable laws and regulations.

USE AT YOUR OWN RISK. If you decide to use this software CONDUCT A THOROUGH INDEPENDENT CODE REVIEW to ensure it meets your standards. No unofficial third party dependencies are included to minimise attack surface of a supply chain risk. I cannot be held responsible for any problems that arise as a result of executing this, the burden is on the user of the software to validate its safety & integrity. All care has been taken to write safe code.

It is the user's responsibility to comply with all relevant local, state, national, and international laws and regulations related to cybersecurity and the use of such tools and information. If you are unsure about the legal implications of using or studying the material provided in this project, please consult with a legal professional before proceeding. Remember, responsible and ethical behavior is paramount in cybersecurity research and practice. The knowledge and tools shared in this project are provided in good faith to contribute positively to the cybersecurity community, and I trust they will be used with the utmost integrity.

This project will ONLY work on certain architectures (x64) by design so it is not an 'out of the box' offensive tool (**responsible contribution** to the security community).