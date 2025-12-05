// Import the io module from Rust's standard library
use std::io;

// Function that reads user input and returns it as a Result<String>
// Returns Result because IO operations can fail
fn get_string() -> io::Result<String> {
    // Create an empty String to use as a temporary buffer
    let mut buffer = String::new();
    
    // Get a handle to stdin (the OS's input stream) and read a line into our buffer
    // Pass &mut buffer so read_line can write to it
    // The ? operator handles the Result: if Ok, continue; if Err, return early with the error
    io::stdin().read_line(&mut buffer)?;
    
    // Wrap buffer in Ok() to match our Result<String> return type
    // This is the success case - we got the input successfully
    Ok(buffer)
}

fn main() {
    // Loop forever to keep echoing input
    loop {
        // Call get_string() which returns Result<String>
        // unwrap() extracts the String from Ok() or panics if there's an error
        let result = get_string().unwrap();
        
        // Print the result, using trim() to remove the newline character that Enter adds
        println!("{}", result.trim());
    }
}