use libinjectionrs::xss::{Html5State, Html5Flags};

fn main() {
    let input = "<foo          >";
    let input_bytes = input.as_bytes();
    
    println!("Input: {}", input);
    
    // Test with data state (standard HTML context)
    let mut html5 = Html5State::new(input_bytes, Html5Flags::DataState);
    
    let mut count = 0;
    while html5.next() {
        count += 1;
        if count > 10 {
            println!("Breaking due to too many iterations");
            break;
        }
        
        let data = if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
            std::str::from_utf8(&html5.token_start[..html5.token_len])
                .unwrap_or("<invalid utf8>")
        } else {
            "<empty>"
        };
        
        println!("Token #{}: {},{},{}", count, html5.token_type, html5.token_len, data);
    }
    println!("Final input length: {}", input_bytes.len());
}