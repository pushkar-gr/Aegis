use std::{thread, time::Duration};

fn main() {
    println!("🛡️ Aegis Agent: Online & Waiting...");
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
