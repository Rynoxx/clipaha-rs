use std::time::SystemTime;

use clipaha_rs::{hash, Strength};

// Fetch from env or other configuration
const DOMAIN: &str = "example.com/clipaha";

fn main() {
    let total_start = SystemTime::now();

    let username = "Bob";
    let password = "Hunter2";

    println!("Generating hash for {} with strength Ultra", username);

    let hash = hash(DOMAIN, username, password, Strength::Ultra).expect("Couldn't hash password?");
    println!("{}", hash);

    println!(
        "Took {} seconds to generate hash.",
        SystemTime::now()
            .duration_since(total_start)
            .expect("Clock ran backwards?")
            .as_secs_f64()
    );

    // Send hash to server either for registration, login or password change.
}
