use std::time::SystemTime;

use clipaha_rs::{hash, Strength};
use std::io;
use std::io::prelude::*;

// Fetch from env or other configuration
const DOMAIN: &str = "example.com/clipaha";

fn main() {
    let stdin = io::stdin();

    loop {
        println!("Specify your desired strength (Low/Medium/High/Ultra): [Medium]");
        let mut strength = Strength::Medium;
        for line in stdin.lock().lines() {
            let strength_str = line.expect("Unable to read line from stdin");

            if strength_str.trim().is_empty() {
                break;
            }

            strength = Strength::try_from(strength_str).unwrap();
            break;
        }

        println!("Enter your username: ");
        let mut username = String::new();
        for line in stdin.lock().lines() {
            username = line.expect("Unable to read line from stdin");
            break;
        }

        println!("Enter your password: ");
        let mut password = String::new();
        for line in stdin.lock().lines() {
            password = line.expect("Unable to read line from stdin");
            break;
        }

        println!(
            "Generating hash for {} with strength Medium on domain {}",
            &username, DOMAIN
        );

        let total_start = SystemTime::now();
        let hash = hash(DOMAIN, &username, &password, strength).expect("Couldn't hash password?");
        println!("{}", hash);

        println!(
            "Took {} seconds to generate hash.",
            SystemTime::now()
                .duration_since(total_start)
                .expect("Clock ran backwards?")
                .as_secs_f64()
        );

        println!("Want to create another hash? Y/n");
        for line in stdin.lock().lines() {
            let again = line.expect("Unable to read line from stdin");

            if !again.to_lowercase().starts_with("y") {
                return;
            }

            break;
        }
    }
}
