//! A Rust implementation of the [**Cli**entside **pa**ssword **ha**shing research](https://eprint.iacr.org/2022/1746.pdf) and [clipaha JS/WASM library](https://github.com/clipaha/clipaha) by Francisco et. al.  
//! Inspired by Francisco's talk at FOSSNorth 2023.
//!
//! Used to offload password hashing to the client, different [strengths](Strength) available which target different system specs. E.g. it's not suitable to run with Ultra strength on an old smartphone.
//!
//! The resulting hashes should still be hashed with a low-cost hash before being stored in a DB, such as SHA-384, or SHA-512, to prevent direct usage of the hash in the database for authentication against the service should the database be compromised.
//! ## Example
//! ```no_run
//! use clipaha_rs::{hash, Strength};
//!
//! // Fetch from env or other configuration
//! const DOMAIN: &str = "example.com/clipaha";
//!
//! fn main() {
//!     let username = "Bob";
//!     let password = "Hunter2";
//!
//!     println!("Generating hash for {} with strength Medium", username);
//!
//!     let hash = hash(DOMAIN, username, password, Strength::Medium).expect("Couldn't hash password?");
//!     println!("{}", hash);
//!
//!     // Send hash to server either for registration, login or password change.
//! }
//! ```
use argon2::{
    password_hash::{Error, Salt, SaltString},
    Argon2, Params, ParamsBuilder, PasswordHasher,
};

/// Overhead to take into account when comparing byte array length vs Salt::MAX_LENGTH which is for a base64 string.
/// base64 strings are 4/3 the size of the byte array, therefore the base64.len()/1.3333... = byte_array.len()
const SALT_BYTES_MAX_LENGTH: usize = Salt::MAX_LENGTH - (Salt::MAX_LENGTH / 4);

/// Used to specify the strength/complexity to use for the argon2 hash in the hash function.
///
/// `Strength::<value>.value()` returns the t_cost and m_cost to be used.
/// The numbers for t_cost and m_cost
///
/// # Examples
/// See [hash](hash) for example usage.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Strength {
    /// Low is intended to maximize the support for ancient devices, like smartphones, ebook readers, or even computers from the early 2000s
    Low,
    /// Medium targets all computers from the mid-2000s and most smartphones and ebooks from the last 5 years.
    Medium,
    /// High is the value that we would recommend for new developments where only computers from the last 5 years are considered.
    High,
    /// uses the maximum amount of RAM possible currently (a bit less than 2 GiB due to browser limits as explained on Subsection 5.1 of their paper) and will run flawlessly on most modern laptops with at least 3 GiB of RAM.
    Ultra,
}

impl Strength {
    /// Returns the t_cost and m_cost respectively.
    /// Magic numbers determined by the clipaha research paper for a good balance of security and performance.
    pub const fn value(&self) -> (u32, u32) {
        match self {
            Strength::Low => (6, 192 << 10),
            Strength::Medium => (5, 384 << 10),
            Strength::High => (3, 1 << 20),
            Strength::Ultra => (3, ((2 << 20) - (32 << 10))),
        }
    }
}

impl TryFrom<&str> for Strength {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let lowercase_value = value.to_lowercase();

        if lowercase_value == "low" {
            return Ok(Self::Low);
        } else if lowercase_value == "medium" {
            return Ok(Self::Medium);
        } else if lowercase_value == "high" {
            return Ok(Self::High);
        } else if lowercase_value == "ultra" {
            return Ok(Self::Ultra);
        }

        Err("Unrecognized strength specified, must be one of: low, medium, high, ultra".into())
    }
}

impl TryFrom<String> for Strength {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

/// Generates a base64 encoded salt based on the clipaha specifications.
/// The two strings are combined and their lengths are used to pad out the salt.
///
/// If the resulting base64 string is bigger than 64 bytes it will be truncated to 64 bytes, to match the requirements of the argon2 library used.
///
/// "domain" is ment to be *globally* unique but still concise and determinable by clients.
/// It is recommended to use the FQDN (Fully Qualified Domain Name) of your service or FQDN with subdirectory, but try to keep it short. Eg. `example.com`, `service.example.com` or `example.com/service`.
///
/// Intended for use internally by clipaha_rs::hash, but might be useful for other cases as well.
///
/// # Examples
/// ```
/// let domain = "example.com";
/// let login = "user";
///
/// assert_eq!(clipaha_rs::create_salt(domain, login).expect("Shouldn't fail").as_str(), "CwAAAAAAAABleGFtcGxlLmNvbQQAAAAAAAAAdXNlcg");
/// ```
///
/// Long domain + login which results in a truncated salt.
/// ```
/// let domain = "example.com/clipaha";
/// let login = "user-of-clipaha";
///
/// assert_eq!(clipaha_rs::create_salt(domain, login).expect("Shouldn't fail").as_str(), "EwAAAAAAAABleGFtcGxlLmNvbS9jbGlwYWhhDwAAAAAAAAB1c2VyLW9mLWNsaXBh");
/// ```
pub fn create_salt(domain: &str, login: &str) -> Result<SaltString, Error> {
    let mut salt_bytes: Vec<u8> = Vec::with_capacity(domain.len() + login.len());

    // clipaha WASM implementation does little endian. Doesn't really matter, better to keep it consistent
    salt_bytes.extend_from_slice(&domain.len().to_le_bytes());
    salt_bytes.extend_from_slice(domain.as_bytes());
    salt_bytes.extend_from_slice(&login.len().to_le_bytes());
    salt_bytes.extend_from_slice(login.as_bytes());

    // TODO: Maybe a smarter way to truncate to keep uniqueness?
    if salt_bytes.len() > SALT_BYTES_MAX_LENGTH {
        salt_bytes.resize(SALT_BYTES_MAX_LENGTH, 0);
    }

    SaltString::encode_b64(&salt_bytes)
}

/// Generate an argon2id hash using the domain of the application and the users login/username as salt, and predetermined cost parameters based on the strength parameter.
/// "domain" is ment to be *globally* unique, to keep the salt as unique as possible between sites while still predeterminable by clients.
///
/// The resulting hashes should still be hashed with a low-cost hash serverside, such as SHA-384, or SHA-512, to prevent direct usage of the hash in the database for authentication against the service should the database be compromised.
///
/// # Examples
/// Low
/// ```
/// let domain = "example.com/clipaha";
/// let login = "ben";
/// let password = "Hunter2";
///
/// let hash_low = clipaha_rs::hash(domain, login, password, clipaha_rs::Strength::Low).expect("Error occured when hashing password.");
/// assert_eq!(hash_low, "$argon2id$v=19$m=196608,t=6,p=1$EwAAAAAAAABleGFtcGxlLmNvbS9jbGlwYWhhAwAAAAAAAABiZW4$NHM75Wp2NtUxXzjBhbzXMukvT82hk5b9FKwe7P976EQ");
/// ```
///
/// Medium
/// ```
/// let domain = "example.com/clipaha";
/// let login = "username";
/// let password = "Hunter2";
///
/// let hash_medium = clipaha_rs::hash(domain, login, password, clipaha_rs::Strength::Medium).expect("Error occured when hashing password.");
/// assert_eq!(hash_medium, "$argon2id$v=19$m=393216,t=5,p=1$EwAAAAAAAABleGFtcGxlLmNvbS9jbGlwYWhhCAAAAAAAAAB1c2VybmFtZQ$biWgCYPmCuKhzrl05+NHU6iMUMRGLhSf0aSOBsoEjT0");
/// ```
///
/// High
/// ```
/// let domain = "example.com/clipaha";
/// let login = "username";
/// let password = "Hunter2";
///
/// let hash_high = clipaha_rs::hash(domain, login, password, clipaha_rs::Strength::High).expect("Error occured when hashing password.");
/// assert_eq!(hash_high, "$argon2id$v=19$m=1048576,t=3,p=1$EwAAAAAAAABleGFtcGxlLmNvbS9jbGlwYWhhCAAAAAAAAAB1c2VybmFtZQ$AZEyzW8Tdoj3t5Wzb19YjJ1XEwSRKLUs4N1x+FcWbUg");
/// ```
///
/// Ultra
/// ```
/// let domain = "example.com/clipaha";
/// let login = "username";
/// let password = "Hunter2";
///
/// let hash_ultra = clipaha_rs::hash(domain, login, password, clipaha_rs::Strength::Ultra).expect("Error occured when hashing password.");
/// assert_eq!(hash_ultra, "$argon2id$v=19$m=2064384,t=3,p=1$EwAAAAAAAABleGFtcGxlLmNvbS9jbGlwYWhhCAAAAAAAAAB1c2VybmFtZQ$jNAVOq3FTP0nplo4xUsn4uPBhx0ndB77wED8R8h6fMQ");
/// ```
pub fn hash(
    domain: &str,
    login: &str,
    password: &str,
    strength: Strength,
) -> Result<String, Error> {
    let salt = create_salt(domain, login)?;
    let (t_cost, m_cost) = strength.value();

    let params: Params = ParamsBuilder::new()
        .t_cost(t_cost)
        .m_cost(m_cost)
        .p_cost(1) // Hard coded to ensure recommendations and so that no changes to 3rd party library changes the output hash.
        .build()?;

    let clipaha_argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let hash = clipaha_argon2.hash_password(password.as_bytes(), salt.as_salt())?;

    Ok(hash.to_string())
}

#[cfg(test)]
mod test {
    use argon2::password_hash::Error;

    use super::*;

    #[test]
    fn test_salt_different_domains() -> Result<(), Error> {
        let domain1 = "example.com/clipaha";
        let domain2 = "example.com/clipaha2";

        let user = "bob";
        let password = "correct-horse-battery-staple";

        assert_ne!(create_salt(domain1, user)?, create_salt(domain2, user)?);

        assert_ne!(
            hash(domain1, user, password, Strength::Low)?,
            hash(domain2, user, password, Strength::Low)?
        );

        Ok(())
    }

    #[test]
    fn test_salt_different_users() -> Result<(), Error> {
        let domain = "example.com/clipaha";

        let user1 = "bob";
        let user2 = "ben";

        let password = "correct-horse-battery-staple";

        assert_ne!(create_salt(domain, user1)?, create_salt(domain, user2)?);

        assert_ne!(
            hash(domain, user1, password, Strength::Low)?,
            hash(domain, user2, password, Strength::Low)?
        );

        Ok(())
    }

    #[test]
    fn test_try_from_str_low() {
        for str in vec!["low", "lOw", "LOW"] {
            let res = Strength::try_from(str);
            assert!(res.is_ok(), "Given string should be parsed correctly");
            assert_eq!(res.unwrap(), Strength::Low);
        }
    }

    #[test]
    fn test_try_from_str_medium() {
        for str in vec!["medium", "MeDIum", "mediuM", "MEDIUM"] {
            let res = Strength::try_from(str);
            assert!(res.is_ok(), "Given string should be parsed correctly");
            assert_eq!(res.unwrap(), Strength::Medium);
        }
    }

    #[test]
    fn test_try_from_str_high() {
        for str in vec!["high", "HIGH", "hIGh", "higH"] {
            let res = Strength::try_from(str);
            assert!(res.is_ok(), "Given string should be parsed correctly");
            assert_eq!(res.unwrap(), Strength::High);
        }
    }

    #[test]
    fn test_try_from_str_ultra() {
        for str in vec!["ultra", "ULTRA", "uLTRa", "UltrA"] {
            let res = Strength::try_from(str);
            assert!(res.is_ok(), "Given string should be parsed correctly");
            assert_eq!(res.unwrap(), Strength::Ultra);
        }
    }

    #[test]
    fn test_try_from_str_invalid() {
        for str in vec!["invalid", "non-existant", "ultrab", "bow"] {
            let res = Strength::try_from(str);
            assert!(res.is_err(), "Should return error");
        }
    }

    #[test]
    fn test_try_from_string() {
        assert_eq!(
            Strength::try_from("Invalid"),
            Strength::try_from("Invalid".to_string())
        );
        assert_eq!(
            Strength::try_from("low"),
            Strength::try_from("low".to_string())
        );
        assert_eq!(
            Strength::try_from("medium"),
            Strength::try_from("medium".to_string())
        );
        assert_eq!(
            Strength::try_from("high"),
            Strength::try_from("high".to_string())
        );
        assert_eq!(
            Strength::try_from("ultra"),
            Strength::try_from("ultra".to_string())
        );
    }
}
