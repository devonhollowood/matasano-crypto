use std::fmt::{Display, Formatter};
use std::fmt;
use std::str::FromStr;
use std::error::Error;
use regex::Regex;
use aes;

pub enum Role {
    User,
    Admin,
}

impl Display for Role {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            &Role::User => formatter.write_str("user"),
            &Role::Admin => formatter.write_str("admin"),
        }
    }
}

pub struct Profile {
    pub email: String,
    pub uid: u64,
    pub role: Role,
}

impl Profile {
    pub fn profile_for(email: &str) -> Profile {
        let cleaned_email = email.chars().filter(|&c| c != '&' && c != '=').collect();
        Profile { email: cleaned_email, uid: 10, role: Role::User }
    }

    pub fn is_admin(&self) -> bool {
        match self.role {
            Role::Admin => true,
            _ => false,
        }
    }

    pub fn encrypt(&self, key: &[u8]) -> Vec<u8> {
        aes::aes_ecb_encrypt(format!("{}", &self).as_bytes(), key)
    }

    pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Profile, ProfileError> {
        use crypto::symmetriccipher::SymmetricCipherError;
        match aes::aes_ecb_decrypt(ciphertext, key) {
            Ok(v) =>  match String::from_utf8(v) {
                Ok(s) => Profile::from_str(&s[..]),
                Err(e) => Err(ProfileError::BadParse(format!("{}", e))),
            },
            Err(e) => match e {
                SymmetricCipherError::InvalidLength =>
                    Err(ProfileError::BadDecrypt("invalid length".to_string())),
                SymmetricCipherError::InvalidPadding =>
                    Err(ProfileError::BadDecrypt("invalid padding".to_string())),
            }
        }
    }
}

impl Display for Profile {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let repr = format!("email={}&uid={}&role={}",
                           self.email, self.uid, self.role);
        formatter.write_str(&repr[..])
    }
}

impl FromStr for Profile {
    type Err = ProfileError;
    fn from_str(s: &str) -> Result<Self, ProfileError> {
        let re = Regex::new(r"email=([^&=]*)&uid=(\d+)&role=(user|admin)").unwrap();
        if let Some(caps) = re.captures(s) {
            let email = caps.at(1).unwrap();
            let uid = caps.at(2).unwrap().parse::<u64>().unwrap();
            let role = match caps.at(3).unwrap() {
                "user" => Role::User,
                "admin" => Role::Admin,
                _ => panic!("This regex (Profile::from_str()) doesn't work at all!"),
            };
            Ok(Profile {email: email.to_string(), uid: uid, role: role})
        }
        else {
            Err(ProfileError::BadParse(format!("Could not parse {}", s)))
        }
    }
}

#[derive(Debug)]
pub enum ProfileError {
    BadParse(String),
    BadDecrypt(String),
}

impl Display for ProfileError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let err = match self {
            &ProfileError::BadParse(ref s) => format!("Bad Profile Parse: {}", s),
            &ProfileError::BadDecrypt(ref s) =>
                format!("Bad Profile Decryption: {}", s),
        };
        formatter.write_str(&err[..])
    }
}

impl Error for ProfileError {
    fn description(&self) -> &str {
        match self {
            &ProfileError::BadParse(_) => "Bad Profile Parse",
            &ProfileError::BadDecrypt(_) => "Bad Profile Decrpytion",
        }
    }
}

