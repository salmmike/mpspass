use age::secrecy::Secret;
use base64::{engine::general_purpose, Engine as _};
use std::io::{Read, Write};

fn do_salt(input: String, salt: String) -> String {
    input + salt.as_str()
}

// Encrypts a string using a salt. Data returned as base64 encoded String
pub fn encrypt(input: &String, salt: &String, key: String) -> String {
    let to_crypt = do_salt(input.to_string(), salt.to_string());

    let encrypted = {
        let encryptor = age::Encryptor::with_user_passphrase(Secret::new(key.as_str().to_owned()));

        let mut encrypted = vec![];
        let res = encryptor.wrap_output(&mut encrypted);
        if res.is_err() {
            return String::new();
        }
        let mut writer = res.unwrap();
        writer.write_all(to_crypt.as_bytes()).unwrap();
        writer.finish().unwrap();

        encrypted
    };
    general_purpose::STANDARD.encode(&encrypted)
}

// Decrypts a base64 encoded String
pub fn decrypt(hash: &String, salt: &String, key: String) -> String {
    let encrypted = general_purpose::STANDARD.decode(&hash).unwrap();

    let decrypted = {
        let decryptor = match age::Decryptor::new(&encrypted[..]).unwrap() {
            age::Decryptor::Passphrase(d) => d,
            _ => unreachable!(),
        };

        let mut decrypted = vec![];
        let res = decryptor.decrypt(&Secret::new(key.to_owned()), None);
        if res.is_err() {
            return String::new();
        }
        let mut reader = res.unwrap();
        reader.read_to_end(&mut decrypted).unwrap();

        decrypted
    };

    let mut out = String::from_utf8(decrypted).unwrap();
    out.drain(out.len() - salt.len()..out.len());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let input = "My secret".to_string();
        let my_salt = "abc".to_string();
        let my_key = "lol".to_string();
        let encrypted = encrypt(&input.clone(), &my_salt.clone(), my_key.clone());
        let decrypted = decrypt(&encrypted.clone(), &my_salt.clone(), my_key.clone());

        assert_eq!(input, decrypted);
    }
}
