use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn do_salt(input: String, salt: String) -> String {
    input + salt.as_str()
}

pub fn encrypt(input: &String, salt: &String, key: String) -> String {
    let to_crypt = do_salt(input.clone(), salt.clone());
    let mcrypt = new_magic_crypt!(key.as_str(), 256);
    mcrypt.encrypt_str_to_base64(to_crypt.as_str())
}

pub fn decrypt(hash: &String, salt: &String, key: String) -> String {
    let mcrypt = new_magic_crypt!(key.as_str(), 256);
    let res = mcrypt.decrypt_base64_to_string(hash.as_str());

    if res.is_err() {
        return "Failed to decrypt".to_string();
    }
    let mut out = res.unwrap();
    out.drain(out.len() - salt.len()..out.len());
    out
}
