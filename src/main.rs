use clap::Parser;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::{distributions::Alphanumeric, Rng};
use rpassword::read_password;
use rusqlite::{Connection, Result};
use std::io::Write;
use std::str;
use home::home_dir;

/// TOY CLI password manager.
/// Assume the passwords are in clear text and sent to a public server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List passwords
    #[arg(short, long, default_value_t = false)]
    list: bool,

    /// Initialize password manager
    #[arg(short, long, default_value_t = false)]
    init: bool,

    /// Add password
    #[arg(short, long, default_value_t = false, requires_all=["name"])]
    add: bool,

    /// Show password
    #[arg(short, long, default_value_t = false, requires_all=["name"])]
    show: bool,

    /// Value for password
    #[arg(short, long, default_value_t = String::new())]
    passwd: String,

    /// Name of password
    #[arg(short, long, default_value_t = String::new())]
    name: String,

    /// Generate password for name
    #[arg(short, long, default_value_t = false, requires_all=["name"])]
    generate: bool,
}

#[derive(Debug)]
struct HashSalt {
    name: String,
    hash: String,
    salt: String,
}

fn input_passwd(is_new: bool, args: &Args) -> Result<String, String> {
    if !is_new {
        print!("Master password: ");
        std::io::stdout().flush().unwrap();
        let password = read_password().unwrap();
        return Ok(password);
    }

    if !args.passwd.is_empty() {
        return Ok(args.passwd.clone());
    }

    print!("Type password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    println!("");
    print!("Retype password: ");
    std::io::stdout().flush().unwrap();
    let retype = read_password().unwrap();
    if password == retype {
        return Ok(password);
    }

    Err("Passwords don't match".to_string())
}

fn get_db_path() -> String {
    home_dir().unwrap().to_str().unwrap().to_string() + "/.mpspasswd.db"
}

fn create_random(len: usize) -> String {
    let s = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    return s;
}

fn do_salt(input: String, salt: String) -> String {
    input + salt.as_str()
}

fn encrypt(input: &String, salt: &String, key: String) -> String {
    let to_crypt = do_salt(input.clone(), salt.clone());
    let mcrypt = new_magic_crypt!(key.as_str(), 256);
    mcrypt.encrypt_str_to_base64(to_crypt.as_str())
}

fn decrypt(hash: &String, salt: &String, key: String) -> String {
    let mcrypt = new_magic_crypt!(key.as_str(), 256);
    let res = mcrypt.decrypt_base64_to_string(hash.as_str());

    if res.is_err() {
        return "Failed to decrypt".to_string();
    }
    let mut out = res.unwrap();
    out.drain(out.len() - salt.len()..out.len());
    out
}

fn create_master_entry(args: &Args) -> Result<String, String> {
    let connection = Connection::open(get_db_path());
    if connection.is_err() {
        return Err("Failed to connect to database".to_string());
    }
    let command = "
        CREATE TABLE manager (name TEXT UNIQUE, hash TEXT, salt TEXT);
    ";
    let res = connection.unwrap().execute(command, ());
    if res.is_err() {
        return Err("Failed to execute SQL command".to_string());
    }

    let salt: String = create_random(16);

    let mut pass = String::new();

    if args.passwd.is_empty() {
        println!("Creating master password.");
        pass = input_passwd(true, args).unwrap();
    } else {
        pass = args.passwd.clone();
    }

    let enc_master_passwd: String = encrypt(&pass.clone(), &salt, pass.clone());
    let res = db_add_password("master".to_string(), enc_master_passwd, salt);
    if res.is_err() {
        return res;
    }

    let salt = create_random(32);
    let master_key = create_random(64);
    let enc_master_key: String = encrypt(&master_key, &salt, pass);
    let res = db_add_password("master-key".to_string(), enc_master_key, salt);
    if res.is_err() {
        return res;
    }
    Ok("Master record created".to_string())
}

fn get_name(args: &Args) -> String {
    if !args.name.is_empty() {
        return args.name.clone();
    }

    String::new()
}

fn get_master_key(args: &Args) -> Result<String, String> {
    let passwd = input_passwd(false, &args).unwrap();
    let res = get_value("master".to_string());
    if res.is_err() {
        return Err("Can't find master password".to_string());
    }

    let mp_values = res.unwrap();

    let m_passwd = decrypt(&mp_values.hash, &mp_values.salt, passwd.clone());
    if passwd != m_passwd {
        return Err("Incorrect master password.".to_string());
    }

    let mk_values: HashSalt = get_value("master-key".to_string()).unwrap();
    return Ok(decrypt(&mk_values.hash, &mk_values.salt, passwd));
}

fn db_add_password(name: String, hash: String, salt: String) -> Result<String, String> {
    let connection = Connection::open(get_db_path());
    if connection.is_err() {
        return Err("Failed to open database".to_string());
    }
    let command: &str = "INSERT INTO manager (name, hash, salt) VALUES(?, ?, ?);";

    let res = connection
        .unwrap()
        .execute(command, (name.as_str(), hash.as_str(), salt.as_str()));
    if res.is_err() {
        return Err("Failed to add password".to_string());
    }
    Ok("Password added to database".to_string())
}

fn add_password(args: &Args) -> Result<String, String> {
    let name = get_name(&args);
    let key = get_master_key(&args)?;

    let passwd = input_passwd(true, &args).unwrap();

    let salt = create_random(32);
    let hash = encrypt(&passwd, &salt, key);

    db_add_password(name, hash, salt)
}

fn get_passwd(args: &Args) -> String {
    let name = get_name(&args);
    let key = get_master_key(&args);
    if key.is_err() {
        return key.err().unwrap();
    }
    let res = get_value(name.clone());
    if res.is_err() {
        return "Can't find password for ".to_string() + name.as_str();
    }

    let values = res.unwrap();

    decrypt(&values.hash, &values.salt, key.unwrap())
}

fn get_values() -> Result<Vec<HashSalt>> {
    let mut res: Vec<HashSalt> = Vec::new();
    let connection: Connection = Connection::open(get_db_path())?;
    let mut stmt = connection.prepare("SELECT name, hash, salt FROM manager")?;

    let master_iter = stmt.query_map([], |row| {
        Ok(HashSalt {
            name: row.get(0)?,
            hash: row.get(1)?,
            salt: row.get(2)?,
        })
    })?;

    for t in master_iter {
        res.push(t.unwrap())
    }

    Ok(res)
}

fn list_passwords() {
    let res: Result<Vec<HashSalt>, _> = get_values();
    if res.is_err() {
        println!("Failed to get password names");
        return;
    }
    for item in res.unwrap() {
        if item.name != "master" && item.name != "master-key" {
            println!("{}", item.name);
        }
    }
}

fn get_value(name: String) -> Result<HashSalt> {
    let connection: Connection = Connection::open(get_db_path())?;
    let mut stmt = connection.prepare("SELECT name, hash, salt FROM manager WHERE name = ?")?;

    let master_iter: HashSalt = stmt.query_row([name.clone().as_str()], |row| {
        Ok(HashSalt {
            name: name,
            hash: row.get(1)?,
            salt: row.get(2)?,
        })
    })?;

    Ok(master_iter)
}

fn main() {
    let args: Args = Args::parse();
    println!("This is a toy, not a real password manager.");
    println!("All data is sent to a public server in clear text!");
    println!("(not really, but treat it as it was)");
    if args.init {
        let res = create_master_entry(&args);
        if res.is_err() {
            println!("{}", res.err().unwrap());
        }
    } else if args.show {
        println!("{}", get_passwd(&args));
    } else if args.add {
        let _ = add_password(&args);
    } else if args.list {
        list_passwords();
    } else {
        println!("--help for usage");
    }
}
