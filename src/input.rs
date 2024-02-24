use clap::Parser;
use rand::{distributions::Alphanumeric, Rng};
use rpassword::read_password;
use std::io::{self, Write};

/// TOY CLI password manager.
/// Assume the passwords are in clear text and sent to a public server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// List passwords
    #[arg(short, long, default_value_t = false)]
    pub list: bool,

    /// Initialize password manager
    #[arg(short, long, default_value_t = false)]
    pub init: bool,

    /// Add password
    #[arg(short, long, default_value_t = false)]
    pub add: bool,

    /// Show password
    #[arg(short, long, default_value_t = false)]
    pub show: bool,

    /// Value for password
    #[arg(short, long, default_value_t = String::new())]
    pub passwd: String,

    /// Name of password
    #[arg(short, long, default_value_t = String::new())]
    pub name: String,

    /// Generate password for name
    #[arg(short, long, default_value_t = false)]
    pub generate: bool,
}

pub fn create_random(len: usize) -> String {
    let s = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    return s;
}

pub fn check_overwrite(name: &String) -> bool {
    print!("Entry {} exists. Overwrite? (y/N): ", name);
    std::io::stdout().flush().unwrap();

    let mut input: String = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.starts_with('y')
}

/// Get password from CLI or from arguments.
pub fn input_passwd(is_new: bool, args: &Args) -> Result<String, String> {
    if !is_new {
        print!("Master password: ");
        std::io::stdout().flush().unwrap();
        let password = read_password().unwrap();
        return Ok(password);
    }

    if !args.passwd.is_empty() {
        return Ok(args.passwd.clone());
    }

    if args.generate {
        return Ok(create_random(32));
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

fn rm_newline(name: String) -> String {
    name.strip_suffix("\r\n")
        .or(name.strip_suffix("\n"))
        .unwrap_or(name.as_str());

    name.to_string()
}

/// Get name from arguments or from CLI.
pub fn input_name(args: &Args) -> String {
    if !args.name.is_empty() {
        return rm_newline(args.name.clone());
    }

    print!("Name: ");
    std::io::stdout().flush().unwrap();
    let mut name: String = String::new();
    io::stdin().read_line(&mut name).unwrap();
    rm_newline(name)
}
