use clap::Parser;
use home::home_dir;
use rusqlite::{Connection, Result};
use std::str;

mod encryption;
mod input;


fn get_db_path() -> String {
    home_dir().unwrap().to_str().unwrap().to_string() + "/.mpspasswd.db"
}

#[derive(Debug)]
struct HashSalt {
    name: String,
    hash: String,
    salt: String,
}

struct MPSDb {
    db_path: String
}

impl MPSDb {
    pub fn new(path: String) -> MPSDb {
        MPSDb {
            db_path: path,
        }
    }

    fn get_connection(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(self.db_path.clone())
    }

    pub fn create_table(&self)  -> Result<String, String> {
        let connection = self.get_connection();

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
        Ok(String::from("Table created."))
    }

    fn get_value(&self, name: String) -> Result<HashSalt> {
        let connection: Connection = self.get_connection()?;
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

    fn get_values(&self) -> Result<Vec<HashSalt>> {
        let mut res: Vec<HashSalt> = Vec::new();
        let connection: Connection = self.get_connection()?;
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

    fn add_password(&self, name: String, hash: String, salt: String) -> Result<String, String> {
        if self.check_exists(&name) && !input::check_overwrite(&name) {
            return Err("Entry exists".to_string());
        }

        let connection = self.get_connection();
        if connection.is_err() {
            return Err("Failed to open database".to_string());
        }
        let command: &str = "REPLACE INTO manager (name, hash, salt) VALUES(?, ?, ?);";

        let res = connection
            .unwrap()
            .execute(command, (name.as_str(), hash.as_str(), salt.as_str()));
        if res.is_err() {
            return Err("Failed to add password".to_string());
        }
        Ok("Password added to database".to_string())
    }


    fn check_exists(&self, name: &String) -> bool {
        let values = self.get_values().unwrap();
        for val in values {
            if val.name.eq(name) {
                return true;
            }
        }
        return false;
    }
}

struct MPSPass {
    db: MPSDb
}

impl MPSPass {
    pub fn new() -> MPSPass {
        MPSPass {
            db: MPSDb::new(get_db_path()),
        }
    }
    pub fn with_db_path(path: String) -> MPSPass {
        MPSPass {
            db: MPSDb::new(path),
        }
    }

    fn create_master_entry(&self, args: &input::Args) -> Result<String, String> {
        self.db.create_table()?; 

        let salt: String = input::create_random(16);

        let pass: String;

        if args.passwd.is_empty() {
            println!("Creating master password.");
            pass = input::input_passwd(true, args).unwrap();
        } else {
            pass = args.passwd.clone();
        }

        let enc_master_passwd: String = encryption::encrypt(&pass.clone(), &salt, pass.to_owned());
        let res = self.db.add_password("master".to_string(), enc_master_passwd, salt);
        if res.is_err() {
            return res;
        }

        let salt = input::create_random(32);
        let master_key = input::create_random(64);
        let enc_master_key: String = encryption::encrypt(&master_key, &salt, pass);
        let res = self.db.add_password("master-key".to_string(), enc_master_key, salt);
        if res.is_err() {
            return res;
        }
        Ok("Master record created".to_string())
    }

    fn get_master_key(&self, args: &input::Args) -> Result<String, String> {
        let passwd = input::input_passwd(false, &args).unwrap();
        let res = self.db.get_value("master".to_string());
        if res.is_err() {
            return Err("Can't find master password".to_string());
        }

        let mp_values = res.unwrap();

        let m_passwd = encryption::decrypt(&mp_values.hash, &mp_values.salt, passwd.clone());
        if passwd != m_passwd {
            return Err("Incorrect master password.".to_string());
        }

        let mk_values: HashSalt = self.db.get_value("master-key".to_string()).unwrap();
        return Ok(encryption::decrypt(
            &mk_values.hash,
            &mk_values.salt,
            passwd,
        ));
    }


    fn add_password(&self, args: &input::Args) -> Result<String, String> {
        let name = input::input_name(&args);
        let key = self.get_master_key(&args)?;

        let passwd = input::input_passwd(true, &args).unwrap();

        let salt = input::create_random(32);
        let hash = encryption::encrypt(&passwd, &salt, key);

        self.db.add_password(name, hash, salt)
    }

    fn get_passwd(&self, args: &input::Args) -> String {
        let name = input::input_name(&args);
        let key = self.get_master_key(&args);
        if key.is_err() {
            return key.err().unwrap();
        }
        let res = self.db.get_value(name.clone());
        if res.is_err() {
            return "Can't find password for ".to_string() + name.as_str();
        }

        let values = res.unwrap();

        encryption::decrypt(&values.hash, &values.salt, key.unwrap())
    }

    fn list_passwords(&self) {
        let res: Result<Vec<HashSalt>, _> = self.db.get_values();
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

}

fn main() {
    let args: input::Args = input::Args::parse();
    println!("This is a toy, not a real password manager.");
    println!("All data is sent to a public server in clear text!");
    println!("(not really, but treat it as it was)");
    let vault = MPSPass::new();
    if args.init {
        let res = vault.create_master_entry(&args);
        if res.is_err() {
            println!("{}", res.err().unwrap());
        }
    } else if args.show {
        println!("{}", vault.get_passwd(&args));
    } else if args.add {
        let _ = vault.add_password(&args);
    } else if args.list {
        vault.list_passwords();
    } else {
        println!("--help for usage");
    }
}

