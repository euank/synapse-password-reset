extern crate clap;
extern crate crypto;
#[macro_use]
extern crate nickel;
extern crate nickel_mustache;
extern crate rustc_serialize;
extern crate rand;
extern crate postgres;


use std::path::Path;
use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::fmt;
use std::io::prelude::*;
use rand::os::OsRng;
use rand::Rng;

use nickel::status::StatusCode;
use nickel::{Nickel, HttpRouter, FormBody};
use nickel_mustache::Render;

use clap::{App, Arg};

use crypto::bcrypt;

use postgres::{Connection, TlsMode};


fn main() {
    let matches = App::new("synapse-password-reset")
        .version("v0.0.1")
        .author("Euan Kemp <euank@euank.com>")
        .args(&[Arg::with_name("token-dir")
                    .help("sets the database directory to use")
                    .takes_value(true)
                    .short("t")
                    .long("token-dir")
                    .required(true),
                Arg::with_name("pepper")
                    .help("sets the hash pepper (e.g. from your synapse config)")
                    .takes_value(true)
                    .short("p")
                    .long("pepper")
                    .required(true),
                Arg::with_name("db")
                    .help("sets the postgres db to connect to (including username,pass)")
                    .takes_value(true)
                    .short("d")
                    .long("db")
                    .required(true)])
        .get_matches();

    let mut server = Nickel::new();

    server.get("/",
               middleware!{ |_, res|
        let data: HashMap<String, String> = HashMap::new();
        return Render::render(res, "public/index.tpl", &data);
    });

    server.post("/",
                middleware! {|req, mut res|

        let token_dir = matches.value_of("token-dir").unwrap();
        let pepper = matches.value_of("pepper").unwrap();
        let db = matches.value_of("db").unwrap();

        let form_body = req.form_body().or_else(|err| {
            let (_, body_err) = err;
            Err(format!("no form body available: {}", body_err))
        });

        let account_info =
            form_body.and_then(|form| {
                let uname = form.get("username")
                    .map(|u| u.trim())
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({"Username must be set".to_string()});

                let token = form.get("token")
                    .map(|u| u.trim())
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({"Token must be set".to_string()});

                let pass = form.get("password")
                    .map(|u| u.trim())
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({"Password must be set".to_string()});

                Ok((uname?, token?, pass?))
            });

        let output = account_info.and_then(|(uname, token, pass): (&str, &str, &str)| {
            // now that we've gathered the information, validate that this is a legit request and
            // do the password reset

            validate_password(pass)?;
            validate_uname_and_token(token_dir, uname, token)?;

            let pw_hash = hash_password(pass, pepper);

            set_new_password(db, uname, pw_hash.as_ref())?;
            if !delete_token(token_dir, token).is_ok() {
                return Err("unable to invalidate your token, please talk to an administrator".to_string());
            }
            Ok("Password changed!".to_string())
        });

        let mut data: HashMap<&str, String> = HashMap::new();
        match output {
            Ok(o) => {
                data.insert("notice", o);
            }
            Err(e) => {
                res.set(StatusCode::BadRequest);
                data.insert("notice", e);
            }
        };

        return Render::render(res, "public/index.tpl", &data)
    });


    let _ = server.listen("127.0.0.1:6767").unwrap();
}

fn validate_password(pass: &str) -> Result<(), String> {
    if pass.len() < 10 {
        return Err("password must be at least 10 characters long".to_string());
    }
    Ok(())
}

fn validate_uname_and_token(token_dir: &str, uname: &str, token: &str) -> Result<(), String> {
    // token database is just the filesystem (fuckit shipit).
    // Tokens are stored in the hierarchy "tokens/$token" relative to the program's cwd.
    // The token file contains the string "username".
    //
    // For obvious security reasons, '.' and '/' should be invalid in the token. Just assert it's
    // alphanumeric for simplicity, which solves that.
    if !token.chars().all(|c| c.is_ascii() && c.is_alphanumeric()) {
        return Err("token must be ascii/alphanumeric".to_string());
    }

    let token_path = Path::new(token_dir).join(format!("tokens/{}", token).as_str());
    let mut f = match File::open(token_path) {
        Ok(f) => f,
        Err(_) => return Err("invalid token".to_string()), // TODO log non-ENOENT errs
    };

    let mut token_uname = String::new();
    if !f.read_to_string(&mut token_uname).is_ok() {
        return Err("invalid token + username".to_string());
    }

    if token_uname.trim() != uname {
        return Err("invalid token + username".to_string());
    }
    Ok(())
}

// delete_token should be called after validate_uname_and_token since it assumes the token has been
// validated
fn delete_token(token_dir: &str, token: &str) -> std::io::Result<()> {
    let token_path = Path::new(token_dir).join(format!("tokens/{}", token).as_str());
    std::fs::remove_file(token_path)
}



fn set_new_password(db_conn: &str, uname: &str, password_hash: &str) -> Result<(), SetPwError> {
    // TODO, connection pooling a level above this function
    let conn = Connection::connect(db_conn, TlsMode::None)?;
    // Based on the synapse readme here: https://github.com/matrix-org/synapse/blob/f9834a3d1a25d0a715718a53e10752399985e3aa/README.rst#password-reset
    // UPDATE users SET password_hash='$2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' WHERE
    // name='@test:test.com';
    // is the query we want
    let updates = conn.execute("UPDATE users SET password_hash = $1 WHERE name = $2",
                 &[&password_hash, &uname])?;

    match updates {
        0 => Err(SetPwError::InvalidUserError()),
        1 => Ok(()),
        _ => Err(SetPwError::UnexpectedError()),
    }
}

fn hash_password(password: &str, pepper: &str) -> String {
    // This function closely mimics
    // https://github.com/matrix-org/synapse/blob/9bba6ebaa903a81cd94fada114aa71e20b685adb/scripts/hash_password

    // Match the default from synapse arbitrarily
    let bcrypt_rounds = 12;

    let mut salt = [0u8; 16];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut salt[..]);
    let mut output = [0u8; 24];

    bcrypt::bcrypt(bcrypt_rounds,
                   &salt[..],
                   format!("{}{}", password, pepper).as_bytes(),
                   &mut output[..]);

    output.iter().map(|b| format!("{:X}", b).to_string()).collect::<Vec<String>>().join("")
}

#[derive(Debug)]
enum SetPwError {
    PgConnectError(postgres::error::ConnectError),
    PgError(postgres::error::Error),
    InvalidUserError(),
    UnexpectedError(),
}

impl fmt::Display for SetPwError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SetPwError::PgError(ref err) => write!(f, "postgres error: {}", err),
            SetPwError::PgConnectError(ref err) => write!(f, "postgres error: {}", err),
            SetPwError::InvalidUserError() => write!(f, "invalid user error"),
            SetPwError::UnexpectedError() => write!(f, "unexpected error"),
        }
    }
}

impl Error for SetPwError {
    fn description(&self) -> &str {
        match *self {
            SetPwError::PgError(ref err) => err.description(),
            SetPwError::PgConnectError(ref err) => err.description(),
            SetPwError::InvalidUserError() => "invalid user",
            SetPwError::UnexpectedError() => "unexpected error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            SetPwError::PgError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<postgres::error::ConnectError> for SetPwError {
    fn from(err: postgres::error::ConnectError) -> SetPwError {
        SetPwError::PgConnectError(err)
    }
}

impl From<postgres::error::Error> for SetPwError {
    fn from(err: postgres::error::Error) -> SetPwError {
        SetPwError::PgError(err)
    }
}

impl From<SetPwError> for String {
    fn from(err: SetPwError) -> String {
        err.description().to_string()
    }
}
