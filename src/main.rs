#[macro_use]
extern crate log;
#[macro_use]
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

// TODO arg should be db-pool, not db-connect-str
fn reset_handler(token_dir: &str,
                 pepper: &str,
                 db: &str,
                 bcrypt_rounds: u32,
                 req: &mut nickel::Request)
                 -> Result<(), ResetRequestError> {

    let form = req.form_body().map_err(|_| UserError::EmptyForm)?;

    let uname = form.get("username")
        .map(|u| u.trim())
        .and_then(|x| match x {
            "" => None,
            x => Some(x),
        })
        .ok_or::<UserError>(UserError::EmptyUsername)?;

    let token = form.get("token")
        .map(|u| u.trim())
        .and_then(|x| {
            match x {
                "" => None,
                x => Some(x),
            }
        })
        .ok_or::<UserError>(UserError::EmptyToken)?;

    let pass = form.get("password")
        .map(|u| u.trim())
        .and_then(|x| {
            match x {
                "" => None,
                x => Some(x),
            }
        })
        .ok_or(UserError::EmptyPassword)?;

    validate_password(pass)?;

    validate_uname_and_token(token_dir, uname, token)?;

    let pw_hash = hash_password(pass, pepper, bcrypt_rounds);

    set_new_password(db, uname, pw_hash.as_ref())?;

    delete_token(token_dir, token)?;

    Ok(())
}

fn main() {
    let matches = App::new("synapse-password-reset")
        .version(crate_version!())
        .author(crate_authors!())
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
                    .help("sets the postgres db to connect to (e.g. \
                           'postgres://user:pass@host:port/database')")
                    .takes_value(true)
                    .short("d")
                    .long("db")
                    .required(true),
                Arg::with_name("bcrypt-rounds")
                    .help("sets number of bcrypt rounds (should match your synapse config value, default 12)")
                    .takes_value(true)
                    .short("b")
                    .long("bcrypt-rounds")
                    .required(false)])
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
        let bcrypt_rounds = value_t!(matches, "bcrypt-rounds", u32).unwrap_or(12);

        let response = reset_handler(token_dir, pepper, db, bcrypt_rounds, req);

        let mut data: HashMap<&str, String> = HashMap::new();
        match response {
            Ok(_) => {
                data.insert("notice", "Password successfully changed".to_string());
            },
            Err(ResetRequestError::UserError(err)) => {
                res.set(StatusCode::BadRequest);
                data.insert("notice", format!("{}", err));
            },
            Err(ResetRequestError::InternalError(err)) => {
                warn!("error handling reuqest: {}", err);
                res.set(StatusCode::InternalServerError);
                data.insert("notice", "Internal server error".to_string());
            },
        }

        return Render::render(res, "public/index.tpl", &data)

    });


    let _ = server.listen("127.0.0.1:6767").unwrap();
}

fn validate_password(pass: &str) -> Result<(), UserError> {
    if pass.len() < 10 {
        return Err(UserError::InsecurePassword("password must be at least 10 characters long"
            .to_string()));
    }
    Ok(())
}

fn validate_uname_and_token(token_dir: &str,
                            uname: &str,
                            token: &str)
                            -> Result<(), ResetRequestError> {
    // token database is just the filesystem (fuckit shipit).
    // Tokens are stored in the hierarchy "tokens/$token" relative to the program's cwd.
    // The token file contains the string "username".
    //
    // For obvious security reasons, '.' and '/' should be invalid in the token. Just assert it's
    // alphanumeric for simplicity, which solves that.
    if !token.chars().all(|c| c.is_ascii() && c.is_alphanumeric()) {
        Err(UserError::InvalidToken)?;
    }

    let token_path = Path::new(token_dir).join(format!("tokens/{}", token).as_str());
    let mut f = File::open(token_path).map_err(|_| UserError::InvalidTokenOrUsername)?;
    // TODO log non-ENOENT errs and treat them as server errors

    let mut token_uname = String::new();
    if !f.read_to_string(&mut token_uname).is_ok() {
        Err(UserError::InvalidTokenOrUsername)?
    }

    if token_uname.trim() != uname {
        Err(UserError::InvalidTokenOrUsername)?
    }
    Ok(())
}

// delete_token should be called after validate_uname_and_token since it assumes the token has been
// validated
fn delete_token(token_dir: &str, token: &str) -> Result<(), InternalError> {
    let token_path = Path::new(token_dir).join(format!("tokens/{}", token).as_str());
    std::fs::remove_file(token_path).map_err(|e| InternalError::TokenDeletionError(e))
}



fn set_new_password(db_conn: &str, uname: &str, password_hash: &str) -> Result<(), InternalError> {
    // TODO, connection pooling a level above this function
    let conn = Connection::connect(db_conn, TlsMode::None)?;
    // Based on the synapse readme here: https://github.com/matrix-org/synapse/blob/f9834a3d1a25d0a715718a53e10752399985e3aa/README.rst#password-reset
    // UPDATE users SET password_hash='$2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' WHERE
    // name='@test:test.com';
    // is the query we want
    let updates = conn.execute("UPDATE users SET password_hash = $1 WHERE name = $2",
                 &[&password_hash, &uname])?;

    match updates {
        0 => Err(InternalError::InvalidUserError),
        1 => Ok(()),
        _ => Err(InternalError::UnexpectedError),
    }
}

fn hash_password(password: &str, pepper: &str, rounds: u32) -> String {
    // This function closely mimics
    // https://github.com/matrix-org/synapse/blob/9bba6ebaa903a81cd94fada114aa71e20b685adb/scripts/hash_password
    let mut salt = [0u8; 16];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut salt[..]);
    let mut output = [0u8; 24];

    // ... See https://github.com/pyca/bcrypt/blob/fcebaa0db74dc822877128e57a79dcfda2a2dc4f/src/bcrypt/__init__.py#L66-L72
    // and https://github.com/DaGenix/rust-crypto/blob/cc1a5fde1ce957bd1a8a2e30169443cdb4780111/src/bcrypt.rs#L26
    let peppered_password = format!("{}{}", password, pepper);
    let bcryptable_password = &peppered_password.as_bytes()[0..72];

    bcrypt::bcrypt(rounds,
                   &salt[..],
                   bcryptable_password,
                   &mut output[..]);

    // rust-crypto doesn't do anything nice for us so we have to format our own hash output
    let salt_hex = salt.iter().map(|b| format!("{:X}", b)).collect::<Vec<String>>().join("");
    let out_hex = output.iter().map(|b| format!("{:X}", b)).collect::<Vec<String>>().join("");
    format!("$2b${}${}$", salt_hex, out_hex)
}

#[derive(Debug)]
enum ResetRequestError {
    UserError(UserError),
    InternalError(InternalError),
}

impl From<UserError> for ResetRequestError {
    fn from(err: UserError) -> ResetRequestError {
        ResetRequestError::UserError(err)
    }
}

impl From<InternalError> for ResetRequestError {
    fn from(err: InternalError) -> ResetRequestError {
        ResetRequestError::InternalError(err)
    }
}


#[derive(Debug)]
enum UserError {
    EmptyForm,
    EmptyPassword,
    EmptyToken,
    EmptyUsername,
    InvalidToken,
    InvalidTokenOrUsername,
    InsecurePassword(String),
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UserError::EmptyForm => write!(f, "empty form submitted"),
            UserError::EmptyPassword => write!(f, "password must be set"),
            UserError::EmptyToken => write!(f, "token must be set"),
            UserError::EmptyUsername => write!(f, "username must be set"),
            UserError::InvalidToken => write!(f, "invalid token: must be alphanumeric"),
            UserError::InvalidTokenOrUsername => {
                write!(f,
                       "invalid token + username combination; one or both were invalid")
            }
            UserError::InsecurePassword(ref s) => write!(f, "bad password choice: {}", s),
        }
    }
}

impl Error for UserError {
    fn description(&self) -> &str {
        match *self {
            UserError::EmptyForm => "empty form",
            UserError::EmptyPassword => "empty password",
            UserError::EmptyToken => "empty token",
            UserError::EmptyUsername => "empty username",
            UserError::InvalidToken => "invalid token",
            UserError::InvalidTokenOrUsername => "invalid token or username",
            UserError::InsecurePassword(_) => "insecure password",
        }
    }
}

#[derive(Debug)]
enum InternalError {
    PgConnectError(postgres::error::ConnectError),
    PgError(postgres::error::Error),
    InvalidUserError,
    UnexpectedError,
    TokenDeletionError(std::io::Error),
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InternalError::PgError(ref err) => write!(f, "postgres error: {}", err),
            InternalError::PgConnectError(ref err) => write!(f, "postgres error: {}", err),
            InternalError::InvalidUserError => write!(f, "invalid user error"),
            InternalError::UnexpectedError => write!(f, "unexpected error"),
            InternalError::TokenDeletionError(ref err) => write!(f, "token io error: {}", err),
        }
    }
}

impl Error for InternalError {
    fn description(&self) -> &str {
        match *self {
            InternalError::PgError(ref err) => err.description(),
            InternalError::PgConnectError(ref err) => err.description(),
            InternalError::InvalidUserError => "invalid user",
            InternalError::UnexpectedError => "unexpected error",
            InternalError::TokenDeletionError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            InternalError::PgError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<postgres::error::ConnectError> for InternalError {
    fn from(err: postgres::error::ConnectError) -> InternalError {
        InternalError::PgConnectError(err)
    }
}

impl From<postgres::error::Error> for InternalError {
    fn from(err: postgres::error::Error) -> InternalError {
        InternalError::PgError(err)
    }
}

impl From<InternalError> for String {
    fn from(err: InternalError) -> String {
        err.description().to_string()
    }
}
