// Synapse password reset
// Copyright (C) 2016 Euan Kemp
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#[macro_use]
extern crate log;
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate nickel;
extern crate bcrypt;
extern crate postgres;
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use nickel::status::StatusCode;
use nickel::{FormBody, HttpRouter, Nickel};

use clap::{Arg, Command};

use postgres::{Client, NoTls};

// TODO arg should be db-pool, not db-connect-str
fn reset_handler(
    token_dir: &str,
    pepper: &str,
    db: &str,
    bcrypt_rounds: u32,
    req: &mut nickel::Request,
) -> Result<(), ResetRequestError> {
    let form = req.form_body().map_err(|_| UserError::EmptyForm)?;

    let uname = form
        .get("username")
        .map(|u| u.trim())
        .and_then(|x| match x {
            "" => None,
            x => Some(x),
        })
        .ok_or(UserError::EmptyUsername)?;

    let token = form
        .get("token")
        .map(|u| u.trim())
        .and_then(|x| match x {
            "" => None,
            x => Some(x),
        })
        .ok_or(UserError::EmptyToken)?;

    let pass = form
        .get("password")
        .map(|u| u.trim())
        .and_then(|x| match x {
            "" => None,
            x => Some(x),
        })
        .ok_or(UserError::EmptyPassword)?;

    validate_password(pass)?;

    validate_uname_and_token(token_dir, uname, token)?;

    let pw_hash = hash_password(pass, pepper, bcrypt_rounds);

    set_new_password(db, uname, pw_hash.as_ref())?;

    delete_token(token_dir, token)?;

    Ok(())
}

fn render_template(
    template_path: &str,
    data: &HashMap<&str, String>,
) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(template_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut result = contents.clone();
    for (key, value) in data.iter() {
        let placeholder = format!("{{{{ {} }}}}", key);
        result = result.replace(&placeholder, value);
    }

    Ok(result)
}

fn main() {
    env_logger::init();

    let matches = Command::new("synapse-password-reset")
        .version("0.1.0")
        .author("Euan Kemp <euank@euank.com>")
        .args(&[
            Arg::new("token-dir")
                .help("sets the database directory to use")
                .value_name("DIR")
                .short('t')
                .long("token-dir")
                .required(true),
            Arg::new("pepper")
                .help("sets the hash pepper (e.g. from your synapse config)")
                .value_name("PEPPER")
                .short('p')
                .long("pepper")
                .required(true),
            Arg::new("db")
                .help(
                    "sets the postgres db to connect to (e.g. \
                           'postgres://user:pass@host:port/database')",
                )
                .value_name("DATABASE")
                .short('d')
                .long("db")
                .required(true),
            Arg::new("bcrypt-rounds")
                .help(
                    "sets number of bcrypt rounds (should match your synapse config \
                           value, default 12)",
                )
                .value_name("ROUNDS")
                .short('b')
                .long("bcrypt-rounds")
                .value_parser(|v: &str| -> Result<u32, String> {
                    let rounds: u32 = v
                        .parse()
                        .map_err(|_| "bcrypt-rounds must be an int".to_string())?;
                    match rounds {
                        5..=31 => Ok(rounds),
                        _ => Err("rounds must be between 5 and 31".to_string()),
                    }
                })
                .required(false),
        ])
        .get_matches();

    let mut server = Nickel::new();

    server.get(
        "/",
        middleware! { |_, mut res|
            let mut data: HashMap<&str, String> = HashMap::new();
            data.insert("notice", "".to_string());
            let html = render_template("public/index.tpl", &data).unwrap_or_else(|e| {
                error!("Failed to render template: {}", e);
                "Internal Server Error".to_string()
            });
            return res.send(html)
        },
    );

    server.post(
        "/",
        middleware! {|req, mut res|

            let token_dir = matches.get_one::<String>("token-dir").unwrap();
            let pepper = matches.get_one::<String>("pepper").unwrap();
            let db = matches.get_one::<String>("db").unwrap();
            let bcrypt_rounds = matches.get_one::<u32>("bcrypt-rounds").copied().unwrap_or(12);

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
                    warn!("error handling request: {}", err);
                    res.set(StatusCode::InternalServerError);
                    data.insert("notice", "Internal server error".to_string());
                },
            }

            let html = render_template("public/index.tpl", &data).unwrap_or_else(|e| {
                error!("Failed to render template: {}", e);
                res.set(StatusCode::InternalServerError);
                "Internal Server Error".to_string()
            });
            return res.send(html)
        },
    );

    let _ = server.listen("0.0.0.0:6767").unwrap();
}

fn validate_password(pass: &str) -> Result<(), UserError> {
    if pass.len() < 10 {
        return Err(UserError::InsecurePassword(
            "password must be at least 10 characters long".to_string(),
        ));
    }
    Ok(())
}

fn validate_uname_and_token(
    token_dir: &str,
    uname: &str,
    token: &str,
) -> Result<(), ResetRequestError> {
    // token database is just the filesystem (fuckit shipit).
    // Tokens are stored in the hierarchy "$token_dir/$token".
    // The token file contains the string "username".
    //
    // For obvious security reasons, '.' and '/' should be invalid in the token. Just assert it's
    // alphanumeric for simplicity, which solves that.
    if !token.chars().all(|c| c.is_ascii() && c.is_alphanumeric()) {
        Err(UserError::InvalidToken)?;
    }

    let token_path = Path::new(token_dir).join(token);
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
    let token_path = Path::new(token_dir).join(format!("{}", token).as_str());
    std::fs::remove_file(token_path).map_err(|e| InternalError::TokenDeletionError(e))
}

fn set_new_password(db_conn: &str, uname: &str, password_hash: &str) -> Result<(), InternalError> {
    // TODO, connection pooling a level above this function
    let mut conn = Client::connect(db_conn, NoTls)?;
    // Based on the synapse readme here: https://github.com/matrix-org/synapse/blob/f9834a3d1a25d0a715718a53e10752399985e3aa/README.rst#password-reset
    // UPDATE users SET password_hash='$2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' WHERE
    // name='@test:test.com';
    // is the query we want
    info!("updating password for {}", uname);
    let updates = conn.execute(
        "UPDATE users SET password_hash = $1 WHERE name = $2",
        &[&password_hash, &uname],
    )?;

    match updates {
        0 => Err(InternalError::InvalidUserError),
        1 => Ok(()),
        _ => Err(InternalError::UnexpectedError),
    }
}

fn hash_password(password: &str, pepper: &str, rounds: u32) -> String {
    // This function closely mimics
    // https://github.com/matrix-org/synapse/blob/9bba6ebaa903a81cd94fada114aa71e20b685adb/scripts/hash_password
    let peppered_password = format!("{}{}", password, pepper);

    let result = bcrypt::hash(&peppered_password, rounds);
    // only possible error is `bcrypt-rounds` being too large/small, which we already validated.
    // TODO, this can be improved by defining a type in the bcrypt crate
    let crypt_hash = result.unwrap();
    // Soooo, this is hacky, but python *only* supports $2a$ and $2b$, while this crate only
    // supports $2y$.
    // The differences are tiny, so it turns out that just pretending this is $2a$ works at least.
    // Some side effects may occur, please consult your local crypto expert before use.
    crypt_hash
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 2 {
                // Index of 'y' in '$2y'
                'a'
            } else {
                c
            }
        })
        .collect()
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
                write!(
                    f,
                    "invalid token + username combination; one or both were invalid"
                )
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
    PgError(postgres::Error),
    InvalidUserError,
    UnexpectedError,
    TokenDeletionError(std::io::Error),
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InternalError::PgError(ref err) => write!(f, "postgres error: {}", err),
            InternalError::InvalidUserError => write!(f, "invalid user error"),
            InternalError::UnexpectedError => write!(f, "unexpected error"),
            InternalError::TokenDeletionError(ref err) => write!(f, "token io error: {}", err),
        }
    }
}

impl Error for InternalError {
    fn description(&self) -> &str {
        match *self {
            InternalError::PgError(_) => "postgres error",
            InternalError::InvalidUserError => "invalid user",
            InternalError::UnexpectedError => "unexpected error",
            InternalError::TokenDeletionError(_) => "token io error",
        }
    }

    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            InternalError::PgError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<postgres::Error> for InternalError {
    fn from(err: postgres::Error) -> InternalError {
        InternalError::PgError(err)
    }
}

impl From<InternalError> for String {
    fn from(err: InternalError) -> String {
        err.to_string()
    }
}
