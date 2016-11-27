extern crate clap;
extern crate crypto;
#[macro_use]
extern crate nickel;
extern crate nickel_mustache;
extern crate rustc_serialize;
extern crate rand;

use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use rand::os::OsRng;
use rand::Rng;

use nickel::status::StatusCode;
use nickel::{Nickel, HttpRouter, FormBody};
use nickel_mustache::Render;

use clap::{App, Arg};

use crypto::bcrypt;


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
                                  .help("sets the postgres db to connect to (including \
                                         username,pass)")
                                  .takes_value(true)
                                  .short("d")
                                  .long("db")
                                  .required(true)])
                      .get_matches();

    let token_dir = matches.value_of("token-dir").unwrap();
    let pepper = matches.value_of("pepper").unwrap();
    let db = matches.value_of("db").unwrap();

    let mut server = Nickel::new();

    server.get("/",
               middleware!{ |_, res|
        let data: HashMap<String, String> = HashMap::new();
        return Render::render(res, "public/index.tpl", &data);
    });

    server.post("/",
                middleware! {|req, mut res|
        let form_body = req.form_body().or_else(|err| {
            let (_, body_err) = err;
            Err(format!("No form body available: {}", body_err).to_string())
        });

        let account_info =
            form_body.and_then(|form| {
                let uname: Result<&str, String> = form.get("username")
                    .map(|u| u.trim())
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({"Username must be set".to_string()});

                let token = form.get("token")
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({
                    "Token must be set".to_string()
                });

                let pass = form.get("password")
                    .and_then(|x| {
                        match x {"" => None, x => Some(x)}
                    })
                    .ok_or({
                    "Password must be set".to_string()
                });

                uname.and_then(|u| {
                    token.and_then(|t| {
                        pass.and_then(|p| {
                            Ok((u, t, p))
                        })
                    })
                })
            });

        let output = account_info.and_then(|(uname, token, pass): (&str, &str, &str)| {
            // now that we've gathered the information, validate that this is a legit request and
            // do the password reset

            validate_password(pass)?;
            if !validate_uname_and_token(uname, token) {
                return Err("invalid username or token".to_string());
            }
            set_new_password(uname, pass); // TODO
            if !delete_token(token).is_ok() {
                return Err("unable to invalidate your token, please talk to an administrator".to_string());
            }
            Ok("Password changed!".to_string())
        });

        let mut data = HashMap::new();
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

fn validate_password(pass: &str) -> Result<(), &str> {
    if pass.len() < 10 {
        return Err("password must be at least 10 characters long");
    }
    Ok(())
}

fn validate_uname_and_token(uname: &str, token: &str) -> bool {
    // token database is just the filesystem (fuckit shipit).
    // Tokens are stored in the hierarchy "tokens/$token" relative to the program's cwd.
    // The token file contains the string "username".
    //
    // For obvious security reasons, '.' and '/' should be invalid in the token. Just assert it's
    // alphanumeric for simplicity, which solves that.
    if !token.chars().all(|c| c.is_ascii() && c.is_alphanumeric()) {
        return false;
    }

    let mut f = match File::open(format!("tokens/{}", token).as_str()) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut token_uname = String::new();
    if !f.read_to_string(&mut token_uname).is_ok() {
        return false;
    }

    token_uname.trim() == uname
}

// delete_token should be called after validate_uname_and_token since it assumes the token has been
// validated
fn delete_token(token: &str) -> std::io::Result<()> {
    std::fs::remove_file(format!("tokens/{}", token).as_str())
}

fn set_new_password(uname: &str, password: &str) -> Result<(), String> {
    // Here there be postgresql dragons
    Ok(())
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

    bcrypt::bcrypt(bcrypt_rounds, &salt[..], format!("{}{}", password, pepper).as_bytes(), &mut output[..]);

    output.iter().map(|b| format!("{:X}", b).to_string()).collect::<Vec<String>>().join("")
}
