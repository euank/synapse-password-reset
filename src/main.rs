#[macro_use]
extern crate nickel;
extern crate nickel_mustache;
extern crate rustc_serialize;

use std::collections::HashMap;
use std::path::Path;
use nickel_mustache::Render;
use nickel::{Nickel, HttpRouter, StaticFilesHandler, FormBody};
use nickel::status::StatusCode;
use std::ascii::AsciiExt;


fn main() {
    let mut server = Nickel::new();

    server.get("/",
               middleware!{ |_req, res|
        let mut data: HashMap<String, String> = HashMap::new();
        return Render::render(res, "public/index.tpl", &data);
    });

    server.post("/",
                middleware! {|req, mut res|
        let form_body = req.form_body().or_else(|err| {
            Err("No form body available".to_string())
        });

        let account_info =
            form_body.and_then(|form| {
                let uname: Result<&str, String> = form.get("username")
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

            if !validate_uname_and_token(uname, token) {
                return Err("invalid username or token".to_string());
            }
            // set_new_password(uname, pass); // TODO
            Ok("Password changed".to_string())
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

fn validate_uname_and_token(uname: &str, token: &str) -> bool {
    // token database is just the filesystem (fuckit shipit).
    // Tokens are stored in the hierarchy "tokens/token" relative to the program's cwd.
    // The token file contains the string "username".
    //
    // For obvious security reasons, '.' and '/' should be invalid in the token. Just assert it's
    // alphanumeric for simplicity, which solves that.
    if !token.chars().all(|c| c.is_ascii() && c.is_alphanumeric()) {
        return false;
    }
    Path::new(format!("tokens/{}", token).as_str()).exists()
}
