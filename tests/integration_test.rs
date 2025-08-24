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

#[cfg(feature = "integ-tests")]
mod integ_tests {
    extern crate reqwest;
    extern crate url;
    extern crate rand;
    extern crate serde;
    extern crate serde_json;

    use self::url::form_urlencoded;
    use self::reqwest::blocking::Client;
    use self::reqwest::StatusCode;
    use self::rand::Rng;
    use std::io::Write;
    use std::fs::File;
    use serde::Serialize;

    fn register_user(c: &Client, uname: String, password: String) {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("Username", uname.as_ref())
            .append_pair("Password", password.as_ref())
            .finish();
        let res = c.post("http://localhost:8082")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .unwrap();
        assert!(res.status().is_success());
    }

    fn reset_password(c: &Client,
                      uname: String,
                      token: String,
                      password: String)
                      -> (StatusCode, String) {
        let encoded = form_urlencoded::Serializer::new(String::new())
            .append_pair("username", uname.as_ref())
            .append_pair("token", token.as_ref())
            .append_pair("password", password.as_ref())
            .finish();
        let res = c.post("http://localhost:6767")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .unwrap();
        let status = res.status();
        let body = res.text().unwrap();

        (status, body)
    }

    // TODO make an externally usable matrix client to handle this stuff
    struct PasswordLoginRequest {
        user: String,
        password: String,
    }

    impl Serialize for PasswordLoginRequest {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(3))?;
            map.serialize_entry("type", "m.login.password")?;
            map.serialize_entry("user", &self.user)?;
            map.serialize_entry("password", &self.password)?;
            map.end()
        }
    }

    fn login_with_user(c: &Client,
                       login: PasswordLoginRequest)
                       -> Result<(), StatusCode> {
        let resp = c.post("http://localhost:8080/_matrix/client/r0/login")
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&login).unwrap())
            .send()
            .unwrap();

        let status = resp.status();
        match status {
            StatusCode::OK => Ok(()),
            _ => Err(status),
        }
    }

    #[test]
    fn it_works() {
        let c = Client::new();
        let mut rng = rand::rng();
        let orig_pass = format!("password{}", rng.random::<u64>());
        let username1 = format!("user{}", rng.random::<u64>());

        register_user(&c, username1.clone(), orig_pass.clone());
        let result = login_with_user(&c,
                                     PasswordLoginRequest {
                                         user: username1.clone(),
                                         password: orig_pass.clone(),
                                     });
        assert!(result.is_ok());

        let token = format!("token{}", rng.random::<u64>());
        let full_uname = format!("@{}:synapse_password_reset.local", username1);
        let new_pass = format!("newpassword{}", rng.random::<u64>());

        // Fail to reset password due to this token not being in the token-db yet
        let (sc, body) = reset_password(&c, username1.clone(), token.clone(), new_pass.clone());
        assert!(sc.is_client_error(), "error response: {}", body);
        // Create a token so we can succeed
        let mut token_file = File::create(format!("./tokens/{}", token)).unwrap();
        token_file.write_all(full_uname.clone().as_bytes()).unwrap();

        let (sc, body) = reset_password(&c, full_uname.clone(), token.clone(), new_pass.clone());
        assert!(sc.is_success(), "error response: {}", body);

        let result = login_with_user(&c,
                                     PasswordLoginRequest {
                                         user: username1.clone(),
                                         password: orig_pass.clone(),
                                     });
        assert!(result.is_err());

        // New password
        let result = login_with_user(&c,
                                     PasswordLoginRequest {
                                         user: username1.clone(),
                                         password: new_pass.clone(),
                                     });
        assert!(result.is_ok(),
                "did not expect err, but was: {:?}", result.err());
    }
}
