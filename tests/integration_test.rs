#[cfg(feature = "integ-tests")]
mod integ_tests {
    extern crate hyper;
    extern crate url;
    extern crate rand;
    extern crate rustc_serialize;

    use self::url::form_urlencoded;
    use self::hyper::Client;
    use self::rand::{Rng, OsRng};
    use std::io::{Read, Write};
    use std::fs::File;
    use std::collections::BTreeMap;
    use self::rustc_serialize::json::{self, Json, ToJson};

    fn register_user(c: &hyper::Client, uname: String, password: String) {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("Username", uname.as_ref())
            .append_pair("Password", password.as_ref())
            .finish();
        let mut res = c.post("http://localhost:8082")
            .header(hyper::header::ContentType::form_url_encoded())
            .body(encoded.as_bytes())
            .send()
            .unwrap();
        let mut body: String = "".to_string();
        res.read_to_string(&mut body).unwrap();
        assert!(res.status.is_success());
    }

    fn reset_password(c: &hyper::Client,
                      uname: String,
                      token: String,
                      password: String)
                      -> (hyper::status::StatusCode, String) {
        let encoded = form_urlencoded::Serializer::new(String::new())
            .append_pair("username", uname.as_ref())
            .append_pair("token", token.as_ref())
            .append_pair("password", password.as_ref())
            .finish();
        let mut res = c.post("http://localhost:6767")
            .header(hyper::header::ContentType::form_url_encoded())
            .body(encoded.as_bytes())
            .send()
            .unwrap();
        let mut body: String = "".to_string();
        res.read_to_string(&mut body).unwrap();

        (res.status, body)
    }

    // TODO make an externally usable matrix client to handle this stuff
    struct PasswordLoginRequest {
        user: String,
        password: String,
    }

    impl ToJson for PasswordLoginRequest {
        fn to_json(&self) -> Json {
            let mut obj = BTreeMap::new();
            // https://matrix.org/docs/spec/client_server/r0.2.0.html#login
            obj.insert("type".to_string(), "m.login.password".to_json());
            obj.insert("user".to_string(), self.user.to_json());
            obj.insert("password".to_string(), self.password.to_json());
            Json::Object(obj)
        }
    }

    fn login_with_user(c: &hyper::Client,
                       login: PasswordLoginRequest)
                       -> Result<(), hyper::status::StatusCode> {
        let resp = c.post("http://localhost:8080/_matrix/client/r0/login")
            .header(hyper::header::ContentType::json())
            .body(format!("{}", login.to_json()).as_bytes())
            .send()
            .unwrap();

        match resp.status {
            hyper::status::StatusCode::Ok => Ok(()),
            _ => Err(resp.status),
        }
    }

    #[test]
    fn it_works() {
        let c = Client::new();
        let mut rng = OsRng::new().unwrap();
        let orig_pass = format!("password{}", rng.next_u64());
        let username1 = format!("user{}", rng.next_u64());

        register_user(&c, username1.clone(), orig_pass.clone());
        let result = login_with_user(&c,
                                     PasswordLoginRequest {
                                         user: username1.clone(),
                                         password: orig_pass.clone(),
                                     });
        assert!(result.is_ok());

        let token = format!("token{}", rng.next_u64());
        let full_uname = format!("@{}:synapse_password_reset.local", username1);
        let new_pass = format!("newpassword{}", rng.next_u64());

        // Fail to reset password due to this token not being in the token-db yet
        let (sc, body) = reset_password(&c, username1.clone(), token.clone(), new_pass.clone());
        assert!(sc.is_client_error(), format!("error response: {}", body));
        // Create a token so we can succeed
        let mut token_file = File::create(format!("./tokens/{}", token)).unwrap();
        token_file.write_all(full_uname.clone().as_bytes()).unwrap();

        let (sc, body) = reset_password(&c, full_uname.clone(), token.clone(), new_pass.clone());
        assert!(sc.is_success(), format!("error response: {}", body));

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
                format!("did not expect err, but was: {}", result.err().unwrap()));
    }
}
