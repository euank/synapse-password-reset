#[cfg(feature = "integ-tests")]
mod integ_tests {
    extern crate hyper;
    extern crate url;

    use self::url::form_urlencoded;
    use self::hyper::Client;

    fn register_user(c: &hyper::Client, uname: String, password: String) {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("Username", uname.as_ref())
            .append_pair("Password", password.as_ref())
            .finish();
        let res = c.post("http://localhost:8082").body(encoded.as_bytes()).send();

        res.unwrap();
    }

    fn reset_password(c: &hyper::Client, uname: String, token: String, password: String) -> hyper::status::StatusCode {
        let encoded = form_urlencoded::Serializer::new(String::new())
            .append_pair("username", uname.as_ref())
            .append_pair("token", token.as_ref())
            .append_pair("password", password.as_ref())
            .finish();
        let res = c.post("http://localhost:6767").body(encoded.as_bytes()).send();

        res.unwrap().status
    }

#[test]
    fn it_works() {
        let c = Client::new();
        let orig_pass = "password1234".to_string();

        register_user(&c, "bob".to_string(), orig_pass.clone());

        // TODO: login with the above username and password

        let token = "abcd".to_string();
        let full_uname = "bob:synapse_password_reset.local".to_string();
        let new_pass = "newpassword123".to_string();
        // Fail to reset password due to this token not being in the token-db yet
        let sc = reset_password(&c, full_uname, token, new_pass);
        assert!(sc.is_client_error());

        // TODO login with new password

        // TODO verify login with old password fails
    }
}
