<!DOCTYPE html>
<html>
  <head>
    <title>Wobscale.chat password reset</title>
  </head>
  <body>
    <h1>So, you forgot your password</h1>

    <h2> {{ notice }} </h2>

    <form method="POST">
      Username (in the form @user:wobscale.chat): <br>
      <input id="username" type="text" name="username" /><br>
      Forgot password token: <br>
      <input id="token" type="text" name="token" /><br>
      New Password: <br>
      <input id="password" type="text" name="password" /><br>
      <input type="submit" name="submit" />
    </form>
    <script>
      (function() {
        "use strict";

        // Hash of the format @username:wobscale.chat/reset-token
        var hash = location.hash.substr(1);
        if(hash.length > 0) {
          var parts = hash.split("/")
          if(parts.length == 2) {
            document.querySelector("#username").value = parts[0];
            document.querySelector("#token").value = parts[1];
          } else {
            document.querySelector("#token").value = token;
          }
        }
      })()
    </script>
  </body>
</html>

