<!DOCTYPE html>
<html>
  <head>
    <title>Wobscale.chat password reset</title>
    <script>
      
    </script>
  </head>
  <body>
    <h1>So, you forgot your password</h1>

    <h2> {{ notice }} </h2>

    <form method="POST">
      Username: <br>
      <input type="text" name="username" /><br>
      Forgot password token: <br>
      <input type="text" name="token" /><br>
      New Password: <br>
      <input type="text" name="password" /><br>
      <input type="submit" name="submit" />
    </form>
  </body>
</html>

