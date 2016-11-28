This is a password reset tool based on the following things:

1) https://github.com/matrix-org/synapse/blob/9bba6ebaa903a81cd94fada114aa71e20b685adb/README.rst#password-reset

2) a filesystem-based database for storing shared secrets and expiration

3) the assumption that an administrator will be able to access said filesystem DB and use it as the means of generating a reset link

## Usage

Deploy this over https. Really.

### Administering a password reset

As an admin, you should have access to the filesystem including the token database directory.

Enter into the token database directory, and run the following to make a password reset:

```bash
token=$(cat /dev/uraneom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)
echo -n "username:matrix.server.name.com" > $token
```

Provide the token to the user who forgot their password. Carefully validate it is actually them. gpg encrypt it for them. Live your dreams of the government trying to intercept your communication.

Eventually this might be less manual!

### TODO

* Update the user weberface to allow '#token' links which auto-fill the token box (js)
* Web interface for admin (pls u2f)
* A better web interface for users.
* I dunno.

### LICENSE

AGPL3
