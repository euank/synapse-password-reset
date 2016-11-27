This is a password reset tool based on the following things:

1) https://github.com/matrix-org/synapse/blob/9bba6ebaa903a81cd94fada114aa71e20b685adb/README.rst#password-reset

2) a filesystem-based database for storing shared secrets and expiration

3) the assumption that an administrator will be able to access said filesystem DB and use it as the means of generating a reset link

## Usage

Deploy this over https. Really.


### TODO

* Web interface for admin (pls u2f)
* A better web interface for users.
* I dunno.

### LICENSE

AGPL3
