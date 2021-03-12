# Daemon to maintain authz files for Apache Subversion

This daemon uses pubsub to watch for template/defition changes for
authz files, and also watches for LDAP group changes to fill into
the template(s).

This uses the ASF's "pipservice" Puppet class to operate/configure
the daemon.

_more tbd_
