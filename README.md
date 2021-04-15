# Daemon to maintain authz files for Apache Subversion

## About the SVNAuthz Service

This daemon uses pubsub to watch for both: 
  * template/defition changes for authz files
  * LDAP group changes to fill into the template(s).

If either are detected, an updated asf-authorization and
pit-authorization file will be generated in the directory
specified as `output_dir` in the svnauthz.yaml.erb template 
found in the subversion_server module.

## SVNAuthz Service configuration

This service uses the ASF's `pipservice` Puppet class to operate
and configure the daemon, and is deployed using the custom
`subversion_server::svnauthz` class.

Encrypted vars used to generate svnauthz.yaml from template are 
handled by and scoped for the `subversion_server::svnauthz` class.

These values are defined in the encrypted nodefile for the host 
running the service.

This service runs as `www-data`. 
The installation directory: `/opt/svnauthz`
and its contents are owned by `www-data:www-data`

This service is deployed and runs as a systemd service unit.

## Process control

`systemctl (start|stop|status) pipservice-svnauthz.service`

## Logging

`journalctl -u pipservice-svnauthz.service`

## Testing

In order to test changes to template files

* clone this repository to your workstation.
* acquire an `svnauthz.yaml`
  * from the production machine (easiest)
  * or, from
    [svnauthz.yaml.erb](https://github.com/apache/infrastructure-p6/blob/production/modules/subversion_server/templates/svnauthz.yaml.erb)
    and insert two pairs of user/pass values
* edit the .yaml
  * change the `output_dir` to (say) `/tmp/authz`
  * change the `template_url` to `/path/to/your/templates/`
    (this will likely be `.../modules/subversion_server/files/authorization/`;
    make sure the trailing slash is present)
* create a subdir named `ref` to hold "reference" outputs
* in the subdir, fetch the current/live set of authz files using
  ```
  $ scp svn-master.apache.org:/x1/svn/authorization/*n .
  ```
* start the daemon using
  ```
  $ ./authz.py
  ```
* the daemon will write a new set of output authz files at startup;
  watch the debug output for the `WRITE_FILE:` lines
* then you can check whether you made breaking changes, or just
  minor acceptable changes (after stopping the daemon with ^C, or in
  another window):
  ```
  $ diff /tmp/authz/asf-authorization ref/
  ```
* if you leave the daemon running, it will write the outputs at the
  next LDAP change or next commit
  (as of April 15, it is any commit to any git repository; in the
  future, it will be limited to just the template area; you'll need
  to stop/restart the daemon to regenerate files)

