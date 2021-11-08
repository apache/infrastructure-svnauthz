# Daemon to maintain authz files for Apache Subversion

## About the SVNAuthz Service

This daemon uses pubsub to watch for both: 
  * template/definition changes for authz files
  * LDAP group changes to fill into the template(s).

If either is detected, an updated asf-authorization and
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
* ensure you have all dependencies installed, per `requirements.txt`
* acquire an `svnauthz.yaml`
  * from the production machine (easiest)
  * or, from
    [svnauthz.yaml.erb](https://github.com/apache/infrastructure-p6/blob/production/modules/subversion_server/templates/svnauthz.yaml.erb)
    and insert two pairs of user/pass values
* edit the .yaml
  * change the `output_dir` to (say) `/tmp/authz`
    * NOTE: make sure the directory exists before starting the daemon (it does not auto-create it)
  * change the `template_url` to `/path/to/your/templates/`
    (this will likely be `.../modules/subversion_server/files/authorization/`;
    make sure the trailing slash is present and use the full path to the file, relative is not supported.)
* create a subdir named `ref` to hold "reference" outputs (call it anything and place it anywhere, it's just used
     to hold a pristine copy of the auth files as comparision.)
* in the `ref` directory, fetch the current/live set of authz files using
  ```
  $ scp svn-master.apache.org:/x1/svn/authorization/*n .
  ```
* generate a new set of authz files using:
  ```
  $ ./authz.py --test
  ```
  (note the daemon will not start; the script will produce the authz
  files, then exit)
* then you can check[1] whether you made breaking changes, or just
  your intended changes (maybe along with acceptable unintended changes):
  ```
  $ diff /tmp/authz/asf-authorization ref/
  ```

[1] The 'check' is currently just diffing the output, future may provide a syntax checker for validity.
