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
`subversion_server::svnauthz class`.

Encrypted vars used to generate svnauthz.yaml from template are 
handled by and scoped for the `subversion_server::svnauthz` class as 
opposed to `pipservice::svnauthz::custom_yaml_template`. These values 
are defined in the encrypted nodefile for the host running the service.

The service runs as `www-data`. The installation directory:
/opt/svnauthz, and its contents are owned by `www-data:www-data`

This service is deployed and runs as a systemd service unit.

## Process control

systemctl (start|stop|status) pipservice-svnauthz.service

## Logging

journalctl -u pipservice-svnauthz.service
