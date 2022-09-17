#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os.path
import time
import argparse

import asfpy.pubsub
import asfpy.syslog
import yaml
import requests

import gen

#print = asfpy.syslog.Printer(stdout=True, identity="authz")

# The service will set the working directory, so we can find this.
CONFIG_FNAME = 'svnauthz.yaml'

# Specify a time in the far future to indicate that we have not
# (recently) signaled a need to write the authz files.
FAR_FUTURE = 1e13


class Authorization:
    # There are some groups with custom DN values
    DN_AUTH = 'ou=auth,ou=groups,dc=apache,dc=org'
    DN_GROUPS = 'ou=groups,dc=apache,dc=org'
    DN_SERVICES = 'ou=groups,ou=services,dc=apache,dc=org'

    def __init__(self, cfg, verbose=0):
        self.cfg = cfg

        def verbose1(*args):
            if verbose >= 1: print(*args)
        def verbose2(*args):
            if verbose >= 2: print(*args)
        self.verbose1 = verbose1
        self.verbose2 = verbose2

        # Gather up a bunch of changes, then write new files. We want to
        # avoid writing for each change. Gather them up for a bit of time,
        # then dump the group of changes into the new authz files.
        self.delay = cfg['config']['delay']
        self.verbose2('DELAY:', self.delay)

        url = cfg['config']['ldap']
        self.verbose2('LDAP:', url)

        self.verbose2('AUTH:', cfg['special']['auth'])
        self.verbose2('GROUPS:', cfg['special']['groups'])
        self.verbose2('SERVICES:', cfg['special']['services'])
        self.verbose2('EXPLICIT:', cfg['explicit'])

        special = { a: self.DN_AUTH for a in cfg['special']['auth'] }
        special.update((g, self.DN_GROUPS) for g in cfg['special']['groups'])
        special.update((s, self.DN_SERVICES) for s in cfg['special']['services'])

        self.gen = gen.Generator(url, special, cfg['explicit'])

        self.auth = (cfg['generate']['template_username'],
                     cfg['generate']['template_password'],
                     )

        turl = cfg['generate']['template_url']
        odir = cfg['generate']['output_dir']
        self.verbose1(f'TURL: {turl}\nODIR: {odir}')

        self.dist_authz = os.path.join(odir, cfg['generate']['dist_output'])

        self.mappings = { }
        for name in cfg['generate']:
            ob = cfg['generate'][name]
            if isinstance(ob, dict):
                # Note: NAME is unused, except as a descriptor/grouping
                t = turl + ob['template']
                o = os.path.join(odir, ob['output'])
                self.mappings[t] = o

        # Write new authz files on startup.
        self.write_signal = 0  # epoch

    def write_needed(self):
        "Signal that a (re)write of the authz files is needed."

        # Avoid shifting the time that we first signaled.
        self.write_signal = min(self.write_signal, time.time())

    def handle_commit(self, commit_info):
        self.verbose1('COMMIT FILES:', commit_info['files'])
        ### check against cfg/commit/path

        self.write_needed()

    def write_files(self):
        self.write_signal = FAR_FUTURE
        t0 = time.time()
        self.verbose1('WRITE_FILES: beginning at', t0)
        for t, o in self.mappings.items():
            if t.startswith('/'):
                # File path. Just read it.
                template = open(t).read()
            else:
                template = requests.get(t, auth=self.auth, timeout=30).text
            self.gen.write_file(template.splitlines(), o)

        self.gen.write_dist(self.dist_authz)

        self.verbose1(f'  DURATION: {time.time() - t0}')

    def handler(self, payload):
        # If a (re)write has been signaled, then wait for a bit before
        # writing more files. This prevents rewriting on EVERY change.
        # Given that a heartbeat occurs every 5 seconds (as of this
        # comment), we'll get an opportunity to check/write.
        if time.time() > self.write_signal + self.delay:
            self.write_files()

        # What kind of packet/payload arrived from PUBSUB ?

        if 'stillalive' in payload:
            self.verbose2('HEARTBEAT:', payload)
        elif 'commit' in payload:
            self.handle_commit(payload['commit'])
        elif 'dn' in payload:
            # LDAP has changed, but we don't need the details. It would
            # be incredibly difficult to map changes against what LDAP
            # records are needed by the authz files. So, just rebuild the
            # files, regardless.
            self.verbose1('LDAP CHANGE:', payload['dn'])
            self.write_needed()
        else:
            # unknown payload. (???)
            pass


def main(args):
    cfg = yaml.safe_load(open(CONFIG_FNAME))
    authz = Authorization(cfg, args.verbose)

    ### deal with args.templates

    if args.test:
        # Generate the files, then exit. No daemon.
        authz.write_files()
        return

    username = cfg['server']['username']
    password = cfg['server']['password']

    topics = set()
    topics.add(cfg['commit']['topic'])
    topics.add(cfg['ldap']['topic'])
    # FUTURE: can add more topics here.

    url = cfg['server']['url'] + ','.join(topics)
    authz.verbose2('URL:', url)

    # Run forever
    asfpy.pubsub.listen_forever(authz.handler, url, (username, password))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Monitor/generate svn authz files.')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help=
                          'Print information during operation.'
                          ' Multiple uses, for additional information.')
    parser.add_argument('--test', action='store_true',
                        help='Run a test generation of the authz files.')
    parser.add_argument('--templates',
                        help='Directory containing the (locally-modified) templates.')
    args = parser.parse_args()

    # When testing, always produce some of the basic debug output.
    if args.test:
        args.verbose = max(1, args.verbose)

    main(args)
