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

import asfpy.pubsub
import asfpy.syslog
import yaml

import gen

#print = asfpy.syslog.Printer(stdout=True, identity="authz")

# The service will set the working directory, so we can find this.
CONFIG_FNAME = 'authz.yaml'

# Specify a time in the far future to indicate that we have not
# (recently) signaled a need to write the authz files.
FAR_FUTURE = 1e13


class Authorization:
    def __init__(self, cfg, debug=False):
        self.cfg = cfg
        self.debug = debug

        # Gather up a bunch of changes, then write new files. We want to
        # avoid writing for each change. Gather them up for a bit of time,
        # then dump the group of changes into the new authz files.
        self.delay = cfg['config']['delay']
        print('DELAY:', self.delay)

        url = cfg['config']['ldap']
        print('LDAP:', url)

        ### read auth.conf ... better yet: merge that into the yaml config
        ### for now: ln -s modules/subversion_server/files/authorization/auth.conf .
        import configparser
        cp = configparser.ConfigParser()
        cp.read('auth.conf')
        special = dict((k, v.strip()) for k, v in cp.items('special'))
        explicit = dict((k, v.split()) for k, v in cp.items('explicit'))

        self.gen = gen.Generator(url, special, explicit)

        tdir = cfg['generate']['template_dir']
        odir = cfg['generate']['output_dir']
        #print(f'TDIR: {tdir}\nODIR: {odir}')

        self.mappings = { }
        for name in cfg['generate']:
            ob = cfg['generate'][name]
            if isinstance(ob, dict):
                # Note: NAME is unused, except as a descriptor/grouping
                t = os.path.join(tdir, ob['template'])
                o = os.path.join(odir, ob['output'])
                self.mappings[t] = o

        # Write new authz files on startup.
        self.write_signal = 0  # epoch

    def write_needed(self):
        "Signal that a (re)write of the authz files is needed."

        # Avoid shifting the time that we first signaled.
        self.write_signal = min(self.write_signal, time.time())

    def handle_commit(self, commit_info):
        if self.debug:
            print('COMMIT FILES:', commit_info['files'])
        ### check against cfg/commit/path

        self.write_needed()

    def write_files(self):
        self.write_signal = FAR_FUTURE
        if self.debug:
            print('WRITE_FILES: written at', time.time())
        for t, o in self.mappings.items():
            self.gen.write_file(t, o)

    def handler(self, payload):
        # If a (re)write has been signaled, then wait for a bit before
        # writing more files. This prevents rewriting on EVERY change.
        # Given that a heartbeat occurs every 5 seconds (as of this
        # comment), we'll get an opportunity to check/write.
        if time.time() > self.write_signal + self.delay:
            self.write_files()

        # What kind of packet/payload arrived from PUBSUB ?

        if 'stillalive' in payload:
            if self.debug:
                print('HEARTBEAT:', payload)
        elif 'commit' in payload:
            self.handle_commit(payload['commit'])
        elif 'dn' in payload:
            # LDAP has changed, but we don't need the details. It would
            # be incredibly difficult to map changes against what LDAP
            # records are needed by the authz files. So, just rebuild the
            # files, regardless.
            if self.debug:
                print('LDAP CHANGE:', payload['dn'])
            self.write_needed()
        else:
            # unknown payload. (???)
            pass


def asfpy_pubsub_listener(callback, url, username, password):
    "Construct and run a pubsub Listener forever."
    print('Starting listener:', callback)
    asfpy.pubsub.Listener(url).attach(callback,
                                      auth=(username, password),
                                      raw=True)


def main():
    cfg = yaml.safe_load(open(CONFIG_FNAME))
    authz = Authorization(cfg, debug=True)

    username = cfg['server']['username']
    password = cfg['server']['password']

    topics = set()
    topics.add(cfg['commit']['topic'])
    topics.add(cfg['ldap']['topic'])
    # FUTURE: can add more topics here.

    url = cfg['server']['url'] + ','.join(topics)
    if authz.debug:
        print('URL:', url)

    # Run forever
    ### FUTURE: use asfpy.pubsub.listen_forever()
    asfpy_pubsub_listener(authz.handler, url, username, password)


if __name__ == '__main__':
    main()
