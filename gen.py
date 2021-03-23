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

import re

import ldap
import ezt


class FunkyLDAP(Exception):
    def __init__(self, cn):
        self.cn = cn


class LDAPClient:
    "An augmented connection to our LDAP servers."

    # Extract UIDs from an LDAP response.
    UID_RE = re.compile(r'^uid=([^,]*),.*')

    # Disable cert check. The self-signed cert throws off python-ldap.
    ### global option, not per connection? ugh.
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    def __init__(self, url):
        # Easy to front-load client handle creation. It will lazy connect.
        self.handle = ldap.initialize(url)

    def get_members(self, cn, dn, attr):
        if attr:
            attrlist = [ attr ]
        else:
            attrlist = None
        results = self.handle.search_s(dn, scope=ldap.SCOPE_ONELEVEL,
                                       filterstr='(cn=%s)' % (cn,),
                                       attrlist=attrlist)
        # Should be a single result.
        if len(results) != 1:
            ### any data beyond the CN ?
            raise FunkyLDAP(cn)

        _, data = results[0]
        if attr is None:
            if 'memberUid' in data:
                members = data['memberUid']
            elif 'member' in data:
                members = data['member']
        else:
            members = data[attr]

        # Sometimes the result items look like: uid=FOO,ou=people,...
        # Trim to just the uid values.
        if members[0].startswith('uid='):
            return [ self.UID_RE.match(m).group(1) for m in members ]
        return members


class Generator:
    # Query patterns for LDAP
    QUERY_MAIN = ('ou=project,ou=groups,dc=apache,dc=org', 'member')
    QUERY_PMC = ('ou=project,ou=groups,dc=apache,dc=org', 'owner')
    QUERY_COMMITTERS = ('ou=groups,dc=apache,dc=org', 'memberUid')

    def __init__(self, ldap_url, special, explicit):
        self.client = LDAPClient(ldap_url)
        self.special = special
        self.explicit = explicit

    def group_members(self, group):
        "Given an authz @GROUP, return its members."

        if group in self.explicit:
            # This is an explicitly-defined authz group; not LDAP.
            return self.explicit[group]

        # Trim the authz group down to a {cn} value.
        if group.endswith('-pmc'):
            cn = group[:-4]
        elif group.endswith('-ppmc'):
            cn = group[:-5]
        else:
            cn = group

        if group == 'committers':
            # Special case this one. It uses a different attribute.
            dn, attr = self.QUERY_COMMITTERS
        elif group in self.special:
            # These are defined in [special]
            dn = self.special[group]
            attr = None
        elif group != cn:
            # cn has had -(p)pmc sliced off. Look up the PMC.
            dn, attr = self.QUERY_PMC
        else:
            # Not explicit, committers, special, or a PMC. Thus, it is
            # a list of a project's committers.
            dn, attr = self.QUERY_MAIN

        # Find the group members within LDAP.
        return self.client.get_members(cn, dn, attr)

    def write_file(self, template, output):
        print(f'WRITE_FILE: t="{template}" o="{output}"')
