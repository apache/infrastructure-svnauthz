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


UID_RE = re.compile(r'^uid=([^,]*),.*')


class FunkyLDAP(Exception):
    def __init__(self, cn):
        self.cn = cn


class LDAPClient:

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
            return [ UID_RE.match(m).group(1) for m in members ]
        return members
