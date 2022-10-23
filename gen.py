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

import os
import re
import time

import ldap
import ezt

### move this to the config file, or LDAP
SVN_ADMINS = 'gmcdonald,humbedooh,cml,christ,dfoulks,gstein,iroh'

### also, for config
# Some projects allow committers to make releases.
### should cross-check this list against Attic
COMMITTERS_MAY_RELEASE = {
    'abdera',
    'bookkeeper',
    'calcite',
    'camel',
    'commons',
    'couchdb',
    'lucene',
    'trafficcontrol',
    'zookeeper',
    }


class FunkyLDAP(Exception):
    def __init__(self, cn):
        self.cn = cn


class LDAPClient:
    "An augmented connection to our LDAP servers."

    # Extract UIDs from an LDAP response.
    UID_RE = re.compile(rb'^uid=([^,]*),.*')

    # Disable cert check. The self-signed cert throws off python-ldap.
    ### global option, not per connection? ugh.
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    def __init__(self, url, binddn, bindpw):
        # Easy to front-load client handle creation. It will lazy connect.
        self.handle = ldap.initialize(url)
        self.handle.simple_bind_s(binddn, bindpw)

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
        if members[0].startswith(b'uid='):
            return [ self.UID_RE.match(m).group(1) for m in members ]
        return members

    def get_all_cn(self, dn):
        results = self.handle.search_s(dn, scope=ldap.SCOPE_ONELEVEL,
                                       attrlist=['cn'])
        # The CN attributes have a single value, which is a simple
        # string, so pull it and decode from unicode.
        return set(attrs['cn'][0].decode() for _, attrs in results)


class Generator:
    # Query patterns for LDAP
    QUERY_MAIN = ('ou=project,ou=groups,dc=apache,dc=org', 'member')
    QUERY_PMC = ('ou=project,ou=groups,dc=apache,dc=org', 'owner')
    QUERY_COMMITTERS = ('ou=groups,dc=apache,dc=org', 'memberUid')

    def __init__(self, ldap_url, binddn, bindpw, special, explicit):
        self.client = LDAPClient(ldap_url, binddn, bindpw)
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
        # Note: all member IDs are ascii, so convert to simple strings.
        return [m.decode() for m in self.client.get_members(cn, dn, attr)]

    def write_file(self, t_lines, output):
        print(f'WRITE_FILE: writing to "{output}"')

        new_z = [ ]
        for line in t_lines:
            if line.startswith(':readonly:'):
                # FORMAT:
                #   :readonly:/some/random/path
                #   :readonly:/root/path/(alt1|alt2|alt3)
                if '(' in line:
                    root, rest = line[10:].split('(')
                    subdirs = [ root+p for p in rest[:-1].split('|') ]
                else:
                    subdirs = [ line[10:] ]
                for s in subdirs:
                    new_z.append(f'[{s}]\n* = r')
            elif line.startswith('#') or '={' not in line:
                new_z.append(line)
            else:
                # Only GROUP={auth} is allowed here.
                assert '={auth}' in line
                group = line.split('=')[0]
                ### Place this specific auth, at this point in the authz file.
                ### This is temporary, as we manage this forward.
                members = self.group_members(group)
                new_z.append(f'{group}={",".join(members)}')

        atomic_write(output, '\n'.join(new_z) + '\n')

    def write_dist(self, output):

        content = [
            DIST_PREAMBLE.format(
                now=time.ctime(),
                SVN_ADMINS=SVN_ADMINS,
                ),
            ]

        # Fetch the list of projects. They are described by the CN
        # values within the PROJECTS schema in LDAP.
        projects = self.client.get_all_cn(self.QUERY_PMC[0])
        print('LEN:', len(projects))
        print('RV:', projects)

        ### not sure what these are, but the old code did this.
        SKIP_PROJECTS = { 'incubator', 'tac', 'diversity', 'security', }

        # Define each of the authz groups: committers, and PMC members.
        # For some reasons, incubator is moved to the end. ??
        for p in sorted(projects - SKIP_PROJECTS) + ['incubator',]:
            committers = self.group_members(p)
            pmc = self.group_members(p+'-pmc')

            content.append(f'{p}={",".join(sorted(committers))}')
            content.append(f'{p}-pmc={",".join(sorted(pmc))}')

        # Construct ACLs for all the projects.
        for p in sorted(projects - SKIP_PROJECTS):
            content.extend([
                '',
                '',
                f'# {p}',
                '',
                f'[/dev/{p}]',
                f'@{p}-pmc = rw',
                f'@{p} = rw',
                '',
                f'[/release/{p}]',
                f'@{p}-pmc = rw',
                ])

            # Some projects allow committers to make releases.
            if p in COMMITTERS_MAY_RELEASE:
                content.append(f'@{p} = rw')

        content.append(DIST_EPILOGUE)
        atomic_write(output, '\n'.join(content))

DIST_PREAMBLE = """\
#
# THIS IS A GENERATED FILE --- DO NOT EDIT
#

# Generated on: {now}

[/]
@svnadmins = rw
* = r

[/release/META]
humbedooh = rw

[/release/zzz]
humbedooh = rw

[groups]
svnadmins={SVN_ADMINS}\
"""

DIST_EPILOGUE = """\


# incubator

[/dev/incubator]
@incubator-pmc = rw
@incubator = rw

[/release/incubator]
@incubator-pmc = rw
@incubator = rw

"""


def atomic_write(fname, content):
    # Write to an intermediate file, then do an atomic move into place.
    ### TODO: throw an alert if the new file is "too different" from the old
    tmp = '%s.%d' % (fname, os.getpid())
    open(tmp, 'w').write(content)
    os.rename(tmp, fname)
