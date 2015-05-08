#
# Copyright 2015 Filippo Bonazzi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""A module providing several abstraction classes on a SELinux policy
and its components"""

from setools import apol, qpol
from collections import defaultdict

class Context(object):
    """Class providing an abstraction for a SELinux context"""
    def __init__(self, context):
        if context and len(context.split(':')) == 4:
            self._user = context.split(':')[0]
            self._role = context.split(':')[1]
            self._type = context.split(':')[2]
            self._sens = context.split(':')[3]
        else:
            raise Exception('Bad context: "{}"'.format(context))

    @property
    def user(self):
        """Get the context user"""
        return self._user

    @property
    def role(self):
        """Get the context role"""
        return self._role

    @property
    def type(self):
        """Get the context type"""
        return self._type

    @property
    def sens(self):
        """Get the context sens"""
        return self._sens

    def __repr__(self):
        return "{}:{}:{}:{}".format(
                self._user, self._role, self._type, self._sens)

    def __eq__(self, other):
        if str(self) == str(other):
            return True
        else:
            return False

    def __hash__(self):
        return hash(str(self))

class AVRule(object):
    """Class providing an abstraction for a SELinux AVRule"""
    def __init__(self, rule, policy):
        if policy is None:
            raise Exception("Bad policy")
        if not rule:
            raise Exception("Bad rule")

        self._policy = policy
        self._qpolicy = policy.get_qpol()
        self._rule = rule

        text_rule = apol.apol_avrule_render(self._policy, self._rule)
        #Textual rule parsing is easier
        try:
            r = text_rule.split(None, 5)
            self._type = r[0]
            self._source = r[1]
            self._target = r[2]
            # r[3] is ':'
            self._security_class = r[4]
            self._permissions = r[5].strip('{}; ').split()
        except IndexError:
            raise Exception('Bad rule: "{}"'.format(text_rule))

    @property
    def type(self):
        """Get the rule type"""
        return self._type

    @property
    def source(self):
        """Get the rule source type"""
        return self._source

    @property
    def target(self):
        """Get the rule target type"""
        return self._target

    @property
    def security_class(self):
        """Get the rule target security class"""
        return self._security_class

    @property
    def permissions(self):
        """Get the rule target permissions"""
        return self._permissions

    def __repr__(self):
        return apol.apol_avrule_render(self._policy, self._rule)

class Policy(object):
    """Class providing an abstraction for the SELinux policy"""
    def __init__(self, filename):
        if filename is None or not filename:
            raise IOError('Invalid policy file')

        self.name = filename
        self._policy_path = apol.apol_policy_path_t(
                apol.APOL_POLICY_PATH_TYPE_MONOLITHIC, filename, None)
        self._policy = apol.apol_policy_t(self._policy_path)

        if self._policy.this is None:
            raise IOError('Invalid policy file')
        self._qpolicy = self._policy.get_qpol()

    @property
    def types(self):
        """Get the policy types"""
        if not hasattr(self, '_types'):
            self._initialise_types()
        return self._types.keys()

    @property
    def attrs(self):
        """Get the policy attributes"""
        if not hasattr(self, '_attrs'):
            self._initialise_attrs()
        return self._attrs.keys()

    @property
    def domains(self):
        """Get the policy domains"""
        if not hasattr(self, '_domains'):
            self._initialise_domains()
        return self._domains.keys()

    @property
    def classes(self):
        """Get the policy classes"""
        if not hasattr(self, '_classes'):
            self._initialise_classes()
        return self._classes.keys()

    @property
    def isids(self):
        """Get the policy initial SIDs"""
        if not hasattr(self, '_isids'):
            self._initialise_isids()
        return self._isids.keys()

    @property
    def levels(self):
        """Get the policy MLS levels"""
        if not hasattr(self, '_levels'):
            self._initialise_levels()
        return self._levels.keys()

    @property
    def cats(self):
        """Get the policy MLS categories"""
        if not hasattr(self, '_cats'):
            self._initialise_cats()
        return self._cats.keys()

    @property
    def constraints(self):
        """Get the policy MLS constraints - NOT IMPLEMENTED"""
        if not hasattr(self, '_constraints'):
            self._initialise_constraints()
        return self._constraints

    @property
    def polcaps(self):
        """Get the policy capabilities - NOT IMPLEMENTED"""
        if not hasattr(self, '_polcaps'):
            self._initialise_polcaps()
        return self._polcaps.keys()

    @property
    def roles(self):
        """Get the policy RBAC roles"""
        if not hasattr(self, '_roles'):
            self._initialise_roles()
        return self._roles.keys()

    @property
    def users(self):
        """Get the policy users"""
        if not hasattr(self, '_users'):
            self._initialise_users()
        return self._users.keys()

    @property
    def fs_uses(self):
        """Get the policy fs_uses"""
        if not hasattr(self, '_fs_uses'):
            self._initialise_fs_uses()
        return self._fs_uses.keys()

    @property
    def genfscons(self):
        """Get the policy genfscons"""
        if not hasattr(self, '_genfscons'):
            self._initialise_genfscons()
        return self._genfscons.keys()

    @property
    def portcons(self):
        """Get the policy portcons"""
        if not hasattr(self, '_portcons'):
            self._initialise_portcons()
        return self._portcons.keys()

    @property
    def allow(self):
        """Get the policy allow rules"""
        if not hasattr(self, '_allow'):
            self._initialise_avrules()
        return self._allow

    @property
    def neverallow(self):
        """Get the policy neverallow rules - NOT IMPLEMENTED"""
        if not hasattr(self, '_neverallow'):
            self._initialise_avrules()
        return self._neverallow

    @property
    def auditallow(self):
        """Get the policy auditallow rules"""
        if not hasattr(self, '_auditallow'):
            self._initialise_avrules()
        return self._auditallow

    @property
    def dontaudit(self):
        """Get the policy dontaudit rules"""
        if not hasattr(self, '_dontaudit'):
            self._initialise_avrules()
        return self._dontaudit

    @property
    def type_trans(self):
        """Get the policy type transition rules"""
        if not hasattr(self, '_type_trans'):
            self._initialise_terules()
        return self._type_trans

    @property
    def type_change(self):
        """Get the policy type change rules"""
        if not hasattr(self, '_type_change'):
            self._initialise_terules()
        return self._type_change

    @property
    def type_member(self):
        """Get the policy type member rules"""
        if not hasattr(self, '_type_member'):
            self._initialise_terules()
        return self._type_member

    @property
    def role_allow(self):
        """Get the policy role allow rules"""
        if not hasattr(self, '_role_allow'):
            self._initialise_role_allow()
        return self._role_allow

    @property
    def role_trans(self):
        """Get the policy role transition rules"""
        if not hasattr(self, '_role_trans'):
            self._initialise_role_trans()
        return self._role_trans

    @property
    def range_trans(self):
        """Get the policy role allow rules"""
        if not hasattr(self, '_range_trans'):
            self._initialise_range_trans()
        return self._range_trans

    def _initialise_types(self):
        """Initialise the policy types dictionary"""
        type_query = apol.apol_type_query_t()
        types_v = type_query.run(self._policy)
        self._types = {}
        for i in range(types_v.get_size()):
            t = qpol.qpol_type_from_void(types_v.get_element(i))
            if (not t.get_isattr(self._qpolicy) and
                    not t.get_isalias(self._qpolicy)):
                self._types[t.get_name(self._qpolicy)] = t

    def _initialise_attrs(self):
        """Initialise the policy attributes dictionary"""
        attr_query = apol.apol_attr_query_t()
        attrs_v = attr_query.run(self._policy)
        self._attrs = {}
        for i in range(attrs_v.get_size()):
            t = qpol.qpol_type_from_void(attrs_v.get_element(i))
            self._attrs[t.get_name(self._qpolicy)] = t

    def _initialise_domains(self):
        """Initialise the policy domains dictionary"""
        if not hasattr(self, '_attrs'):
            self._initialise_attrs()
        i = self._attrs["domain"].get_type_iter(self._qpolicy)
        self._domains = {}
        while not i.end():
            d = qpol.qpol_type_from_void(i.get_item())
            self._domains[d.get_name(self._qpolicy)] = d
            i.next()

    def _initialise_classes(self):
        """Initialise the policy classes dictionary"""
        class_query = apol.apol_class_query_t()
        classes_v = class_query.run(self._policy)
        self._classes = {}
        for i in range(classes_v.get_size()):
            c = qpol.qpol_class_from_void(classes_v.get_element(i))
            self._classes[c.get_name(self._qpolicy)] = c

    def _initialise_isids(self):
        """Initialise the policy initial SIDs dictionary"""
        isids_query = apol.apol_isid_query_t()
        isids_v = isids_query.run(self._policy)
        self._isids = {}
        for i in range(isids_v.get_size()):
            s = qpol.qpol_isid_from_void(isids_v.get_element(i))
            self._isids[s.get_name(self._qpolicy)] = s

    def _initialise_levels(self):
        """Initialise the policy MLS sensitivities dictionary"""
        lev_query = apol.apol_level_query_t()
        lev_v = lev_query.run(self._policy)
        self._levels = {}
        for i in range(lev_v.get_size()):
            l = qpol.qpol_level_from_void(lev_v.get_element(i))
            self._levels[l.get_name(self._qpolicy)] = l

    def _initialise_cats(self):
        """Initialise the policy MLS categories dictionary"""
        cat_query = apol.apol_cat_query_t()
        cat_v = cat_query.run(self._policy)
        self._cats = {}
        for i in range(cat_v.get_size()):
            c = qpol.qpol_cat_from_void(cat_v.get_element(i))
            self._cats[c.get_name(self._qpolicy)] = c

    def _initialise_constraints(self):
        """Initialise the policy MLS constraints list -- NOT IMPLEMENTED"""
        # Currently not implemented
        # Complex, take from seinfo.c:1442
        constraint_query = apol.apol_constraint_query_t()
        constraint_v = constraint_query.run(self._policy)
        self._constraints = []

    def _initialise_polcaps(self):
        """Initialise the policy capabilities dictionary
        NOT IMPLEMENTED in the Python bindings"""
        # Not implemented in the Python bindings yet
        self._polcaps = {}

    def _initialise_roles(self):
        """Initialise the policy RBAC roles dictionary"""
        role_query = apol.apol_role_query_t()
        role_v = role_query.run(self._policy)
        self._roles = {}
        for i in range(role_v.get_size()):
            r = qpol.qpol_role_from_void(role_v.get_element(i))
            self._roles[r.get_name(self._qpolicy)] = r

    def _initialise_users(self):
        """Initialise the policy RBAC users dictionary"""
        user_query = apol.apol_user_query_t()
        user_v = user_query.run(self._policy)
        self._users = {}
        for i in range(user_v.get_size()):
            u = qpol.qpol_user_from_void(user_v.get_element(i))
            self._users[u.get_name(self._qpolicy)] = u

    def _initialise_fs_uses(self):
        """Initialise the policy fs_uses dictionary"""
        fs_use_query = apol.apol_fs_use_query_t()
        fs_use_v = fs_use_query.run(self._policy)
        self._fs_uses = {}
        for i in range(fs_use_v.get_size()):
            f = qpol.qpol_fs_use_from_void(fs_use_v.get_element(i))
            self._fs_uses[f.get_name(self._qpolicy)] = f

    def _initialise_genfscons(self):
        """Initialise the policy genfscons dictionary"""
        genfscon_query = apol.apol_genfscon_query_t()
        genfscon_v = genfscon_query.run(self._policy)
        self._genfscons = {}
        for i in range(genfscon_v.get_size()):
            g = qpol.qpol_genfscon_from_void(genfscon_v.get_element(i))
            self._genfscons[apol.apol_genfscon_render(self._policy, g)] = g

    def _initialise_portcons(self):
        """Initialise the policy portcons dictionary"""
        portcon_query = apol.apol_portcon_query_t()
        portcon_v = portcon_query.run(self._policy)
        self._portcons = {}
        for i in range(portcon_v.get_size()):
            p = qpol.qpol_portcon_from_void(portcon_v.get_element(i))
            self._portcons[p.get_context(self._qpolicy)] = p

    def _initialise_avrules(self):
        """Initialise the policy AV rules lists
        (allow, auditallow, dontaudit)"""
        rule_query = apol.apol_avrule_query_t()
        # neverallow rules are not supported?
        mask = qpol.QPOL_RULE_ALLOW | qpol.QPOL_RULE_AUDITALLOW | qpol.QPOL_RULE_DONTAUDIT
        rule_query.set_rules(self._policy, mask)
        rule_v = rule_query.run(self._policy)
        if rule_v is None:
            raise IOError('AV rule query failed')
        self._allow = []
        self._neverallow = []
        self._auditallow = []
        self._dontaudit = []
        for i in range(rule_v.get_size()):
            r = qpol.qpol_avrule_from_void(rule_v.get_element(i))
            rule = AVRule(r, self._policy)
            # Switch
            if rule.type == 'allow':
                self._allow.append(rule)
                continue
            if rule.type == 'neverallow':
                self._neverallow.append(rule)
                continue
            if rule.type == 'auditallow':
                self._auditallow.append(rule)
                continue
            if rule.type == 'dontaudit':
                self._dontaudit.append(rule)
                continue
            print 'Unexpected AV rule type'

    def _initialise_terules(self):
        """Initialise the policy TE rules lists
        (type_trans, type_change, type_member)"""
        rule_query = apol.apol_terule_query_t()
        mask = qpol.QPOL_RULE_TYPE_TRANS | qpol.QPOL_RULE_TYPE_CHANGE | qpol.QPOL_RULE_TYPE_MEMBER
        rule_query.set_rules(self._policy, mask)
        rule_v = rule_query.run(self._policy)
        if rule_v is None:
            raise IOError("TE rule query failed")
        self._type_trans = []
        self._type_change = []
        self._type_member = []
        for i in range(rule_v.get_size()):
            r = qpol.qpol_terule_from_void(rule_v.get_element(i))
            rt = r.get_rule_type(self._qpolicy)
            # Switch
            if rt == qpol.QPOL_RULE_TYPE_TRANS:
                self._type_trans.append(r)
                continue
            if rt == qpol.QPOL_RULE_TYPE_CHANGE:
                self._type_change.append(r)
                continue
            if rt == qpol.QPOL_RULE_TYPE_MEMBER:
                self._type_member.append(r)
                continue
            print 'Unexpected TE rule type'

    def _initialise_role_allow(self):
        """Initialise the policy role_allow rules list"""
        rule_query = apol.apol_role_allow_query_t()
        rule_v = rule_query.run(self._policy)
        if rule_v is None:
            raise IOError("Role allow rule query failed")
        self._role_allow = []
        for i in range(rule_v.get_size()):
            r = qpol.qpol_role_allow_from_void(rule_v.get_element(i))
            self._role_allow.append(r)

    def _initialise_role_trans(self):
        """Initialise the policy role_trans rules list"""
        rule_query = apol.apol_role_trans_query_t()
        rule_v = rule_query.run(self._policy)
        if rule_v is None:
            raise IOError("Role allow rule query failed")
        self._role_trans = []
        for i in range(rule_v.get_size()):
            r = qpol.qpol_role_trans_from_void(rule_v.get_element(i))
            self._role_trans.append(r)

    def _initialise_range_trans(self):
        """Initialise the policy range_trans rules list -- NOT IMPLEMENTED"""
        # Part of MLS, not a focus right now
        self._range_trans = []

    def get_types_accessible_by(self, context):
        """Return a dictionary of types accessible by a given domain,
        exploding the domain attributes.
        The types are filed in the dictionary by type context"""
        if context is None:
            return None
        accessible_types = defaultdict(list)
        if not hasattr(self, '_types'):
            self._initialise_types()
        src_type = self._types[context.type]
        attr_iter = src_type.get_attr_iter(self._qpolicy)
        src_types = {context.type: src_type}
        while not attr_iter.end():
            a = qpol.qpol_type_from_void(attr_iter.get_item())
            src_types[a.get_name(self._qpolicy)] = a
            attr_iter.next()
        # Parse allow rules to find target types
        for r in self.allow:
            if r.source in src_types:
                accessible_types[r.target].append(r)
        return accessible_types

    def get_domains_allowed_to(self, context):
        """Return a dictionary of domains allowed to access a given type,
        reversing the domain attributes relationships.
        The dictionary keys are the domain names, and the dictionary values are
        dictionaries of key "source type" and value "list of rules from type".
        This should probably be improved by incapsulation in a proper object.
        """
        if context is None:
            return None
        allowed_types = defaultdict(list)
        allowed_domains = defaultdict(list)
        if not hasattr(self, '_types'):
            self._initialise_types()
        if not hasattr(self, '_domains'):
            self._initialise_domains()
        # Parse allow rules to find source types
        for r in self.allow:
            if r.target == context.type:
                allowed_types[r.source].append(r)
        # Go from source types to domains
        for dname, d in self._domains.iteritems():
            attr_iter = d.get_attr_iter(self._qpolicy)
            src_types = {dname: d}
            while not attr_iter.end():
                a = qpol.qpol_type_from_void(attr_iter.get_item())
                src_types[a.get_name(self._qpolicy)] = a
                attr_iter.next()
            # src_types contains all types accessible by the domain d
            for tname in src_types.keys():
                if tname in allowed_types:
                    # If a type accessible by this domain can access the target
                    # type, add the rules for that source type under the domain
                    allowed_domains[dname].extend(allowed_types[tname])
        return allowed_domains
