#
# Written by Filippo Bonazzi
# Copyright (C) 2015 Aalto University
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

import setools
import setools.policyrep
import logging
import tempfile
import os


class Context(object):
    """Class providing an abstraction for a SELinux context"""

    def __init__(self, context):
        # If the context string is not null and contains 4 or 5
        # colon-delimited fields
        if context and len(context.split(":")) in (4, 5):
            # Split the context
            ctx = context.split(":")
            if len(ctx) == 4:
                # If this is an old-style context
                # e.g. "user:role:type:sensitivity"
                self._fields = 4
                self._user = ctx[0]
                self._role = ctx[1]
                self._type = ctx[2]
                self._sens = ctx[3]
            else:
                # This is a new-style context(Android 6)
                # e.g. "user:role:type:sensitivity:categories"
                self._fields = 5
                self._user = ctx[0]
                self._role = ctx[1]
                self._type = ctx[2]
                self._sens = ctx[3]
                self._cats = ctx[4].split(",")
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

    @property
    def cats(self):
        """Get the context cats"""
        return self._cats

    def __repr__(self):
        if self._fields == 4:
            tmp = "{}:{}:{}:{}".format(self._user, self._role, self._type,
                                       self._sens)
        else:
            tmp = "{}:{}:{}:{}:{}".format(self._user, self._role, self._type,
                                          self._sens, ",".join(self.cats))
        return tmp

    def __eq__(self, other):
        if str(self) == str(other):
            return True
        else:
            return False

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(str(self))


class Policy(object):
    """Class providing an abstraction for the SELinux policy"""
    # pylint: disable=too-many-instance-attributes

    def __init__(self, device, sepolicy=None):
        """Return a policy object, initialised from either a policy file or
        a connected Android device"""
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        # Get the correct policy file
        if sepolicy is None:
            # Get policy from device
            if device is None:
                # We have no device and no policy, abort
                raise ValueError(
                    "Invalid policy file \"{}\"".format(sepolicy))
            # Prepare the location for the policy file
            self._tmpdir = tempfile.mkdtemp()
            self.name = os.path.join(self._tmpdir, "sepolicy")
            # We manage the policy file (delete it when done)
            self._sepolicy_managed = True
            # Try to get the policy from the device
            try:
                device.pull_policy(self.name)
            except ValueError:
                self.log.warning("Failed to get the policy from device \"%s\"",
                                 device)
                raise
        else:
            # Work with the provided policy
            self.name = sepolicy
            # It is preexisting: we don't manage it (don't delete it!)
            self._sepolicy_managed = False
        # Parse the policy file
        self.log.info("Parsing policy \"%s\"...", self.name)
        self._policy = setools.policyrep.SELinuxPolicy(self.name)
        if not self._policy:
            raise RuntimeError("Invalid policy file \"{}\"".format(self.name))
        # Initialize some useful variables
        self._types = self.__compute_types()
        self._attrs = self.__compute_attrs()
        self._domains = self.__compute_domains()
        self._classes = self.__compute_classes()
        self._types_count = len(self.types)
        self._attrs_count = len(self.attrs)
        self._domains_count = len(self.domains)
        self._classes_count = len(self.classes)

    def __del__(self):
        # Remove the temporary policy file if we manage it
        # Sanity check: we remove only files in our temporary directory
        if self._sepolicy_managed and self._tmpdir in self.name:
            try:
                os.remove(self.name)
            except OSError:
                self.log.warning("Trying to remove policy file \"%s\"... "
                                 "failed!", self.name)
            else:
                self.log.debug("Trying to remove policy file \"%s\"... "
                               "done!", self.name)
        if self._tmpdir:
            try:
                os.rmdir(self._tmpdir)
            except OSError:
                self.log.warning("Trying to remove the temporary directory "
                                 "\"%s\"... failed!", self._tmpdir)
            else:
                self.log.debug("Trying to remove the temporary directory "
                               "\"%s\"... done!", self._tmpdir)

    @property
    def types(self):
        """Get the policy types as a dictionary of sets.

        Return a dictionary (type, set(attributes))."""
        return self._types

    @property
    def types_count(self):
        """Get the number of policy types."""
        return self._types_count

    @property
    def attrs(self):
        """Get the policy attributes as a dictionary of sets.

        Return a dictionary (attribute, set(types))."""
        return self._attrs

    @property
    def attrs_count(self):
        """Get the number of policy attributes."""
        return self._attrs_count

    @property
    def domains(self):
        """Get the policy domain types as a dictionary of sets.

        Return a dictionary (type, set(attributes))."""
        return self._domains

    @property
    def domains_count(self):
        """Get the number of policy domains."""
        return self._domains_count

    @property
    def classes(self):
        """Get the policy classes as a dictionary of sets.

        Return a dictionary (class, set(perms))."""
        return self._classes

    @property
    def classes_count(self):
        """Get the number of policy classes."""
        return self._classes_count

    @property
    def policy(self):
        """Get the setoolsv4 SELinuxPolicy instance."""
        return self._policy

    def __compute_types(self):
        """Get the SELinuxPolicy attributes as a dictionary of sets.

        Return a dictionary (type, set(attributes))."""
        types = {}
        for tpe in self.policy.types():
            types[str(tpe)] = set(str(x) for x in tpe.attributes())
        return types

    def __compute_attrs(self):
        """Get the SELinuxPolicy attributes as a dictionary of sets.

        Return a dictionary (attribute, set(types))."""
        attributes = {}
        for attr in self.policy.typeattributes():
            attributes[str(attr)] = set(str(x) for x in attr.expand())
        return attributes

    def __compute_domains(self):
        """Get the policy domain types as a dictionary of sets.

        Return a dictionary (type, set(attributes))."""
        domains = {}
        for type_domain in self.attrs["domain"]:
            domains[type_domain] = self.types[type_domain]
        return domains

    def __compute_classes(self):
        """Get the SELinuxPolicy classes as a dictionary of sets.

        Return a dictionary (class, set(perms)).
        Each set contains all the permissions for the associated class,
        both inherited from commons and directly assigned."""
        classes = {}
        for cls in self.policy.classes():
            try:
                cmn = cls.common
            except setools.policyrep.exception.NoCommon:
                cmnset = cls.perms
            else:
                cmnset = cls.perms.union(self.policy.lookup_common(cmn).perms)
            classes[str(cls)] = cmnset
        return classes

    def get_types_accessible_by(self, context):
        """Get the types accessible from a given context.

        NOTE: the mapping currently ignores RBAC and MLS.
        Returns a dictionary (target_type, list(rules))."""
        if not context:
            raise RuntimeError("Invalid context \"{}\"".format(context))
        accessible_types = {}
        query = setools.terulequery.TERuleQuery(policy=self.policy,
                                                ruletype=["allow"],
                                                source=context.type)
        # Filter all rules
        for rule in query.results():
            # Add it to the dictionary
            if rule.target in accessible_types:
                accessible_types[rule.target].append(rule)
            else:
                accessible_types[rule.target] = [rule]
        return accessible_types

    def get_domains_allowed_to(self, context, security_class):
        """Get the domains allowed to access a combination of context/class.

        NOTE: currently the context match is performed only on the type.
        Returns a dictionary (source_type, list(rules))."""
        if not context or not security_class:
            raise RuntimeError(
                "Invalid context or class: \"{}\" {}".format(context,
                                                             security_class))
        allowed_types = {}
        query = setools.terulequery.TERuleQuery(policy=self.policy,
                                                ruletype=["allow"],
                                                target=context.type,
                                                tclass=[security_class])
        # Filter all rules
        for rule in query.results():
            # Add it to the dictionary
            if rule.source in allowed_types:
                allowed_types[rule.source].append(rule)
            else:
                allowed_types[rule.source] = [rule]
            # Sanity check: all source types are by definition domains,
            # so they should be in the "domain" attribute
            if rule.source not in self.attrs["domain"]:
                self.log.warning("Rule source type is not in the"
                                 " \"domain\" attribute: \"%s\"", rule)
        return allowed_types
