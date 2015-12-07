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
import logging
import tempfile
import os
import subprocess


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

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(str(self))


class Policy(object):
    """Class providing an abstraction for the SELinux policy"""
    # pylint: disable=too-many-instance-attributes
    DEFAULT_POLICY_FILE = "/sys/fs/selinux/policy"

    def __init__(self, device, sepolicy=None):
        """Return a policy object, initialised from either a policy file or
        a connected Android device"""
        # TODO modify "device" to be an instance of the Device class
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        # Get the correct policy file
        if sepolicy is None:
            # Get policy from device
            if device is None:
                # We have no device and no policy, abort
                raise RuntimeError(
                    "Invalid policy file \"{}\"".format(sepolicy))
            self._tmpdir = tempfile.mkdtemp()
            self.name = os.path.join(self._tmpdir, "sepolicy")
            self._sepolicy_managed = True
            try:
                subprocess.check_call([adb, "-s", device, "pull",
                                       self.DEFAULT_POLICY_FILE, self.name])
            except subprocess.CalledProcessError:
                self.log.warning("Failed to get the policy from device \"%s\"",
                                 device)
                raise
            else:
                self.log.debug("Copied policy \"%s:%s\" to \"%s\"", device,
                               self.DEFAULT_POLICY_FILE, self.name)
        else:
            self.name = sepolicy
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

    def __del__(self):
        # Remove the temporary policy file if we manage it
        # Sanity check: we remove only files in our temporary directory
        if self._sepolicy_managed and self._tmpdir in self.name:
            try:
                os.remove(self.name)
            except OSError:
                self.log.warning("Trying to remove policy.conf file \"%s\"... "
                                 "failed!", self.name)
            else:
                self.log.debug("Trying to remove policy.conf file \"%s\"... "
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
    def attrs(self):
        """Get the policy attributes as a dictionary of sets.

        Return a dictionary (attribute, set(types))."""
        return self._attrs

    @property
    def domains(self):
        """Get the policy domain types as a dictionary of sets.

        Return a dictionary (type, set(attributes))."""
        return self._domains

    @property
    def classes(self):
        """Get the policy classes as a dictionary of sets.

        Return a dictionary (class, set(perms))."""
        return self._classes

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
        Returns a dictionary (target_type, list(rules))"""
        if not context:
            raise RuntimeError("Invalid context \"{}\"".format(context))
        accessible_types = {}
        # Get the source type from the context
        src_types = [context.type]
        # If an attribute, expand it
        # TODO: does this make sense? does it ever happen?
        if context.type in self.attrs:
            src_types.extend(self.attrs[context.type])
        # Filter all rules
        for rule in self.policy.terules():
            # If we have an allow rule for one of the source types
            if rule.ruletype == "allow" and rule.source in src_types:
                # Add it to the dictionary
                if rule.target in accessible_types:
                    accessible_types[rule.target].append(rule)
                else:
                    accessible_types[rule.target] = [rule]
        return accessible_types

    def get_domains_allowed_to(self, context):
        """Return a dictionary of domains allowed to access a given type,
        reversing the domain attributes relationships.
        The dictionary keys are the domain names, and the dictionary values are
        dictionaries of key "source type" and value "list of rules from type".
        This should probably be improved by incapsulation in a proper object.
        """
        if not context:
            raise RuntimeError("Invalid context \"{}\"".format(context))
        allowed_types = {}
        # Get the target type from the context
        target_types = [context.type]
        # If an attribute, expand it
        # TODO: does this make sense? does it ever happen?
        if context.type in self.attrs:
            target_types.extend(self.attrs[context.type])
        # Filter all rules
        for rule in self.policy.terules():
            # If we have an allow rule for one of the target types
            if rule.ruletype == "allow" and rule.target in target_types:
                # Add it to the dictionary
                if rule.source in allowed_types:
                    allowed_types[rule.source].append(rule)
                else:
                    allowed_types[rule.source] = [rule]
                # Sanity check: all source types are by definition domains,
                # so they should be in the "domain" attribute
                if rule.source not in self.attrs:
                    self.log.warning("Rule source type is not in the"
                                     " \"domain\" attribute: \"%s\"", rule)
        return allowed_types
