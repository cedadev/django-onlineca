# -*- coding: utf-8 -*-
"""
Utilities used by the django-onlineca package.
"""

import re

from OpenSSL import crypto

from django.core.exceptions import PermissionDenied

from .settings import onlineca_settings


def default_subject_name_generator(request):
    """
    The default subject name generator.

    Replaces ``{user}`` in the configured ``SUBJECT_NAME_TEMPLATE`` with the username
    of the current user.

    Requires that the request has an authenticated user.
    """
    if not request.user.is_authenticated:
        raise PermissionDenied('User must be authenticated')
    return onlineca_settings.SUBJECT_NAME_TEMPLATE.format(user = request.user.username)


#: Lookup table for allowed DN components
X509_DN_LOOKUP = {
    'commonName':             'CN',
    'organisationalUnitName': 'OU',
    'organisation':           'O',
    'countryName':            'C',
    'emailAddress':           'EMAILADDRESS',
    'localityName':           'L',
    'stateOrProvinceName':    'ST',
    'streetAddress':          'STREET',
    'domainComponent':        'DC',
    'userid':                 'UID',
}
#: Regex used for parsing a DN string
X509_DN_PARSER_RE = '/(%s)=' % '|'.join(list(X509_DN_LOOKUP.keys()) +
                                        list(X509_DN_LOOKUP.values()))

def x509_name(dn):
    """
    Parses a string distinguished name into a pyOpenSSL ``X509Name``.

    Args:
        dn: The string distinguished name.

    Returns:
        An ``OpenSSL.crypto.X509Name`` instance.
    """
    dn_parts = re.split(X509_DN_PARSER_RE, dn)
    # pyOpenSSL X509Name doesn't allowing the setting of multiple values for
    # the same DN component, despite this being a perfectly valid thing to do
    # So we first gather the components into a dictionary
    components = {}
    for k, v in zip(dn_parts[1::2], dn_parts[2::2]):
        k = k.strip()
        components.setdefault(k, []).append(v)
    # Now create the subject name and attach components
    subject_name = crypto.X509().get_subject()
    for k, v in components.items():
        # Ugly hack to get around problem that PyOpenSSL X509Name
        # interface doesn't allowing the setting of multiple values for
        # the same DN component
        _v = '/'.join([v[0]] + ["{}={}".format(k, i) for i in v[1:]])
        setattr(subject_name, k, _v)
    return subject_name
