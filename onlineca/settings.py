"""
Settings utilities for the django-onlineca package.
"""

from OpenSSL import crypto

from django.conf import settings
from django.utils.module_loading import import_string
from django.core.exceptions import ImproperlyConfigured


class OnlineCASettings:
    """
    Settings object for the django-onlineca package.
    """
    DEFAULTS = {
        'SUBJECT_NAME_GENERATOR': 'onlineca.utils.default_subject_name_generator',
        'CA_CERT_CHAIN_PATHS': [],
        'MIN_KEY_BITS': 2048,
        'NOT_BEFORE_TIME_SECS': 0,
        'NOT_AFTER_TIME_SECS': 259200,  # Default to 72 hour lifetime
        'KEY_PASSWORD': None,
    }
    IMPORT_STRINGS = (
        'SUBJECT_NAME_GENERATOR',
    )

    def __init__(self, user_settings = {}):
        self.user_settings = user_settings

    def _default_ca_cert_chain(self):
        # If not given in user_settings, certs for the CA chain can be loaded
        # from named files instead
        def read(path):
            with open(path) as f:
                return f.read()
        return [read(path) for path in self.CA_CERT_CHAIN_PATHS]

    def _default_certificate_authority(self):
        # If not given in user_settings, configure a certificate authority
        # from other settings
        from contrail.security.ca.impl import CertificateAuthority
        val = CertificateAuthority.from_keywords(
            cert = self.CERT,
            key = self.KEY,
            min_key_nbits = self.MIN_KEY_BITS,
            not_before_time_nsecs = self.NOT_BEFORE_TIME_SECS,
            not_after_time_nsecs = self.NOT_AFTER_TIME_SECS
        )

    def _default_cert(self):
        # If not given in user_settings, cert can be loaded from a path
        with open(self.CERT_PATH) as cert_file:
            cert = cert_file.read()
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    def _default_key(self):
        # If not given in user_settings, key can be loaded from a path with
        # optional password
        with open(self.KEY_PATH) as key_file:
            key = key_file.read()
        password = self.KEY_PASSWORD
        return crypto.load_privatekey(
            crypto.FILETYPE_PEM, key, *([password] if password else [])  
        )

    def __getattr__(self, attr):
        if attr in self.user_settings:
            # First, try user settings
            val = self.user_settings[attr]
        elif attr in self.DEFAULTS:
            # Then try the defaults dict (for simple defaults)
            val = self.DEFAULTS[attr]
        elif hasattr(self, '_default_' + attr.lower()):
            # Then see if there is a method to generate the default
            val = getattr(self, '_default_' + attr.lower())()
        else:
            # If no default is available, the setting is required in user_settings
            raise ImproperlyConfigured("ONLINECA setting required: {}".format(attr))

        # If the setting is an import string, perform the import
        if attr in self.IMPORT_STRINGS:
            val = import_string(val)

        # Check that any certificates given in the CA_CERT_CHAIN setting are valid,
        # whether they come directly from user_settings or from CA_CERT_CHAIN_PATHS
        if attr == 'CA_CERT_CHAIN':
            for cert in val:
                try:
                    crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                except Exception:
                    raise ImproperlyConfigured(
                        'Failed to parse CA_CERT_CHAIN element as PEM-formatted '
                        'certificate: {}'.format(cert)
                    )

        # Before returning, cache the value for future use
        setattr(self, attr, val)
        return val


onlineca_settings = OnlineCASettings(getattr(settings, 'ONLINECA', {}))
