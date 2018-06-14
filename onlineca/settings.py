# -*- coding: utf-8 -*-
"""
Settings utilities for the django-onlineca package.
"""

from OpenSSL import crypto

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from settings_object import SettingsObject, Setting, ImportStringSetting


def default_certificate_authority(settings):
    """
    Generate a certificate authority from other settings.
    """
    # If not given in user_settings, configure a certificate authority
    # from other settings
    from contrail.security.ca.impl import CertificateAuthority
    return CertificateAuthority.from_keywords(
        cert = settings.CA_CERT,
        key = settings.CA_KEY,
        min_key_nbits = settings.MIN_KEY_BITS,
        not_before_time_nsecs = settings.NOT_BEFORE_TIME_NSECS,
        not_after_time_nsecs = settings.NOT_AFTER_TIME_NSECS
    )


def load_pem_encoded_cert(path):
    """
    Attempts to load a PEM-encoded certificate from the given path.

    Raises ``ImproperlyConfigured`` if the path does not contain a valid
    certificate.
    """
    try:
        with open(path) as cert_file:
            cert = cert_file.read()
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    except Exception:
        raise ImproperlyConfigured(
            'Failed to parse PEM-encoded certificate: {}'.format(path)
        )


def default_ca_cert(settings):
    """
    Load the CA cert from the path specified in the ``CA_CERT_PATH`` setting.
    """
    return load_pem_encoded_cert(settings.CA_CERT_PATH)


def default_ca_key(settings):
    """
    Load the CA key from the path specified in the ``CA_KEY_PATH`` setting. If
    the key is protected by a password, the password should also be given in the
    ``CA_KEY_PASSWORD`` setting.
    """
    with open(settings.CA_KEY_PATH) as key_file:
        key = key_file.read()
    password = settings.CA_KEY_PASSWORD
    return crypto.load_privatekey(
        crypto.FILETYPE_PEM, key, *([password] if password else [])
    )


def default_ca_cert_chain(settings):
    """
    Load the certificates for the CA trust chain from the paths specified in the
    ``CA_CERT_CHAIN_PATHS`` setting.
    """
    return [
        load_pem_encoded_cert(path)
        for path in settings.CA_CERT_CHAIN_PATHS
    ]


class OnlineCASettings(SettingsObject):
    #: Directory containing the trustroots for the CA.
    TRUSTROOTS_DIR = Setting()
    #: Function for generating a certificate subject name for the current request.
    SUBJECT_NAME_GENERATOR = ImportStringSetting(
        default = 'onlineca.utils.default_subject_name_generator'
    )
    #: Template used by :py:func:`onlineca.utils.default_subject_name_generator`.
    SUBJECT_NAME_TEMPLATE = Setting()
    #: Certificate authority object used to issue certificates.
    CERTIFICATE_AUTHORITY = Setting(default = default_certificate_authority)
    #: X509 certificate object to use for the certificate authority.
    CA_CERT = Setting(default = default_ca_cert)
    #: Path to file containing the PEM-encoded certificate for the CA.
    CA_CERT_PATH = Setting()
    #: Private key object to use for the certificate authority.
    CA_KEY = Setting(default = default_ca_key)
    #: Path to file containing the PEM-encoded, possibly encrypted private key
    #: for the CA.
    CA_KEY_PATH = Setting()
    #: Private key password if file given in :py:attr:`CA_KEY_PATH`.
    CA_KEY_PASSWORD = Setting(default = None)
    #: The minimum number of bits allowed in issued certificates.
    MIN_KEY_BITS = Setting(default = 2048)
    #: The number of seconds from issuing until the certificate becomes valid.
    NOT_BEFORE_TIME_NSECS = Setting(default = 0)
    #: The number of seconds from issuing that the certificate remains valid.
    NOT_AFTER_TIME_NSECS = Setting(default = 259200)  # Default 72 hours
    #: List of X509 certificate objects comprising the trust chain for the CA.
    CA_CERT_CHAIN = Setting(default = default_ca_cert_chain)
    #: List of paths containing the PEM-encoded certificates comprising the
    #: trust chain for the CA.
    CA_CERT_CHAIN_PATHS = Setting(default = ())


onlineca_settings = OnlineCASettings('ONLINECA', getattr(settings, 'ONLINECA', {}))
