# -*- coding: utf-8 -*-
"""
Django views for the django-onlineca package.
"""

import os
import base64
import logging
import binascii

from OpenSSL import crypto

from django.views.decorators.http import require_safe, require_POST
from django import http

from .settings import onlineca_settings
from .utils import x509_name


log = logging.getLogger("onlineca")


@require_safe
def trustroots(request):
    """
    Handler for ``/trustroots/``.

    Returns the set of trust roots (CA certificates and associated signing policy
    files) needed to trust this service.
    """
    trust_roots = b''
    for filename in os.listdir(onlineca_settings.TRUSTROOTS_DIR):
        filepath = os.path.join(onlineca_settings.TRUSTROOTS_DIR, filename)
        if os.path.isdir(filepath):
            continue
        with open(filepath, 'rb') as trustroot_file:
            content = trustroot_file.read()
        trust_roots += b'%s=%s\n' % (filename.encode('utf-8'),
                                     base64.b64encode(content))
    return http.HttpResponse(content = trust_roots, content_type = 'text/plain')


@require_POST
def certificate(request):
    """
    Handler for ``/certificate/``.

    Issues a new user certificate from the given Certificate Signing Request.

    The user must be authenticated before entering this view, either by
    middleware or by decorating this view.
    """
    # The user must be authenticated somehow
    # We don't use the login_required decorator because we have no opinion on
    # how that happens.
    if not request.user.is_authenticated:
        return http.HttpResponse(status = 403)

    csr = request.POST.get('certificate_request')
    if not csr:
        return http.HttpResponse(
            status = 400,
            content = 'Missing POST parameter certificate_request.',
            content_type = 'text/plain'
        )

    log.info('Issuing cert for csr: %r', csr)

    # We support PEM-encoded or base64-encoded ASN1 CSRs.
    try:
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    except crypto.Error:
        # Re-try, this time interpreting the text as a base64 encoded value
        try:
            decoded = base64.b64decode(csr)
            csr = crypto.load_certificate_request(crypto.FILETYPE_ASN1, decoded)
        except (binascii.Error, crypto.Error):
            log.exception('Error loading input csr: %r', csr)
            return http.HttpResponse(
                status = 400,
                content = 'Error loading certificate request.',
                content_type = 'text/plain'
            )

    # Get the subject name using the configured generator
    subject_name = x509_name(onlineca_settings.SUBJECT_NAME_GENERATOR(request))

    # Issue the certificate
    cert = onlineca_settings.CERTIFICATE_AUTHORITY.issue_certificate(
        csr,
        subject_name = subject_name
    )

    # Dump the certificate in PEM format
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    # Add any additional CA certificates in the trust chain
    for ca_cert in onlineca_settings.CA_CERT_CHAIN:
        cert_pem += crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
    # Return the issued certificate
    return http.HttpResponse(content = cert_pem, content_type = 'text/plain')
