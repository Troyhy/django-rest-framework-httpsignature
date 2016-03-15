from rest_framework import authentication
from rest_framework import exceptions
from httpsig import HeaderSigner, HeaderVerifier
from httpsig.utils import HttpSigException

import re


class SignatureAuthentication(authentication.BaseAuthentication):

    SIGNATURE_RE = re.compile('signature="(.+?)"')
    SIGNATURE_HEADERS_RE = re.compile('headers="([\(\)\sa-z0-9-]+?)"')
    KEYID_RE = re.compile('.*keyId="(.*?)".*')

    API_KEY_HEADER = 'X-Api-Key'
    ALGORITHM = 'hmac-sha256'
    REQUIRED_HEADERS = ['date']

    def get_signature_from_signature_string(self, signature):
        """Return the signature from the signature header or None."""
        match = self.SIGNATURE_RE.search(signature)
        if not match:
            return None
        return match.group(1)

    def get_keyid_from_auth_string(self, auth_header):
        """Return the signature from the signature header or None."""
        match = self.KEYID_RE.search(auth_header)
        if not match:
            return None
        return match.group(1)

    def get_headers_from_signature(self, signature):
        """Returns a list of headers fields to sign.

        According to http://tools.ietf.org/html/draft-cavage-http-signatures-03
        section 2.1.3, the headers are optional. If not specified, the single
        value of "Date" must be used.
        """
        match = self.SIGNATURE_HEADERS_RE.search(signature)
        if not match:
            return ['date']
        headers_string = match.group(1)
        return headers_string.split()

    def header_canonical(self, header_name):
        """Translate HTTP headers to Django header names."""
        # Translate as stated in the docs:
        # https://docs.djangoproject.com/en/1.6/ref/request-response/#django.http.HttpRequest.META
        header_name = header_name.lower()
        if header_name == 'content-type':
            return 'CONTENT-TYPE'
        elif header_name == 'content-length':
            return 'CONTENT-LENGTH'
        return 'HTTP_%s' % header_name.replace('-', '_').upper()

    def build_dict_to_sign(self, request, signature_headers):
        """Build a dict with headers and values used in the signature.

        "signature_headers" is a list of lowercase header names.
        """
        d = {}
        for header in signature_headers:
            if header == '(request-target)':
                continue
            d[header] = request.META.get(self.header_canonical(header))
        return d

    def build_signature(self, user_api_key, user_secret, request):
        """Return the signature for the request."""
        path = request.get_full_path()
        sent_signature = request.META.get(
            self.header_canonical('Authorization'))
        signature_headers = self.get_headers_from_signature(sent_signature)
        unsigned = self.build_dict_to_sign(request, signature_headers)

        # Sign string and compare.
        signer = HeaderSigner(
            key_id=user_api_key, secret=user_secret,
            headers=signature_headers, algorithm=self.ALGORITHM)
        signed = signer.sign(unsigned, method=request.method, path=path)
        return signed['authorization']

    def fetch_user_data(self, api_key):
        """Retuns (User instance, API Secret) or None if api_key is bad."""
        return None

    def authenticate(self, request):

        # Check if request has a "Signature" request header.
        authorization_header = self.header_canonical('Authorization')
        auth_string = request.META.get(authorization_header)
        if not auth_string:
            raise exceptions.AuthenticationFailed('No signature provided')

        # Check for API key header.
        api_key = None
        if self.ALGORITHM.lower().startswith('rsa'):
            api_key = self.get_keyid_from_auth_string(auth_string)
        else:
            api_key_header = self.header_canonical(self.API_KEY_HEADER)
            api_key = request.META.get(api_key_header)

        if not api_key:
            raise exceptions.AuthenticationFailed('No api key provided')

        # Fetch credentials for API key from the data store.
        try:
            user, secret = self.fetch_user_data(api_key)
        except TypeError:
            raise exceptions.AuthenticationFailed('Bad API key')

        # Build string to sign from "headers" part of Signature value.
        path = request.get_full_path()
        sent_signature = request.META.get(
            self.header_canonical('Authorization'))
        host = request.META.get(self.header_canonical('Host'))
        signature_headers = self.get_headers_from_signature(sent_signature)
        unsigned = self.build_dict_to_sign(request, signature_headers)

        unsigned.update({'authorization': auth_string})

        #unsigned['date'] = unsigned['date'] + 'd'

        try:
            hv = HeaderVerifier(headers=unsigned,
                                secret=secret,
                                required_headers=self.REQUIRED_HEADERS,
                                method=request.method,
                                path=path,
                                host=host)
        except (HttpSigException, KeyError, Exception) as e:
            raise exceptions.AuthenticationFailed(str(e))

        try:
            if not hv.verify():
                raise exceptions.AuthenticationFailed('Bad signature')
        except Exception as e:
            raise exceptions.AuthenticationFailed(str(e))

        return (user, api_key)
