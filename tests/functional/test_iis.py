import unittest2 as unittest
import requests
import ssl
import hashlib
import re

from socket import socket
from requests.auth import AuthBase
from ntlm_auth import ntlm

"""
    These tests are functional tests to test out the NTLM calculations and message structures with an actual Microsoft
    server rather than documented examples. Because it is reliant on IIS being present this can only run on the tests
    on appveyor and not travis-ci or locally. If these tests past it is a fairly good indication that everything works
    as expected in a real life scenario.

    This will test out all 4 NTLM compatibility levels (0-3) that affect client behaviour and test out their response
    code as well as if we can get the IIS page's contents. The credentials, urls and expected contents are all set up
    in the appveyor/setup_iis.ps1 script. There are 4 types of scenarios that will be tested with each compatibility level;
        1. A HTTP site that has Extended Protection set to None
        2. A HTTP site that has Extended Protection set to Require (CBT Required)
        3. A HTTPS site that has Extended Protection set to None
        4. A HTTPS site that has Extended Protection set to Require (CBT Required)
    Theoretically 1 and 2 are the same as CBT is only checked when running over HTTPS but it is best to verify.
    Scenario 4 would only work when running with the compatibility level of 3 as CBT support was only added in NTLMv2
    authentication.
"""

user = 'User'
domain = '.'
password = 'Password01'
http_with_cbt = 'http://127.0.0.1:81/contents.txt'
http_without_cbt = 'http://127.0.0.1:82/contents.txt'
https_with_cbt = 'https://127.0.0.1:441/contents.txt'
https_without_cbt = 'https://127.0.0.1:442/contents.txt'
expected = 'contents'

class Test_Functional(unittest.TestCase):
    def test_ntlm_0_http_with_cbt(self):
        actual = send_request(http_with_cbt, user, domain, password, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_0_http_without_cbt(self):
        actual = send_request(http_without_cbt, user, domain, password, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_0_https_with_cbt(self):
        actual = send_request(https_with_cbt, user, domain, password, 0)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_0_https_without_cbt(self):
        actual = send_request(https_without_cbt, user, domain, password, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_1_http_with_cbt(self):
        actual = send_request(http_with_cbt, user, domain, password, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_1_http_without_cbt(self):
        actual = send_request(http_without_cbt, user, domain, password, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_1_https_with_cbt(self):
        actual = send_request(https_with_cbt, user, domain, password, 1)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_1_https_without_cbt(self):
        actual = send_request(https_without_cbt, user, domain, password, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_2_http_with_cbt(self):
        actual = send_request(http_with_cbt, user, domain, password, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_2_http_without_cbt(self):
        actual = send_request(http_without_cbt, user, domain, password, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_2_https_with_cbt(self):
        actual = send_request(https_with_cbt, user, domain, password, 2)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_2_https_without_cbt(self):
        actual = send_request(https_without_cbt, user, domain, password, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_3_http_with_cbt(self):
        actual = send_request(http_with_cbt, user, domain, password, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_3_http_without_cbt(self):
        actual = send_request(http_without_cbt, user, domain, password, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_3_https_with_cbt(self):
        actual = send_request(https_with_cbt, user, domain, password, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        # Only case where CBT should work as we are using NTLMv2 as the auth type
        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_3_https_without_cbt(self):
        actual = send_request(https_without_cbt, user, domain, password, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected


def send_request(url, username, domain, password, ntlm_compatibility):
    """
    Sends a request to the url with the credentials specified. Returns the final response
    """
    session = requests.Session()
    session.verify = False
    session.auth = NtlmAuth(username, domain, password, ntlm_compatibility)
    request = requests.Request('GET', url)
    prepared_request = session.prepare_request(request)
    response = session.send(prepared_request)

    return response

class NtlmAuth(AuthBase):
    def __init__(self, username, domain, password, ntlm_compatibility):
        self.username = username
        self.domain = domain.upper()
        self.password = password
        self.ntlm_context = ntlm.Ntlm(ntlm_compatibility=ntlm_compatibility)

    def __call__(self, response):
        response.headers['Connection'] = 'Keep-Alive'
        response.register_hook('response', self.hook)
        return response

    def hook(self, response, **kwargs):
        if response.status_code == 401:
            return self.retry_with_ntlm_auth('www-authenticate', 'Authorization', response, 'NTLM', kwargs)
        else:
            return response

    def retry_with_ntlm_auth(self, auth_header_field, auth_header, response, auth_type, args):
        # Consume the original response contents and release the connection for later
        response.content
        response.raw.release_conn()

        # Create the negotiate request
        negotiate_request = response.request.copy()
        negotiate_header_value = self.ntlm_context.create_negotiate_message(self.domain)
        negotiate_header = auth_type + ' ' + negotiate_header_value.decode('ascii')
        negotiate_request.headers[auth_header] = negotiate_header

        # Send the negotiate request and receive the challenge message
        disable_stream_args = dict(args, stream=False)
        challenge_response = response.connection.send(negotiate_request, **disable_stream_args)
        challenge_response.content
        challenge_response.raw.release_conn()

        # Parse the challenge response in the ntlm_context
        challenge_response_auth_header = challenge_response.headers[auth_header_field]
        challenge_response_auth_value = challenge_response_auth_header.replace(auth_type + ' ', '')
        self.ntlm_context.parse_challenge_message(challenge_response_auth_value)

        # Create the authenticate request
        authenticate_request = challenge_response.request.copy()
        server_certificate_hash = self._get_server_cert(authenticate_request.url)
        authenticate_header_value = self.ntlm_context.create_authenticate_message(self.username, self.password, self.domain, server_certificate_hash=server_certificate_hash)
        authenticate_header = auth_type + ' ' + authenticate_header_value.decode('ascii')
        authenticate_request.headers[auth_header] = authenticate_header

        # Send the authenticate request
        final_response = challenge_response.connection.send(authenticate_request, **args)
        final_response.history.append(response)
        final_response.history.append(challenge_response)

        return final_response

    def _get_server_cert(self, request_url):
        """
        Gets the server's SHA256 hash to use when setting up Channel Binding Tokens in NTLMv2 messages
        """
        if request_url.startswith('https://'):
            host_pattern = re.compile('(?i)^(https://)?(?P<host>[0-9a-z-_.]+)(:(?P<port>\d+))?')
            match = host_pattern.match(request_url)

            if match:
                host = match.group('host')
                port = match.group('port')

                if not port:
                    port = 443
                else:
                    port = int(port)

                s = socket()
                c = ssl.wrap_socket(s)
                c.connect((host, port))
                server_certificate = c.getpeercert(True)
                hash_object = hashlib.sha256(server_certificate)
                server_certificate_hash = hash_object.hexdigest().upper()
            else:
                server_certificate_hash = None

            return server_certificate_hash
        else:
            return None