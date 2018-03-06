# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import struct
from ntlm_auth.constants import NegotiateFlags
from ntlm_auth.messages import AuthenticateMessage, ChallengeMessage, \
    NegotiateMessage
from ntlm_auth.session_security import SessionSecurity


class Ntlm(object):

    def __init__(self, ntlm_compatibility=3):
        """
        Initialises the NTLM context to use when sending and receiving messages
        to and from the server. You should be using this object as it supports
        NTLMv2 authenticate and it easier to use than before. It also brings in
        the ability to use signing and sealing with session_security and
        generate a MIC structure.

        :param ntlm_compatibility: (Default 3)
            The Lan Manager Compatibility Level to use with the auth message
            This is set by an Administrator in the registry key
            'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
            The values correspond to the following;
                0 : LM and NTLMv1
                1 : LM, NTLMv1 and NTLMv1 with Extended Session Security
                2 : NTLMv1 and NTLMv1 with Extended Session Security
                3-5 : NTLMv2 Only
            Note: Values 3 to 5 are no different from a client perspective

        Attributes:
            negotiate_flags: A NEGOTIATE structure that contains a set of bit
                flags. These flags are the options the client supports and are
                sent in the negotiate_message
            ntlm_compatibility: The Lan Manager Compatibility Level, same as
                the input if supplied
            negotiate_message: A NegotiateMessage object that is sent to the
                server
            challenge_message: A ChallengeMessage object that has been created
                from the server response
            authenticate_message: An AuthenticateMessage object that is sent to
                the server based on the ChallengeMessage
            session_security: A SessionSecurity structure that can be used to
                sign and seal messages sent after the authentication challenge
        """
        self.ntlm_compatibility = ntlm_compatibility

        # Setting up our flags so the challenge message returns the target info
        # block if supported
        self.negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_128 | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_56 | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL

        # Setting the message types based on the ntlm_compatibility level
        self._set_ntlm_compatibility_flags(self.ntlm_compatibility)

        self.negotiate_message = None
        self.challenge_message = None
        self.authenticate_message = None
        self.session_security = None

    def create_negotiate_message(self, domain_name=None, workstation=None):
        """
        Create an NTLM NEGOTIATE_MESSAGE

        :param domain_name: The domain name of the user account we are
            authenticating with, default is None
        :param worksation: The workstation we are using to authenticate with,
            default is None
        :return: A base64 encoded string of the NEGOTIATE_MESSAGE
        """
        self.negotiate_message = NegotiateMessage(self.negotiate_flags,
                                                  domain_name, workstation)

        return base64.b64encode(self.negotiate_message.get_data())

    def parse_challenge_message(self, msg2):
        """
        Parse the NTLM CHALLENGE_MESSAGE from the server and add it to the Ntlm
        context fields

        :param msg2: A base64 encoded string of the CHALLENGE_MESSAGE
        """
        msg2 = base64.b64decode(msg2)
        self.challenge_message = ChallengeMessage(msg2)

    def create_authenticate_message(self, user_name, password,
                                    domain_name=None, workstation=None,
                                    server_certificate_hash=None):
        """
        Create an NTLM AUTHENTICATE_MESSAGE based on the Ntlm context and the
        previous messages sent and received

        :param user_name: The user name of the user we are trying to
            authenticate with
        :param password: The password of the user we are trying to authenticate
            with
        :param domain_name: The domain name of the user account we are
            authenticated with, default is None
        :param workstation: The workstation we are using to authenticate with,
            default is None
        :param server_certificate_hash: The SHA256 hash string of the server
            certificate (DER encoded) NTLM is authenticating to. Used for
            Channel Binding Tokens. If nothing is supplied then the CBT hash
            will not be sent. See messages.py AuthenticateMessage for more
            details
        :return: A base64 encoded string of the AUTHENTICATE_MESSAGE
        """
        self.authenticate_message = \
            AuthenticateMessage(user_name, password, domain_name, workstation,
                                self.challenge_message,
                                self.ntlm_compatibility,
                                server_certificate_hash)
        self.authenticate_message.add_mic(self.negotiate_message,
                                          self.challenge_message)

        # Setups up the session_security context used to sign and seal messages
        # if wanted
        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL or \
                self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN:
            flags = self.authenticate_message.negotiate_flags
            flag_bytes = struct.unpack("<I", flags)[0]
            self.session_security = \
                SessionSecurity(flag_bytes,
                                self.authenticate_message.exported_session_key)

        return base64.b64encode(self.authenticate_message.get_data())

    def _set_ntlm_compatibility_flags(self, ntlm_compatibility):
        if (ntlm_compatibility >= 0) and (ntlm_compatibility <= 5):
            if ntlm_compatibility == 0:
                self.negotiate_flags |= \
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
                    NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
            elif ntlm_compatibility == 1:
                self.negotiate_flags |= \
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
                    NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            else:
                self.negotiate_flags |= \
                    NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        else:
            raise Exception("Unknown ntlm_compatibility level - "
                            "expecting value between 0 and 5")
