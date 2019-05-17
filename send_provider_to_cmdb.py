#!/usr/bin/env python

import argparse
import json
import logging
import sys
import requests

def parse_opts():
    """
        Parse CLI arguments
    """
    parser = argparse.ArgumentParser(
        description='Write provider to CMDB',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        fromfile_prefix_chars='@',
        conflict_handler="resolve",
    )
    parser.add_argument(
        '--cmdb-read-url',
        required=True,
        help=('URL of the CMDB endpoint'))
    parser.add_argument(
        '--cmdb-write-url',
        required=True,
        help=('URL of the CMDB endpoint'))
    parser.add_argument(
        '--cmdb-allow-insecure',
        action='store_true',
        help=('Allow insecure connection to the CMDB endpoint'))
    parser.add_argument(
        '--oidc-token-url',
        required=True,
        help=('OpenID Connect token endpoint'))
    parser.add_argument(
        '--oidc-client-id',
        required=True,
        help=('OpenID Connect Client ID'))
    parser.add_argument(
        '--oidc-client-secret',
        required=True,
        help=('OpenID Connect Client Secret'))
    parser.add_argument(
        '--oidc-username',
        required=True,
        help=('OpenID Connect username'))
    parser.add_argument(
        '--oidc-password',
        required=True,
        help=('OpenID Connect password'))
    parser.add_argument(
        '--provider-id',
        required=True,
        help=('Provider ID'))
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help=('Verbose output'))
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help=('Debug output'))
    return parser.parse_args()

class SendProviderToCMDB(object):
    """
       Send provider to CMDB
    """

    def __init__(self, opts):
        """
            Initialize required instance variable from the parameters
        """
        self.opts = opts
        self.cmdb_read_url = opts.cmdb_read_url
        self.cmdb_write_url = opts.cmdb_write_url
        self.cmdb_verify_cert = not opts.cmdb_allow_insecure
        self.token_url = opts.oidc_token_url
        self.client_id = opts.oidc_client_id
        self.client_secret = opts.oidc_client_secret
        self.oidc_username = opts.oidc_username
        self.oidc_password = opts.oidc_password
        self.provider_id = opts.provider_id
        self.debug = opts.debug
        self.verbose = opts.verbose
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
            logging.getLogger('requests').setLevel(logging.DEBUG)
            logging.getLogger('urllib3').setLevel(logging.DEBUG)
        elif self.verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('requests').setLevel(logging.WARNING)
            logging.getLogger('urllib3').setLevel(logging.WARNING)

    def get_provider(self):
        """
            Get provider object from standard input
        """
        json_input = ''
        for line in sys.stdin.readlines():
            json_input += line.strip().rstrip('\n')
        self.provider = json_input

    def get_token(self):
        """
            Get access token from IAM
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.oidc_username,
            'password': self.oidc_password,
            'grant_type': 'password',
            'scope': 'openid email profile'
        }
        r = requests.post(self.token_url, data=data)
        if r.status_code == requests.codes.ok:
            json_answer = r.json()
            self.oidc_token = json_answer['access_token']
            logging.debug("Access token: %s" % self.oidc_token)
        else:
            logging.error("Unable to get access token: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

    def write_provider(self):
        """
            Write provider to CMDB
        """
        url = self.cmdb_write_url + '/' + self.provider_id
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        data = '{"type":"provider","data":%s}' % self.provider
        r = requests.put(url, headers=headers, data=data, verify=self.cmdb_verify_cert)
        if r.status_code == requests.codes.created:
            json_answer = r.json()
            cmdb_provider_id = json_answer['id']
            cmdb_provider_rev = json_answer['rev']
            logging.info("Successfully imported provider id=%s rev=%s" % (cmdb_provider_id, cmdb_provider_rev))
        else:
            logging.error("Unable to write provider: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

def main():
    """
        Use SendProviderToCMDB class to write provider to the CMDB
    """
    opts = parse_opts()
    sender = SendProviderToCMDB(opts)
    sender.get_provider()
    sender.get_token()
    sender.write_provider()

if __name__ == '__main__':
    main()
