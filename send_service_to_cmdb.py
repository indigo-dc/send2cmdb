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
        description='Write service to CMDB',
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
        '--service-id',
        required=True,
        help=('Service ID'))
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help=('Verbose output'))
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help=('Debug output'))
    return parser.parse_args()

class SendServiceToCMDB(object):
    """
       Send service to CMDB
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
        self.service_id = opts.service_id
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

    def get_service(self):
        """
            Get service object from standard input
        """
        json_input = ''
        for line in sys.stdin.readlines():
            json_input += line.strip().rstrip('\n')
        self.service = json_input

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

    def get_service_rev(self):
        """
            Get current revision of service in CMDB or None if service doesn't exist
        """
        url = self.cmdb_read_url + '/service/id/' + self.service_id
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        r = requests.get(url, headers=headers, verify=self.cmdb_verify_cert)
        if r.status_code == requests.codes.ok:
            json_answer = r.json()
            cmdb_service_rev = json_answer['_rev']
            logging.debug("Service rev: %s" % cmdb_service_rev)
            return cmdb_service_rev
        return None

    def write_service(self):
        """
            Write service to CMDB
        """
        cmdb_service_rev = self.get_service_rev()

        url = self.cmdb_write_url + '/' + self.service_id
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        if cmdb_service_rev == None:
            data = '{"type":"service","data":%s}' % self.service
        else:
            data = '{"_rev":"%s","type":"service","data":%s}' % (cmdb_service_rev, self.service)
        r = requests.put(url, headers=headers, data=data, verify=self.cmdb_verify_cert)
        if r.status_code == requests.codes.created:
            json_answer = r.json()
            cmdb_service_id = json_answer['id']
            cmdb_service_rev = json_answer['rev']
            logging.info("Successfully imported service id=%s rev=%s" % (cmdb_service_id, cmdb_service_rev))
        else:
            logging.error("Unable to write service: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

def main():
    """
        Use SendServiceToCMDB class to write service to the CMDB
    """
    opts = parse_opts()
    sender = SendServiceToCMDB(opts)
    sender.get_service()
    sender.get_token()
    sender.write_service()

if __name__ == '__main__':
    main()
