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
        description='Write images to CMDB',
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

class SendImagesToCMDB(object):
    """
       Send images to CMDB
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

    def get_images(self):
        """
            Get image list from standard input
        """
        json_input = ''
        for line in sys.stdin.readlines():
            json_input += line.strip().rstrip('\n')
        self.images = json.loads(json_input)

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

    def get_cmdb_images_ids(self):
        """
            Get ids of all images of the service from CMDB
        """
        url = self.cmdb_read_url + '/service/id/' + self.service_id + '/has_many/images?include_docs=true'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        r = requests.get(url, headers=headers, verify=self.cmdb_verify_cert)
        if r.status_code == requests.codes.ok:
            json_answer = r.json()
            json_images = json_answer["rows"]
            self.cmdb_images_ids = {}
            if len(json_images) > 0:
                for image in json_images:
                    image_id = image['doc']['data']['image_id']
                    cmdb_image = { 'doc_id': image['id'], 'doc_rev': image['doc']['_rev'] }
                    self.cmdb_images_ids[image_id] = cmdb_image
        else:
            logging.error("Unable to get images of service: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

    def write_image(self, image):
        """
            Write image to CMDB
        """
        image['service'] = self.service_id
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        image_id = image['image_id']
        if image_id in self.cmdb_images_ids.keys():
            doc_id = self.cmdb_images_ids[image_id]['doc_id']
            doc_rev = self.cmdb_images_ids[image_id]['doc_rev']
            url = self.cmdb_write_url + '/' + doc_id
            data = '{"_rev":"%s","type":"image","data":%s}' % (doc_rev, json.dumps(image))
            r = requests.put(url, headers=headers, data=data, verify=self.cmdb_verify_cert)
        else:
            url = self.cmdb_write_url
            data = '{"type":"image","data":%s}' % json.dumps(image)
            r = requests.post(url, headers=headers, data=data, verify=self.cmdb_verify_cert)
        if r.status_code == requests.codes.created:
            json_answer = r.json()
            doc_id = json_answer['id']
            doc_rev = json_answer['rev']
            logging.info("Successfully imported image id=%s rev=%s" % (doc_id, doc_rev))
        else:
            logging.error("Unable to write image: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

    def delete_image(self, doc_id, rev):
        """
           Delete image from CMDB
        """
        url = self.cmdb_write_url + '/' + doc_id + '?rev=' + rev
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer %s" % self.oidc_token
        }
        r = requests.delete(url, headers=headers, verify=self.cmdb_verify_cert)
        if r.status_code in (requests.codes.ok, requests.codes.created):
            logging.info("Deleted image id=%s rev=%s" % (doc_id, rev))
        else:
            logging.error("Unable to delete image: %s" % r.status_code)
            logging.error("Response %s" % r.text)
            sys.exit(1)

    def write_images(self):
        """
            Get ids of all images of the service from CMDB,
            then upload new and updated images and delete images no more present
        """
        self.get_cmdb_images_ids()

        for image in self.images:
            self.write_image(image)

        new_images_ids = [image['image_id'] for image in self.images]
        for image_id, image in self.cmdb_images_ids.items():
            if image_id not in new_images_ids:
                doc_id = image['doc_id']
                doc_rev = image['doc_rev']
                self.delete_image(doc_id, doc_rev)

def main():
    """
        Use SendImagesToCMDB class to write images to the CMDB
    """
    opts = parse_opts()
    sender = SendImagesToCMDB(opts)
    sender.get_images()
    sender.get_token()
    sender.write_images()

if __name__ == '__main__':
    main()
