#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>

import argparse
import json
import logging
import sys
from authzero import AuthZero

class DotDict(dict):
    """return a dict.item notation for dict()'s"""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

if __name__ == "__main__":
    # Logging
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=sys.stdout)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Default credentials loading
    try:
        with open('credentials.json', 'r') as fd:
            credentials = DotDict(json.load(fd))
            require_creds = False
    except FileNotFoundError:
        credentials = DotDict({'client_id': '', 'client_secret': '', 'uri': 'auth-dev.mozilla.auth0.com'})
        require_creds = True

    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--uri', default=credentials.uri, help='URI to Auth0 management API')
    parser.add_argument('-c', '--clientid', default=credentials.client_id, required=require_creds, help='Auth0 client id')
    parser.add_argument('-s', '--clientsecret', default=credentials.client_secret, required=require_creds, help='Auth0 client secret')
    parser.add_argument('--default-client', default='VNGM4quJw3Nhx28j8XKVYmu5LcPMCgAH',
                        help='Default Auth0 client id, needed for login page for example')
    parser.add_argument('--login-page', required=True, help='Auth0 hosted login page (HTML)')
    args = parser.parse_args()

    config = DotDict({'client_id': args.clientid, 'client_secret': args.clientsecret, 'uri': args.uri})
    authzero = AuthZero(config)
    authzero.get_access_token()
    logger.debug("Got access token for client_id:{}".format(args.clientid))

    client_attributes = DotDict(dict())
    with open(args.login_page, 'r', encoding='utf-8') as fd:
        client_attributes.custom_login_page = fd.read()
    # on any error, `authzero` will raise an exception and python will exit with non-zero code
    ret = authzero.update_client(args.default_client, client_attributes)
    trimmed_ret = {k: v if type(v) not in [unicode, str] else v[:128] for k, v in ret.iteritems()}
    logger.debug("Default client updated {}".format(json.dumps(trimmed_ret, indent=4)))
    sys.exit(0)
