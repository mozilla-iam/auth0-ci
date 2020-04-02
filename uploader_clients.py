#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>

import argparse
import difflib
import glob
import json
import logging
import logging.handlers
import os
import sys
from authzero import AuthZero,AuthZeroRule

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

def find_client_by_id(clients, client_id):
    """
    client_id: str - a client id
    clients: list - list of client objects
    Returns: client object or None
    """
    for c in clients:
        if (c.get('client_id') == client_id):
            return c
    return None

if __name__ == "__main__":
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
    parser.add_argument('-i', '--clientid', default=credentials.client_id, required=require_creds, help='Auth0 client id')
    parser.add_argument('-s', '--clientsecret', default=credentials.client_secret, required=require_creds, help='Auth0 client secret')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug mode')
    parser.add_argument('-v', '--verbose', action="store_true", help='Show log messages on stderr instead of sending to syslog')
    parser.add_argument('-r', '--clients-dir', default='clients', help='Directory containing clients in Auth0 format')
    parser.add_argument('--show-diff', action="store_true", help='Show a unified diff of the client being updated on stdout')
    parser.add_argument('-g', '--get-clients-only', action="store_true",
                        help='Get clients from the Auth0 deployment and write them to disk. This will make NO changes '
                        'to Auth0, but will OVERWRITE all local client files')
    args = parser.parse_args()

    # Logging
    logger = logging.getLogger(__name__)
    if not args.verbose:
        logger.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
    else:
        formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
        logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=sys.stderr)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    config = DotDict({'client_id': args.clientid, 'client_secret': args.clientsecret, 'uri': args.uri})
    authzero = AuthZero(config)
    authzero.get_access_token()
    logger.debug("Got access token for client_id:{}".format(args.clientid))

    # on any error, `authzero` will raise an exception and python will exit with non-zero code

    # Remote clients loader
    remote_clients = authzero.get_clients()
    logger.debug("Loaded {} remote clients from current Auth0 deployment".format(len(remote_clients)))

    if not os.path.isdir(args.clients_dir):
        raise Exception('NotAClientsDirectory' (args.clients_dir))


    # Write remote clients back to disk/local
    if args.get_clients_only:
        for client in remote_clients:
            with open("{}/{}.json".format(args.clients_dir, client.get('client_id')), 'w') as fd:
                fd.write(json.dumps(client, indent=4))
                logger.debug("Wrote local client configuration {}".format(client.get('client_id')))
        sys.exit(0)

    # Process all local clients
    local_clients_files = glob.glob("{}/*.json".format(args.clients_dir))
    local_clients = []
    for rfile in local_clients_files:
        logger.debug("Reading local clients configuration {}".format(rfile))
        with open(rfile, 'r') as fd:
            client = DotDict(json.load(fd))

        # Match with existing remote client to see if we need to update
        client_nr = [i for i,_ in enumerate(remote_clients) if _.get('client_id') == client.client_id]
        if client_nr:
            # Just in case we have dupe client_id's (this is not supposed to be possible)
            if (len(client_nr) > 1):
                raise Exception('ClientMatchByIdFailed', (client.name, client_nr))
        else:
            logger.debug('Client only exists locally, considered new and to be created: {}'.format(rule.name))

        local_clients.append(client)
    logger.debug("Found {} local clients".format(len(local_clients)))

    # Find dead clients (i.e. to remove clients that only exist remotely)
    remove_clients = []
    for rl in local_clients:
        if (find_client_by_id(local_clients, rl.client_id) is None):
            remove_clients.append(rr)
            continue
    logger.debug("Found {} clients that not longer exist locally and will be deleted remotely".format(len(remove_clients)))

    # Update or create (or delete) clients as needed
    for r in remove_clients:
        logger.debug("Removing remote client {} ({}) from Auth0".format(r.name, r.client_id))
        authzero.delete_client(r.client_id)

    ## Update & Create (I believe this may be atomic swaps for updates)
    for lclient in local_clients:
        if not lclient.client_id:
            logger.debug("Creating new remote client {} on Auth0".format(lclient.name))
            noop
            ret = authzero.create_client(r)
            logger.info("New remote client {} ({}) created on Auth0".format(ret.get('client_id'), ret.get('name')))
        else:
            rclient = find_client_by_id(remote_clients, lclient.client_id)
            if (rclient == lclient):
                logger.debug("Remote and local clients for id {} ({}) are identical, no need to "
                             "update".format(lclient.client_id, lclient.name))
                continue

            # Show pretty informational unified diff if requested, of the changes to be pushed to Auth0
            if args.show_diff:
                diff = difflib.unified_diff(json.dumps(rclient, indent=4).split('\n'),
                                            json.dumps(lclient, indent=4).split('\n'),
                                            fromfile="previous_{}.json".format(lclient.client_id),
                                            tofile="new_{}.json".format(lclient.client_id))
                print("Unified diff for client {} ({})".format(lclient.client_id, lclient.name))
                print('\n'.join(diff))

            logger.debug("Updating remote client {} ({}) on Auth0".format(lclient.name, lclient.client_id))
            authzero.update_client(lclient.client_id, lclient)
            logger.info("Client {} ({}) has been updated on Auth0".format(client.name, lclient.client_id))

    sys.exit(0)
