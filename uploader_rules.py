#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>

import argparse
import glob
import json
import logging
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
    parser.add_argument('-r', '--rules-dir', default='rules', help='Directory containing rules in Auth0 format')
    args = parser.parse_args()

    config = DotDict({'client_id': args.clientid, 'client_secret': args.clientsecret, 'uri': args.uri})
    authzero = AuthZero(config)
    authzero.get_access_token()
    logger.debug("Got access token for client_id:{}".format(args.clientid))

    # on any error, `authzero` will raise an exception and python will exit with non-zero code

    # Remote rules loader
    remote_rules = authzero.get_rules()
    logger.debug("Loaded {} remote rules from current Auth0 deployment".format(len(remote_rules)))

    # Local rules loader
    if not os.path.isdir(args.rules_dir):
        raise Exception('NotARulesDirectory' (args.rules_dir))

    # Process all local rules
    local_rules_files = glob.glob("{}/*.json".format(args.rules_dir))
    local_rules = []
    for rfile in local_rules_files:
        logger.debug("Reading local rule configuration {}".format(rfile))
        rule = AuthZeroRule()
        # Overload the object with our own statuses
        rule.is_new = False
        rule.is_the_same = False

        # Rule name comes from the filename with the auth0 format
        rule.name = rfile.split('/')[-1].split('.')[:-1][0]
        with open(rfile, 'r') as fd:
            rule_conf = DotDict(json.load(fd))
        rule.enabled = bool(rule_conf.enabled)
        rule.order = int(rule_conf.order)

        rcfile = rfile.rstrip('on') # Equivalent to s/blah.json/blah.js/
        logger.debug("Reading local rule code {}".format(rcfile))
        with open(rcfile, 'r') as fd:
            rule.script = fd.read()

        # Match with existing remote rule if we need to update.. this uses the rule name!
        rule_nr = [i for i,_ in enumerate(remote_rules) if _.get('name') == rule.name]
        if rule_nr:
            # If there's multi matches it means we have duplicate rule names and we're screwed.
            # To fix that we'd need to change the auth0 local format to use rule ids (which we could eventually)
            if (len(rule_nr) > 1):
                raise Exception('RuleMatchByNameFailed', (rule.name, rule_nr))
            rule.id = remote_rules[rule_nr[0]].get('id')
            rule.is_new = False

            # Is the rule different?
            remote_rule = remote_rules[rule_nr[0]]
            rule.is_the_same = (rule.script == remote_rule.get('script')) & (rule.enabled == bool(remote_rule.get('enabled'))) \
                   & (rule.stage == remote_rule.get('stage')) & (rule.order == remote_rule.get('order'))

        else:
            # No remote rule match, so it's a new rule
            logger.debug('Rule only exists locally, considered new and to be created: {}'.format(rule.name))
            rule.is_new = True

        if not rule.validate():
            logger.error('Rule failed validation: {}'.format(rule.name))
            sys.exit(127)
        else:
            local_rules.append(rule)
    logger.debug("Found {} local rules".format(len(local_rules)))

    # Find dead rules (i.e. to remove/rules that only exist remotely)
    remove_rules = []
    for rl in local_rules:
        ok = False
        rr = None
        for rr in remote_rules:
            if (rl.id == rr.get('id')) or (rl.is_new):
                ok = True
                continue
        if not ok and rr is not None:
            remove_rules.append(rr)
    logger.debug("Found {} rules that not longer exist locally and will be deleted remotely".format(len(remove_rules)))

    # Update or create (or delete) rules as needed
    ## Delete first in case we need to get some order numbers free'd
    for r in remove_rules:
        logger.debug("[-] Removing rule {} ({}) from Auth0".format(r.name, r.id))
        authzero.delete_rule(r.id)

    ## Update & Create (I believe this may be atomic swaps for updates)
    for r in local_rules:
        if r.is_new:
            logger.debug("[+] Creating new rule {} on Auth0".format(r.name))
            ret = authzero.create_rule(r)
            logger.debug("+ New rule created with id {}".format(ret.get('id')))
        elif r.is_the_same:
            logger.debug("[=] Rule {} is unchanged, will no update".format(r.name))
        else:
            logger.debug("[~] Updating rule {} ({}) on Auth0".format(r.name, r.id))
            authzero.update_rule(r.id, r)

    sys.exit(0)
