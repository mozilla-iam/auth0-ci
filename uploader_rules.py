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
from authzero import AuthZero, AuthZeroRule
import difflib


MAINTENANCE_RULE_NAME = 'default-deny-for-maintenance'


class NotARulesDirectory(Exception):
    pass


class DotDict(dict):
    """return a dict.item notation for dict()'s"""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dict_):
        super().__init__()
        for key, value in dict_.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value


def empty_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    elif os.listdir(directory):
        raise argparse.ArgumentTypeError(
            "Directory {} is not empty. Please choose either a directory "
            "which doesn't exist or an empty directory".format(directory))
    return directory

def parse_credential_files(filenames: list) -> tuple:
    # load the credentials file
    credentials = DotDict({
        'client_id': '',
        'client_secret': '',
        'uri': 'auth-dev.mozilla.auth0.com',
    })
    for filename in filenames:
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                credentials = DotDict(json.load(fd))

    return credentials

if __name__ == "__main__":
    CREDENTIAL_FILES = [
        os.path.join(os.path.expanduser('~'), '.config', 'auth0', 'credentials.json'),
        'credentials.json',
    ]

    # Logging
    logger_format = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=logger_format, datefmt="%H:%M:%S", stream=sys.stdout)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Load the default credentials
    credentials = parse_credential_files(CREDENTIAL_FILES)

    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default=None, help='Path to credentials.json')
    parser.add_argument('-u', '--uri', default=credentials.uri, help='URI to Auth0 management API')
    parser.add_argument('-i', '--clientid', default=credentials.client_id, help='Auth0 client id')
    parser.add_argument('-s', '--clientsecret', default=credentials.client_secret, help='Auth0 client secret')
    parser.add_argument('-r', '--rules-dir', default='rules', help='Directory containing rules in Auth0 format')
    parser.add_argument('-b', '--backup-rules-to-directory', type=empty_directory, metavar='DIRECTORY', help='Download all rules from the API and save them to this directory.')
    parser.add_argument('--delete-all-rules-first-causing-outage', action='store_true', help="Before uploading rules, delete all rules causing an outage")
    parser.add_argument('-d', '--dry-run', action='store_true', help="Show what would be done but don't actually make any changes")
    args = parser.parse_args()

    # if we specify a file manually, open that, otherwise walk through the list of CREDENTIAL_FILES
    if args.config is not None:
        if os.path.exists(args.config):
            credentials = parse_credential_files([args.config])
            args.clientid = credentials.client_id
            args.clientsecret = credentials.client_secret
            args.uri = credentials.uri
        else:
            logger.error('Credentials file {} does not exist'.format(args.config))
            sys.exit(1)

    if not args.clientid or not args.clientsecret:
        logger.error('Missing client id and/or client secret')
        sys.exit(1)

    authzero = AuthZero({
        'client_id': args.clientid,
        'client_secret': args.clientsecret,
        'uri': args.uri}
    )

    try:
        authzero.get_access_token()
    except Exception:
        logger.error('Unable to get access token for client_id: {}'.format(args.clientid))
        sys.exit(1)

    logger.debug("Got access token for client_id:{}".format(args.clientid))
    dry_run_message = 'Dry Run : Action not taken : ' if args.dry_run else ''

    # on any error, `authzero` will raise an exception and python will exit with non-zero code

    # Remote rules loader
    remote_rules = authzero.get_rules()
    logger.debug("Loaded {} remote rules from current Auth0 deployment".format(len(remote_rules)))

    if args.backup_rules_to_directory:
        for rule in remote_rules:
            js_filename = os.path.join(
                args.backup_rules_to_directory,
                '{}.js'.format(rule['name']))
            metadata_filename = js_filename + 'on'
            metadata = {
                'enabled': rule['enabled'],
                'order': rule['order']
            }
            logger.debug("{}Writing metadata file {}".format(
                dry_run_message, metadata_filename))
            if not args.dry_run:
                with open(metadata_filename, 'x') as f:
                    json.dump(metadata, f, sort_keys=True, indent=4, separators=(',', ': '))
            logger.debug("{}Writing js file {}".format(
                dry_run_message, js_filename))
            if not args.dry_run:
                with open(js_filename, 'x') as f:
                    f.write(rule['script'])
        print("To restore from this backup run {} --rules-dir {}".format(
            os.path.basename(__file__),
            args.backup_rules_to_directory
        ))
        sys.exit(0)

    # Local rules loader
    if not os.path.isdir(args.rules_dir):
        raise NotARulesDirectory(args.rules_dir)

    # Process all local rules
    local_rules_files = glob.glob("{}/*.json".format(args.rules_dir))
    local_rules = []
    for local_rules_file in local_rules_files:
        logger.debug("Reading local rule configuration {}".format(local_rules_file))
        local_rule = AuthZeroRule()
        # Overload the object with our own statuses
        local_rule.is_new = False
        local_rule.is_the_same = False

        # Rule name comes from the filename with the auth0 format
        local_rule.name = local_rules_file.split('/')[-1].split('.')[:-1][0]
        with open(local_rules_file, 'r') as fd:
            rule_conf = DotDict(json.load(fd))
        local_rule.enabled = bool(rule_conf.enabled)
        local_rule.order = int(rule_conf.order)

        local_rules_file_js = local_rules_file.rstrip('on')  # Equivalent to s/blah.json/blah.js/
        logger.debug("Reading local rule code {}".format(local_rules_file_js))
        with open(local_rules_file_js, 'r') as fd:
            local_rule.script = fd.read()

        if args.delete_all_rules_first_causing_outage and local_rule.name != MAINTENANCE_RULE_NAME:
            # If we're deleting all rules, then we will create all rules anew
            # after deletion with the exception of the maintenance rule
            remote_rule_indexes = []
        else:
            # Match with existing remote rule if we need to update.. this uses the rule name!
            remote_rule_indexes = [i for i, _ in enumerate(remote_rules) if _.get('name') == local_rule.name]

        if remote_rule_indexes:
            # If there's multi matches it means we have duplicate rule names and we're screwed.
            # To fix that we'd need to change the auth0 local format to use rule ids (which we could eventually)
            if len(remote_rule_indexes) > 1:
                raise Exception('RuleMatchByNameFailed', (local_rule.name, remote_rule_indexes))
            remote_rule_index = remote_rule_indexes[0]
            local_rule.id = remote_rules[remote_rule_index].get('id')
            local_rule.is_new = False

            # Is the rule different?
            remote_rule = remote_rules[remote_rule_index]
            rules_match = (
                    (local_rule.script == remote_rule.get('script')) &
                    (local_rule.enabled == bool(remote_rule.get('enabled'))) &
                    (local_rule.stage == remote_rule.get('stage')) &
                    (local_rule.order == remote_rule.get('order')))
            if rules_match:
                local_rule.is_the_same = True
            else:
                logger.debug('Difference found in {} :'.format(local_rule.name))
                for line in difflib.unified_diff(
                        remote_rule.get('script').splitlines(),
                        local_rule.script.splitlines(),
                        fromfile='auth0-{}'.format(local_rule.name),
                        tofile='local-{}'.format(local_rule.name)):
                    logger.debug(line)
        else:
            # No remote rule match, so it's a new rule
            logger.debug('Rule only exists locally, considered new and to be created: {}'.format(local_rule.name))
            local_rule.is_new = True

        if not local_rule.validate():
            logger.error('Rule failed validation: {}'.format(local_rule.name))
            sys.exit(127)
        else:
            local_rules.append(local_rule)
    logger.debug("Found {} local rules".format(len(local_rules)))

    if len(local_rules) == 0:
        logger.error("Exiting to prevent deletion of all rules")
        sys.exit(1)

    if args.delete_all_rules_first_causing_outage:
        rules_to_remove = [x for x in remote_rules if x.get('name') != MAINTENANCE_RULE_NAME]
        logger.debug("Found {} rules that will be deleted remotely".format(len(rules_to_remove)))
    else:
        # Find dead rules (i.e. to remove/rules that only exist remotely)
        rules_to_remove = [x for x in remote_rules if x.get('id') not in [y.id for y in local_rules]]
        logger.debug("Found {} rules that not longer exist locally and will be deleted remotely".format(len(rules_to_remove)))

    maintenance_rule = next(
        x for x in local_rules if x.name == MAINTENANCE_RULE_NAME)
    if args.delete_all_rules_first_causing_outage:
        maintenance_rule.enabled = True
        logger.debug("[+] {}Enabling maintenance rule denying all logins globally {} {}".format(
            dry_run_message, maintenance_rule.name, maintenance_rule.id))
        if not args.dry_run:
            authzero.update_rule(maintenance_rule.id, maintenance_rule)

    # Update or create (or delete) rules as needed
    ## Delete first in case we need to get some order numbers free'd
    for rule in rules_to_remove:
        logger.debug("[-] {}Removing rule {} ({}) from Auth0".format(
            dry_run_message, rule['name'], rule['id']))
        if not args.dry_run:
            authzero.delete_rule(rule['id'])

    ## Update & Create (I believe this may be atomic swaps for updates)
    for local_rule in local_rules:
        if local_rule.is_new:
            if args.delete_all_rules_first_causing_outage and local_rule.name == MAINTENANCE_RULE_NAME:
                continue
            logger.debug("[+] {}Creating new rule {} on Auth0".format(
                dry_run_message, local_rule.name))
            if not args.dry_run:
                result = authzero.create_rule(local_rule)
                logger.debug("+ New rule created with id {}".format(result.get('id')))
        elif local_rule.is_the_same:
            logger.debug("[=] Rule {} is unchanged, will not update".format(local_rule.name))
        else:
            logger.debug("[~] {}Updating rule {} ({}) on Auth0".format(
                dry_run_message, local_rule.name, local_rule.id))
            if not args.dry_run:
                authzero.update_rule(local_rule.id, local_rule)

    if args.delete_all_rules_first_causing_outage:
        maintenance_rule.enabled = False
        logger.debug("[-] {}Disabling maintenance rule {} {}".format(
            dry_run_message, maintenance_rule.name, maintenance_rule.id))
        if not args.dry_run:
            authzero.update_rule(maintenance_rule.id, maintenance_rule)

    sys.exit(0)
