# ci authzero-utils

Various scripts utilizing authzerolib to do things such as sync'ing authzero login page, rules, clients, settings, etc.
Useful to run in your CI!

# Usage

## Credentials & Scopes

### Prerequisites

* Create a non-interactive (machine to machine) client
  ([application](https://auth0.com/docs/applications)) in your Auth0 deployment
  by going to the `Applications` section of the Auth0 UI
* Authorize that Auth0 application so access the Management API by going to the
  [`APIs`](https://auth0.com/docs/api/info) section of the Auth0 UI, selecting
  your application
  * The required scopes depend on the script, though they all follow these general rules:
    - do not require scopes allowing access to secrets if possible (passwords, keys, etc.)
    - require the minimum set of scopes possible
  * Here is a set of scopes you would need to grant for running most scripts present in this repository:
    * read:clients
    * update:clients
    * delete:clients
    * create:clients
    * read:rules
    * update:rules
    * delete:rules
    * create:rules

In Mozilla's Auth0 accounts use the existing `Auth0 CI Updater client` client
which has already been created and granted the correct scopes.

### Credentials

You can either pass the `URI`, `CLIENTID` and `CLIENTSECRET` as arguments on the
command line or store them in `credentials.json` in the current working
directory.

The syntax of `credentials.json` is

```json
{
  "uri": "auth-dev.mozilla.auth0.com",
  "client_id": "AAA",
  "client_secret": "BBB"
}
```

Once these credentials are stored you need not pass them on the command line
and can instead instantiate the tools like this

```
./uploader_rules.py -r rules
```

## Scripts
### uploader_login_page.py
SCOPES: `update:clients`

```
usage: uploader_login_page.py [-h] [-u URI] -c CLIENTID -s CLIENTSECRET
                              [--default-client DEFAULT_CLIENT] --login-page
                              LOGIN_PAGE
```

Example: `./uploader_login_page.py -u auth-dev.mozilla.auth0.com -c AAA -s BBB --default-client CCC --login-page some.html`

Note that `CCC` above represents a special Auth0 "default" client. You can find this `client_id` by going to the "hosted
page" setup in Auth0 and looking at your web-browser dev tools network tab. Click "preview page" and look for the
`client_id` used in the requests.

### uploader_rules.py
SCOPES: `read:rules`, `update:rules`, `delete:rules`, `create:rules`

```
usage: uploader_rules.py [-h] [-u URI] [-c CLIENTID] [-s CLIENTSECRET]
                         [-r RULES_DIR] [-b DIRECTORY]
                         [--delete-all-rules-first-causing-outage] [-d]
```

Example: 

`./uploader_rules.py --uri auth-dev.mozilla.auth0.com --clientid AAA --clientsecret BBB --rules-dir rules`

Where the `rules` directory contains JSON and JS documents such as these:

AccessRules.json:

```
{
    "enabled": true,
    "order": 1
}
```

AccessRules.js:

```
function (user, context, callback) {
  ...code here...
  return callback(null, null, context);
}

```

Note that this is the Auth0 GitHub extension rule format.

To do deploy a set of changed rules safely

* Confirm `credentials.json` contains credentials for the environment you want
  to affect
* Make a local backup of the current live rules
  * `./uploader_rules.py --backup-rules-to-directory production-backup`
* Show what would be changed if you deployed your new local rules
  * `./uploader_rules.py --dry-run --rules-dir ../auth0-deploy/rules`
* Actually deploy the new local rules to the live environment
  * `./uploader_rules.py --rules-dir ../auth0-deploy/rules`
* Test the live environment to see if everything is working
* If there's a problem
  * Show what would be changed if you reverted to your local backup
    * `./uploader_rules.py --dry-run --rules-dir production-backup`
  * Deploy the local backup to rollback your change
    * `./uploader_rules.py --rules-dir production-backup`
  * If there's a bug in `uploader_rules.py` and deploying the backup doesn't work
    * Show what would be changed if you deployed your local backup with the
      `--delete-all-rules-first-causing-outage` enabled.
      * `./uploader_rules.py --dry-run --delete-all-rules-first-causing-outage --rules-dir production-backup`
    * Put Auth0 in maintenance mode, delete all rules, deploy your backup and
      take Auth0 out of maintenance mode
      * `./uploader_rules.py --delete-all-rules-first-causing-outage --rules-dir production-backup`

### uploader_clients.py
SCOPES: `read:clients`, `update:clients`, `delete:clients`, `create:clients`
```
usage: uploader_clients.py [-h] [-u URI] -c CLIENTID -s CLIENTSECRET
                           [-r CLIENTS_DIR] [-g]
uploader_clients.py: error: the following arguments are required: -c/--clientid, -s/--clientsecret
```

Example: `./uploader_clients.py -u auth-dev.mozilla.auth0.com -c AAA -s BBB -r clients`

Where the `clients` directory contains JSON formated Auth0 client descriptions. You can get all current clients from
your Auth0 deployment to provision the initial setup with:

Example: `./uploader_clients.py -u auth-dev.mozilla.auth0.com -c AAA -s BBB -r clients -g`

A client JSON file looks such as this:

1gBNrcIdcyuus3S8DdK7O9A5iFrAdTmj.json <= the file name is the `client_id`
```
{
    "tenant": "auth-dev",
    "global": false,
    "is_token_endpoint_ip_header_trusted": false,
    "name": "cis_hris_publisher",
    "is_first_party": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "oidc_conformant": false,
    "client_id": "1gBNrcIdcyuus3S8DdK7O9A5iFrAdTmj",
    "callback_url_template": false,
    "jwt_configuration": {
        "lifetime_in_seconds": 36000,
        "secret_encoded": false
    },
    "app_type": "non_interactive",
    "grant_types": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "client_credentials"
    ],
    "custom_login_page_on": true
}
```
