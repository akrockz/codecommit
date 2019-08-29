#!/usr/bin/python
#
# How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0
# https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/
# Modified for ABC, using CA Siteminder for SSO into AWS.
#
# Usage:
# pipenv install
# pipenv run python samlapi_formauth.py

import sys
import boto3
import requests
import configparser
import base64
import xml.etree.ElementTree as ET
import re
# import json
import os

from pypac import PACSession
from pypac import pac_context_for_url
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse
from getpass import getpass


##########################################################################
# Variables
# TODO Use argparse for stuff like region

# region: The default AWS region that this script will connect
# to for all API calls
region = 'ap-southeast-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# The file, relative to user's home directory, where this script will store the temp
# credentials under the saml profile
awsconfigfile = os.path.join('.aws', 'credentials')

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# Amount of time to wait before aborting.
request_timeout = 5

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://abc.com/saml2sso?SPID=urn:amazon:webservices'

# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)

# FIXME The requested DurationSeconds exceeds the MaxSessionDuration set for this role.
duration_seconds_long = 28800 # 8h
# duration_seconds_long = 14400 # 4h


def __load_roles_config():
    """Load the aws config profiles data for use."""
    output = {}

    config = configparser.ConfigParser()
    config.read_file(open('aws-extend-switch-roles.txt'))

    for section in config.sections():

        # handle abc-cloud-master edge case.
        profile_name = section
        role_arn = None
        if ' ' in section:
            profile_name = section.split(' ')[1]
            role_arn = config[section]['role_arn']
            account_id = role_arn.split(':')[4]
        else:
            # abc-cloud-master
            account_id = config[section]['aws_account_id']

        output[account_id] = {
            'account_id': account_id,
            'profile_name': profile_name,
            'role_arn': role_arn
        }

    return output


def __get_login():
    # Get the federated credentials from the user
    return (input('Username:'), getpass())


def __get_login_payload(formsoup, creds, wan_ip):
    # Parse the response and extract all the necessary values in order to build a dictionary of all of the form values the IdP expects
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if 'user' in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = creds[0]
        elif 'email' in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = creds[0]
        elif 'password' == name.lower():
            # Append some silly text to the end of the password
            payload[name] = '{}|^_^|{}'.format(creds[1], wan_ip)
        elif 'passwordtemp' == name.lower():
            # Put the password in by itself
            payload[name] = creds[1]
        else:
            # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    return payload


def __get_login_submit_url(idpentryurl, idpauthformsubmiturl, formsoup):
    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target.
    # If the action tag doesn't exist, we just stick with the idpauthformsubmiturl above.
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        if action:
            parsedurl = urlparse(idpentryurl)
            idpauthformsubmiturl = parsedurl.scheme + '://' + parsedurl.netloc + action
    return idpauthformsubmiturl


def __get_wan_ip():
    # Needed for CA siteminder login details
    tmpSession=PACSession()     
    r = tmpSession.get('http://checkip.amazonaws.com/', verify=False)
    return r.text.rstrip()  # Chomp the trailing newline


def __extract_saml_assertion(response):
    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, 'html.parser')
    # print(soup.text)

    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analying the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            # print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if (assertion == ''):
        # TODO: Insert valid error checking/handling
        print('Response did not contain a valid SAML assertion')
        sys.exit(0)

    return assertion


def __process_saml_assertion(assertion, roles_config):

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                # Note the reverse order, typically role_arn documented first.
                principal_arn, role_arn = saml2attributevalue.text.split(',')
                account_id = role_arn.split(':')[4]
                profile_name = roles_config[account_id]['profile_name']
                awsroles.append({
                    'role_arn': role_arn,
                    'principal_arn': principal_arn,
                    'account_id': account_id,
                    'profile_name': profile_name,
                    'saml2attributevalue': saml2attributevalue.text
                })

    # Ssome kind of logical order?
    awsroles = sorted(awsroles, key=lambda k: k['profile_name'])
    # exit('awsroles={}'.format(json.dumps(awsroles, sort_keys=True, indent=4)))

    awsrole = None  # Used for return.
    print('')

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    if len(awsroles) > 1:

        print('Please choose the role you would like to assume:\n')

        i = 0  # Because the data is zero-indexed
        for awsrole in awsroles:
            print('[{}]: {} {}'.format(i + 1, awsrole['profile_name'], awsrole['role_arn']))
            i += 1

        print('')

        selectedrole_valid = False
        while not selectedrole_valid:
            selectedrole_valid = False
            selectedroleindex = int(input('Selection:')) - 1  # zero-indexed
            # Basic sanity checks of input
            if selectedroleindex < 0:
                print('Select a positive number, try again.')
            elif selectedroleindex > (len(awsroles) - 1):
                print('You selected an invalid role index, please try again')
                # sys.exit(0)
            else:
                # We have a winner!
                selectedrole_valid = True

        awsrole = awsroles[int(selectedroleindex)]

    else:
        awsrole = awsroles[0]

    return awsrole


def __get_sts_token_from_login(response, roles_config, duration_seconds):
    # Use the assertion to get an AWS STS token using Assume Role with SAML

    print('Extracting data from SAML assertion...')

    assertion = __extract_saml_assertion(response)
    # print('assertion={}'.format(base64.b64decode(assertion)))

    print('Processing SAML into arns...')

    awsrole = __process_saml_assertion(assertion, roles_config)
    print('Requesting STS credentials for profile_name={}, role_arn={}'.format(awsrole['profile_name'], awsrole['role_arn']))

    # For DurationSeconds info, see http://boto3.readthedocs.io/en/latest/reference/services/sts.html#STS.Client.assume_role_with_saml
    with pac_context_for_url( 'http://checkip.amazonaws.com'):
        stsclient = boto3.client('sts', region_name=region)
    return stsclient.assume_role_with_saml(
        RoleArn=awsrole['role_arn'],
        PrincipalArn=awsrole['principal_arn'],
        SAMLAssertion=assertion,
        DurationSeconds=duration_seconds
    )


def main():
    # Converting a procedural script, piece by piece.

    print('samlapi_formauth running...')

    print('Loading account profile data')
    roles_config = __load_roles_config()
    # exit('roles_config: {}'.format(json.dumps(roles_config, sort_keys=True, indent=4)))

    # Find out the wanip, for IdP.
    wan_ip = __get_wan_ip()
    print('wan_ip {}'.format(wan_ip))

    # Initiate session handler, which takes care of cookies.
    session = PACSession()

    print('Fetching SSO page {}'.format(idpentryurl))

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and gets the resulting login page.
    formresponse = session.get(idpentryurl, verify=sslverification, timeout=request_timeout)
    # print('formresponse = {}'.format(formresponse.text))

    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    # This might change below, based on what we find in html forms.
    idpauthformsubmiturl = formresponse.url
    # print('Redirected initial idpauthformsubmiturl {}'.format(idpauthformsubmiturl))

    # formsoup = BeautifulSoup(formresponse.text.decode('utf8'))
    formsoup = BeautifulSoup(formresponse.text, 'html.parser')

    # Ask User on laptop to enter their username + password.
    creds = __get_login()

    payload = __get_login_payload(formsoup, creds, wan_ip)
    # print('payload {}'.format(json.dumps(payload, sort_keys=True, indent=4)))

    idpauthformsubmiturl = __get_login_submit_url(idpentryurl, idpauthformsubmiturl, formsoup)
    print('idpauthformsubmiturl {}'.format(idpauthformsubmiturl))

    print('')  # Formatting.

    # Performs the submission of the IdP login form with the above post data
    response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification, timeout=request_timeout)
    # print('POST response status {}, headers {}'.format(response.status_code, response.headers))
    # print('response.text={}'.format(response.text))

    # Delete the credential variables, just for safety
    del creds

    token = __get_sts_token_from_login(response, roles_config, duration_seconds_long)
    # print('STS token: {}'.format(json.dumps(token, sort_keys=True, indent=4)))

    # Write the AWS STS token into the AWS credential file
    filename = os.path.join(expanduser('~'), awsconfigfile)
    print('Writing temp creds to {}'.format(filename))

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(filename)

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section('saml'):
        config.add_section('saml')

    config.set('saml', 'output', outputformat)
    config.set('saml', 'region', region)
    config.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    print('\n\n----------------------------------------------------------------')
    print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename))
    # TODO Format to localtime.
    print('Note that it will expire at {:%H:%M:%S %d/%b/%y %Z}.'.format(token['Credentials']['Expiration'].astimezone()))
    print('After this time, you may rerun this script to refresh your access key pair.')
    print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
    print('----------------------------------------------------------------\n\n')


if __name__ == '__main__':
    main()
