#!/usr/bin/env python3
"""OpenVPN OTP auth script.

This script is run on OpenVPN control channel renegotiation.
Use cases:
1. initial connect or after manual disconnect - a new OTP session record is created
2. on reconnect - an user session is validated.

Supports TOTP to use with Google Authenticator.
Retrieves user info from os.environ and username/password/OTP from file passed as the first arg.
"""
import base64
import datetime
import os
import sys

import pyotp

# XXX Put this somewhere in more secure place
USER_SECRETS = {'userX': {'password': 'XXX', 'otp_secret': 'XXX'}}
# To generate a secret, see https://pyotp.readthedocs.io/en/latest/

SESSION_DURATION = 164  # hours (1 week)


def main():
    """Main func."""
    # First arg is a tmp file with 2 lines: username and password
    with open(sys.argv[1], 'r') as tmpfile:
        username = tmpfile.readline().rstrip('\n')
        password = tmpfile.readline().rstrip('\n')

    if username not in USER_SECRETS:
        print(f'>> No TOTP secret for user {username} defined.')
        sys.exit(2)

    password_data = password.split(':')
    if password.startswith('SCRV1:') and len(password_data) == 3:
        # Initial connect or full re-connect phase.
        password = base64.b64decode(password_data[1]).decode()
        otp = base64.b64decode(password_data[2]).decode()
        # print(username, password, otp)

        # Verify password.
        if password != USER_SECRETS[username]['password']:
            print(f'>> Bad password provided by user {username}.')
            sys.exit(3)

        # Verify OTP, no matter if we have a valid OTP user session as the user is prompted for OTP anyway.
        if not verify_totp(USER_SECRETS[username]['otp_secret'], otp):
            print(f'>> Bad OTP provided by user {username}.')
            sys.exit(4)

        create_session(username)

    elif len(password) % 4 == 0:
        # Control channel renegotiation phase.
        # We don't know how to verify auth-token, however it should be base64.
        # Also the server generates a new one anyway and auth-token validation is in fact done only
        # on data channel renegotiation, not on control one.
        # Verify OTP user session previously saved into sqlite.
        validate_session(username)

    else:
        print(f'>> Invalid password data sent by user {username}.')
        sys.exit(99)

    sys.exit(0)


def verify_totp(secret, otp):
    """Verify TOTP."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)


def create_session(username):
    """Create/update user OTP session."""
    vpn_client = os.environ['IV_GUI_VER']
    current_ip = os.environ['untrusted_ip']
    created = datetime.datetime.now()
    print(f'>> New OTP session for user {username} from {current_ip} using {vpn_client}.')

    # Anything you want to do to create or update user session, e.g. write a record to sqlite3 db.
    store_session(username, vpn_client, current_ip, created)


def validate_session(username):
    """Validate user OTP session."""
    vpn_client = os.environ['IV_GUI_VER']
    current_ip = os.environ['untrusted_ip']
    now = datetime.datetime.now()
    session = get_session(username)

    if not session:
        print(f'>> Renegotiation forbidden. No record of OTP session for user {username}.')
        sys.exit(10)

    if session.get('vpn_client') != vpn_client:
        print(f'>> Renegotiation forbidden. User {username} is using the different VPN client: old {session["vpn_client"]}, new {vpn_client}.')
        sys.exit(11)

    if session.get('created') < now - datetime.timedelta(hours=SESSION_DURATION):
        print(f'>> Renegotiation forbidden. OTP session for user {username} has been expired on {session["created"].strftime("%Y-%m-%dT%H:%M:%SZ")}.')
        sys.exit(13)

    if session.get('ip') != current_ip:
        print(f'>> Renegotiation forbidden. User {username} is coming from different IP: {current_ip}, previous: {session["ip"]}')
        sys.exit(14)

    # Anything you want to do to fail the script with sys.exit() when a user session is say expired, unknown IP etc.

    # All good.
    print(f'>> Validated OTP session for user {username} from {current_ip} using {vpn_client}.')


def store_session(username, vpn_client, current_ip, created):
    """Store session data somewhere.

    XXX Requires implementation.
    """
    pass


def get_session(username):
    """Get session record from where you stored it above.

    XXX Requires implementation.
    """
    return {}


if __name__ == '__main__':
    main()
