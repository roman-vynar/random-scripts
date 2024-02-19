#!/usr/bin/env python3

"""OpenVPN OTP auth script.

This script is run on OpenVPN control channel renegotiation.
Use cases:
1. initial connect or after manual disconnect - a new OTP session record is created in sqlite.
 we do this in /tmp to avoid writes on the flash
2. on reconnect - an user session is validated.

Supports TOTP!
Retrieves user info from os.environ and username/password/OTP from file passed as the first arg.
```
auth-user-pass-verify openvpn_otp_auth.py via-file
```

./sciptname.py --genkey <username>
asks for password input via stdin and outputs
username,password bcrypt hash und otp private key

To add a new user, just add a new line into USER_SECRETS

"""
import base64
import datetime
import os
import sqlite3
import sys

import pyotp
import bcrypt
import getpass

USER_SECRETS = {'usera':   {'password': '$2b$12$KvKrkx4yRPW8GzyeyYFSlO5AsbJm1MfuFEDT47Xb4/ev08orDk3t2', 'otp_secret': 'J26SCGVM5JR5YCOLB7WXSTIXRRMZUXGH'},
                'userb':   {'password': '$2b$12$KvKrkx4yRPW8GzyeyYFSlO5AsbJm1MfuFEDT47Xb4/ev08orDk3t2', 'otp_secret': '6JG6YRJSSSNQV2TKFCTAK4ZWCKGATNMF'}
}


SESSION_DURATION = 49  # hours (2 days)
DB_FILE = '/tmp/openvpn-sessions.db'
DB_SCHEMA_SESSION = '''
    CREATE TABLE sessions (
        username VARCHAR PRIMARY KEY,
        vpn_client VARCHAR,
        ip_address VARCHAR,
        verified_on TIMESTAMP
    )
'''
DB_SCHEMA_OTPS='''
    ;
    CREATE TABLE otps (
        username VARCHAR,
        used TIMESTAMP,
        otp VARCHAR
    )
'''

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

        # Verify password.
        #if password != USER_SECRETS[username]['password']:
        if not bcrypt.checkpw(password.encode('utf-8'), USER_SECRETS[username]['password'].encode('utf-8')):
            print(f'>> Bad password provided by user {username}.')
            sys.exit(3)

        if get_last_otps(username,otp) >= 1:
            print(f'>> OTP Value {otp} for user {username}  is already been used')
            sys.exit(4)

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
    vpn_client = os.environ['IV_VER']
    current_ip = os.environ['untrusted_ip']
    created = datetime.datetime.now()

    # Anything you want to do to create or update user session, e.g. write a record to sqlite db.
    store_session(username, vpn_client, current_ip, created)
    print(f'>> New OTP session for user {username} from {current_ip} using {vpn_client}.')


def validate_session(username):
    """Validate user OTP session."""
    vpn_client = os.environ['IV_GUI_VER']
    current_ip = os.environ['untrusted_ip']
    now = datetime.datetime.now()
    session = get_session(username)

    if not session:
        print(f'>> Renegotiation forbidden. No record of OTP session for user {username}.')
        sys.exit(10)

    if session['vpn_client'] != vpn_client:
        print(f'>> Renegotiation forbidden. User {username} is using the different VPN client: old {session["vpn_client"]}, new {vpn_client}.')
        sys.exit(11)

    if session['verified_on'] < now - datetime.timedelta(hours=SESSION_DURATION):
        print(f'>> Renegotiation forbidden. OTP session for user {username} has been expired on {session["verified_on"].strftime("%Y-%m-%dT%H:%M:%SZ")}.')
        sys.exit(13)

    if session['ip_address'] != current_ip:
        print(f'>> Renegotiation forbidden. User {username} is coming from different IP: {current_ip}, previous: {session["ip_address"]}')
        sys.exit(14)

    # Anything you want to do to fail the script with sys.exit() when a user session is say expired, unknown IP etc.

    # All good.
    print(f'>> Validated OTP session for user {username} from {current_ip} using {vpn_client}.')


def get_db_cursor():
    """Connect to sqlite db file."""
    if not os.path.exists(DB_FILE):
        db = sqlite3.connect(DB_FILE,timeout=30.0)
        cursor = db.cursor()
        cursor.execute(DB_SCHEMA_SESSION)
        cursor.execute(DB_SCHEMA_OTPS)
        db.commit()
    else:
        db = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = db.cursor()

    return db, cursor


def store_session(username, vpn_client, current_ip, created):
    """Store session record into sqlite."""
    db, cursor = get_db_cursor()
    cursor.execute('''REPLACE INTO sessions (username, vpn_client, ip_address, verified_on)
                      VALUES (?,?,?,?)''', (username, vpn_client, current_ip, created))
    db.commit()
    db.close()


def get_session(username):
    """Get session record from sqlite."""
    _, cursor = get_db_cursor()
    cursor.execute('''SELECT vpn_client, ip_address, verified_on FROM sessions WHERE username=?''', (username,))
    session = cursor.fetchone()
    cursor.close()
    return session


def get_last_otps(username,otp):
    """Get session record from sqlite."""
    db, cursor = get_db_cursor()

    cursor.execute("delete from otps where datetime(used) < datetime(current_timestamp, '-5 minutes')")
    db.commit()

    cursor.execute("SELECT count(*) AS ANZAHL from otps where datetime(used) >= datetime(current_timestamp, '-2 minutes') and username=? and otp=?",(username,otp))
    last_otps = cursor.fetchone()
    db.commit()
    db.close()
    return last_otps[0]


def read_password(help_text='Password:'):
    """
    Read password from stdin
    """

    while True:
        if help_text:
            print (help_text)
        pw = getpass.getpass()
        if pw:
            break
    return pw

if __name__ == '__main__':

    if len(sys.argv) == 3 and sys.argv[1] == "--genkey":
        username = str(sys.argv[2])
        password = read_password('Enter Password:')
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

		# Gen key for user, store, then display
        b32 = pyotp.random_base32()
        totp = pyotp.totp.TOTP(b32)
        print(username)
        print(hashed)
        print(b32)
        #print(totp.provisioning_uri(username, issuer_name=serverName))
        exit(0)

    main()
