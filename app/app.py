from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import xmlrpc.client
import ssl
import os
import logging
from dotenv import load_dotenv
import base64
from functools import wraps


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def generate_nonce():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

# Load environment variables
load_dotenv()
FLASK_PORT = os.getenv("FLASK_PORT")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")
PAPERCUT_HOST = os.getenv("PAPERCUT_HOST") # Client address will need to be whitelisted with advanced config property "auth.webservices.allowed-addresses"
PAPERCUT_AUTH = os.getenv("PAPERCUT_AUTH") # Value defined in advanced config property "auth.webservices.auth-token".
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
OAUTH_ISSUER = os.getenv("OAUTH_ISSUER")
OAUTH_METADATA_URL = os.getenv("OAUTH_METADATA_URL")

# PaperCut XML API https://www.papercut.com/help/manuals/ng-mf/common/tools-web-services/
context = ssl._create_unverified_context()
proxy = xmlrpc.client.ServerProxy(PAPERCUT_HOST, context=context)

# Initialize OAuth
oauth = OAuth(app)
oauth.register(
    name='kambala',
    server_metadata_url=OAUTH_METADATA_URL,
    client_id=OAUTH_CLIENT_ID,
    client_secret=OAUTH_CLIENT_SECRET,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def login():
    # Generate a random nonce
    session['nonce'] = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

    # Generate a redirect uri
    redirect_uri = url_for('auth_callback', _external=True)
    print(f"Redirect URI: {redirect_uri}")

    return oauth.kambala.authorize_redirect(
        redirect_uri,
        nonce=session['nonce']
    )

@app.route('/auth/callback')
def auth_callback():
    try:
        # Get the token 
        token = oauth.kambala.authorize_access_token()
        # print("\n=== Token Information ===")
        # print(f"Access Token: {token.get('access_token')}")
        # print(f"Token Type: {token.get('token_type')}")
        # print(f"Expires In: {token.get('expires_in')}")
        # print(f"Scope: {token.get('scope')}")
        # print(f"ID Token: {token.get('id_token')}")
        
        # Get the ID token claims
        id_token_claims = oauth.kambala.parse_id_token(token, nonce=session['nonce'])
        # print("\n=== ID Token Claims ===")
        # print(f"All Claims: {id_token_claims}")
        # print(f"Available Claims: {list(id_token_claims.keys())}")
        
        # Get user info from UserInfo endpoint
        user_info = oauth.kambala.userinfo()
        # print("\n=== UserInfo Endpoint Response ===")
        # print(f"User Info: {user_info}")
        # print(f"Available Claims: {list(user_info.keys())}")
        
        # Combine ID token claims with user info
        combined_user_info = {**id_token_claims, **user_info}
        # print("\n=== Combined User Information ===")
        # print(f"All Claims: {combined_user_info}")
        # print(f"Available Claims: {list(combined_user_info.keys())}")
        
        # Store the combined user info in the session
        session['user'] = combined_user_info
        return redirect('/')

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return f"An unexpected error occurred: {str(e)}", 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/success')
def success():
    return render_template('success.html')
# return "Card ID number successfully updated."

@app.route('/failure')
def failure():
    error_message = request.args.get('error_message', 'An unknown error occurred.')
    print(error_message)
    #return True
    return render_template('failure.html', error_message=error_message)

def hex_to_decimal(hex_num):
    try:
        decimal_num = int(hex_num, 16)
        return decimal_num
    except ValueError:
        return "Invalid hexadecimal number"

def set_papercut_primary_card(username, id_number):
    try:
        if proxy.api.setUserProperty(PAPERCUT_AUTH, username, 'primary-card-number', str(id_number)):
            return True
        else:
            return False
    except xmlrpc.client.Fault as error:
        print("\ncalled setUserProperty(). Return fault is {}".format(error.faultString))
        return False
    except xmlrpc.client.ProtocolError as error:
        print("\nA protocol error occurred\nURL: {}\nHTTP/HTTPS headers: {}\nError code: {}\nError message: {}".format(
            error.url, error.headers, error.errcode, error.errmsg))
        return False
    except Exception as error:
        print(f'Error: {error}')
        return False

def set_pager_attribute(username, id_number):
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True)
    
    # Define the search base and filter
    search_base = LDAP_SEARCH_BASE
    search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'

    # Convert the ID number from hex to decimal
    id_number = hex_to_decimal(id_number)
    if isinstance(id_number, str):
        print(id_number)
        return False, 'Card number could not be converted to decimal'
    print(f'Updating {username} with {id_number}')
    
    try:
        # Search for the user
        conn.search(search_base, search_filter, attributes=['distinguishedName'])
        if conn.entries:
            user_dn = conn.entries[0].distinguishedName.value
            # Modify the pager attribute
            conn.modify(user_dn, {'pager': [(MODIFY_REPLACE, [id_number])]})
            if conn.result['description'] == 'success':
                return set_papercut_primary_card(username, id_number), ''
            else:
                print(f"LDAP Error: {conn.result['description']}")
                return False, conn.result['description']
        else:
            print('User not found')
            return False, 'User not found'
    except Exception as e:
        print(f'Error: {e}')
        return False, e

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=FLASK_PORT)
