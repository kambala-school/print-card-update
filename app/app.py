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
import requests
import xml.etree.ElementTree as ET

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
LDAP_STUDENT_GROUP = os.getenv("LDAP_STUDENT_GROUP")
PAPERCUT_HOST = os.getenv("PAPERCUT_HOST") # Client address will need to be whitelisted with advanced config property "auth.webservices.allowed-addresses"
PAPERCUT_AUTH = os.getenv("PAPERCUT_AUTH") # Value defined in advanced config property "auth.webservices.auth-token".
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
OAUTH_ISSUER = os.getenv("OAUTH_ISSUER")
OAUTH_METADATA_URL = os.getenv("OAUTH_METADATA_URL")

# RollCall configuration
ROLLCALL_API_URL = os.getenv("ROLLCALL_API_URL")
ROLLCALL_TOKEN = os.getenv("ROLLCALL_TOKEN")

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

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        username = request.form['username']
        id_number = request.form['id_number']
        success, error_message = set_pager_attribute(username, id_number)
        if success:
            return redirect(url_for('success'))
        else:
            return redirect(url_for('failure', error_message=error_message))
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

def get_student_number(username):
    """Get student number from Active Directory for the given username."""
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True)
    
    search_base = LDAP_SEARCH_BASE
    # Modified search filter to only return users who are members of the specified student group
    search_filter = f'(&(objectClass=user)(sAMAccountName={username})(memberOf={LDAP_STUDENT_GROUP}))'
    
    try:
        # Search for the user with employeeID attribute
        conn.search(search_base, search_filter, attributes=['employeeID'])
        if conn.entries:
            student_number = conn.entries[0].employeeID.value
            if student_number:
                return student_number
            else:
                logger.info(f"User {username} not found in Active Directory with employeeID attribute. Not updating RollCall.")
                return None
        else:
            logger.info(f"User {username} not found in Active Directory with employeeID attribute or is not a member of AllStudents group. Not updating RollCall.")
            return None
    except Exception as e:
        logger.error(f"Error getting student number for {username} from Active Directory: {e}")
        return None
    finally:
        conn.unbind()

def update_rollcall_card(student_number, card_code):
    """Update the card code in RollCall system."""
    if not ROLLCALL_API_URL or not ROLLCALL_TOKEN:
        return False, "RollCall configuration is missing. Please check environment variables."
    
    # Create XML payload
    xml_payload = f'''<xml>
    <Token>{ROLLCALL_TOKEN}</Token>
    <StudentNumber>{student_number}</StudentNumber>
    <CardCode>{card_code}</CardCode>
</xml>'''
    
    headers = {
        'Content-Type': 'application/xml'
    }
    
    try:
        response = requests.post(
            ROLLCALL_API_URL,
            data=xml_payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return True, "Card updated successfully in RollCall"
        elif response.status_code == 400:
            return False, "RollCall API: Bad request - malformed or missing required fields"
        elif response.status_code == 401:
            return False, "RollCall API: Unauthorized - invalid or expired token"
        elif response.status_code == 500:
            return False, "RollCall API: Internal server error"
        else:
            return False, f"RollCall API: Unexpected error (HTTP {response.status_code})"
            
    except requests.exceptions.Timeout:
        return False, "RollCall API: Request timed out"
    except requests.exceptions.ConnectionError:
        return False, "RollCall API: Connection error - unable to reach the server"
    except requests.exceptions.RequestException as e:
        return False, f"RollCall API: Request failed - {str(e)}"
    except Exception as e:
        return False, f"RollCall API: Unexpected error - {str(e)}"

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
                # Update PaperCut
                papercut_success = set_papercut_primary_card(username, id_number)
                if not papercut_success:
                    return False, "LDAP updated but PaperCut update failed"
                
                # Get employee number and update RollCall
                student_number = get_student_number(username)
                if student_number:
                    rollcall_success, rollcall_message = update_rollcall_card(student_number, str(id_number))
                    if not rollcall_success:
                        return False, f"LDAP and PaperCut updated but RollCall failed: {rollcall_message}"
                else:
                    return True, "LDAP and PaperCut updated but could not retrieve employeeID for RollCall"
                
                return True, ''
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
