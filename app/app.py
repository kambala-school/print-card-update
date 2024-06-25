from flask import Flask, request, render_template, redirect, url_for
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import xmlrpc.client
from ssl import create_default_context, Purpose
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables
load_dotenv()
FLASK_PORT = os.getenv("FLASK_PORT")
LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")
PAPERCUT_HOST = os.getenv("PAPERCUT_HOST") # Client address will need to be whitelisted with advanced config property "auth.webservices.allowed-addresses"
PAPERCUT_AUTH = os.getenv("PAPERCUT_AUTH") # Value defined in advanced config property "auth.webservices.auth-token".

# PaperCut XML API https://www.papercut.com/help/manuals/ng-mf/common/tools-web-services/
proxy = xmlrpc.client.ServerProxy(PAPERCUT_HOST)

@app.route('/', methods=['GET', 'POST'])
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
# return "Failed to update the Card ID number. Please check the values and try again."


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=FLASK_PORT)
