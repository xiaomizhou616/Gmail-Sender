import os
import json
import os.path
import psycopg2
from flask import Flask, request, redirect, send_file, jsonify, abort, make_response
from dotenv import load_dotenv

from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from base64 import urlsafe_b64encode
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.ERROR)

app = Flask(__name__)

load_dotenv()

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

REDIRECT_URI = os.getenv("REDIRECT_URIS_3")

CREDS = {
    "web": {
        "client_id": os.getenv("CLIENT_ID"),
        "project_id": os.getenv("PROJECT_ID"),
        "auth_uri": os.getenv("AUTH_URI"),
        "token_uri": os.getenv("TOKEN_URI"),
        "auth_provider_x509_cert_url": os.getenv("AUTH_PROVIDER_X509_CERT_URL"),
        "client_secret": os.getenv("CLIENT_SECRET"),
        "redirect_uris": [
            os.getenv("REDIRECT_URIS_1"),
            os.getenv("REDIRECT_URIS_2"),
            os.getenv("REDIRECT_URIS_3"),
            os.getenv("REDIRECT_URIS_4"),
            os.getenv("REDIRECT_URIS_5"),
            os.getenv("REDIRECT_URIS_6")
        ],
        "javascript_origins": [
            os.getenv("JAVASCRIPT_ORIGINS_1"),
            os.getenv("JAVASCRIPT_ORIGINS_2"),
            os.getenv("JAVASCRIPT_ORIGINS_3"),
            os.getenv("JAVASCRIPT_ORIGINS_4"),
            os.getenv("JAVASCRIPT_ORIGINS_5")
        ]
    }
}
# connect to database
DATABASE_URL = os.getenv('DATABASE_URL')
url = urlparse(DATABASE_URL)

dbname = url.path[1:]
user = url.username
password = url.password
host = url.hostname
port = url.port

conn = None

try:
    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
except Exception as e:
    print(f"Failed to connect to the database: {e}")


@app.route("/.well-known/logo.png")
def plugin_logo():
    filename = '.well-known/logo.png'
    return send_file(filename, mimetype='image/png')

@app.route("/.well-known/ai-plugin.json")
def plugin_manifest(openapi="3.0.1"):
    with open("./.well-known/ai-plugin.json") as f:
        text = f.read()
    return jsonify(json.loads(text))

@app.route("/.well-known/openapi.yaml")
def openapi_spec():
    with open('./.well-known/openapi.yaml', 'r') as f:
        openapi_spec = f.read()
    return openapi_spec, {'Content-Type': 'text/yaml'}

@app.route("/auth", methods=['GET', 'POST'])
def auth():
    global conn
    flow = Flow.from_client_config(CREDS, SCOPES)
    # Generate the authorization URL
    flow.redirect_uri = REDIRECT_URI
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent') # This parameter set to 'content' to force you auth like first time and get a refresh token.   
  
    data = request.json
    user_id = data.get('user_id')
    if user_id is None:
        return jsonify(message="The email address of sender is missing.", status=400)
    cur = None
    try:
        # Check if connection is closed
        if conn is None or conn.closed:
            # Reconnect (you'll need to replace this with your actual connection code)
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
        # Create a cursor object
        cur = conn.cursor()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when connecting postgres: {e}', status=500))
        abort(response)
    # only need for the first time
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS states (
                state TEXT PRIMARY KEY,
                user_id TEXT
            )
        """)
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when creating table states: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    
    try:
        # Insert the token data into the tokens table
        cur.execute("""
            INSERT INTO states (state, user_id)
            VALUES (%s, %s)
            ON CONFLICT (state) DO UPDATE
            SET user_id = excluded.user_id
        """, (state, user_id))

        # Commit the changes
        conn.commit()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when inserting table states: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    finally:
        # Close the cursor 
        if cur is not None:
            cur.close()
    # Need to check whether the client render this link method
    message = f'<a href="{authorization_url}">Click this link, click \'advanced\', and click \'Go to email-manager.fly.dev (unsafe)\' to authorize me</a>'
    #message = f"Copy and paste this link into your browser to authorize me: {authorization_url}"
    return jsonify({"message": message})
    
def create_message(sender, to, subject, message_text):
    """Create a message for an email.

    Args:
        sender: Email address of the sender.
        to: Email address of the receiver.
        subject: The subject of the email message.
        message_text: The text of the email message.

    Returns:
        An object containing a base64url encoded email object.
    """
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return {'raw': urlsafe_b64encode(message.as_string().encode('utf-8')).decode('utf-8')}

def send_message(service, user_id, message):
    """Send an email message.

    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me" can be used to indicate the authenticated user.
        message: Message to be sent.

    Returns:
        Sent Message.
    """
    try:
        message = service.users().messages().send(userId=user_id, body=message).execute()
        return message
    except HttpError as error:
        raise error
    
@app.route('/oauth2callback', methods=['GET', 'POST'])
def oauth2callback():
    global conn
    # Get the state from the url after redirect
    state = request.args.get('state')
    authorization_response = request.url
  
    if authorization_response.startswith("http://"):
        authorization_response = authorization_response.replace("http", "https", 1)

    flow = Flow.from_client_config(CREDS, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI
    flow.fetch_token(authorization_response=authorization_response)
    creds = flow.credentials
    tokens = {
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "bearer"
    }

    cur = None
    result= None
    try:
        # Check if connection is closed
        if conn is None or conn.closed:
            # Reconnect (you'll need to replace this with your actual connection code)
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
        cur = conn.cursor()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when connecting postgres: {e}', status=500))
        abort(response)
    # get email/user_id from postgres
    try:
        cur.execute("""
            SELECT user_id
            FROM states
            WHERE state = %s
        """, (state,))
        result = cur.fetchone()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when get email from the database: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    
    if result:
        user_id=result[0]
    else:
        user_id = None
    
    # Create the tokens table only for the first time
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                user_id TEXT PRIMARY KEY,
                client_id TEXT,
                client_secret TEXT,
                access_token TEXT,
                refresh_token TEXT,
                token_type TEXT
            )
        """)
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when creating table tokens: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    
    try:
        # Insert the token data into the tokens table
        cur.execute("""
            INSERT INTO tokens (user_id, client_id, client_secret, access_token, refresh_token, token_type)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE
            SET client_id = excluded.client_id,
                client_secret = excluded.client_secret,
                access_token = excluded.access_token,
                refresh_token = excluded.refresh_token,
                token_type = excluded.token_type
        """, (user_id, tokens["client_id"], tokens["client_secret"], tokens["access_token"], tokens["refresh_token"], tokens["token_type"]))
        # Commit the changes
        conn.commit()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when inserting table tokens: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    finally:
        # Close the cursor and connection
        if cur is not None:
            cur.close()
    if conn is not None and not conn.closed:
        # Close the connection
        conn.close()
    return jsonify(message=f'Credentials were saved successfully', status=200)

@app.route("/send_email", methods=['GET', 'POST'])
def send_email():
    global conn
    data = request.json
    user_id = data.get('user_id')
    to = data.get('to')
    subject = data.get("subject")
    body = data.get("body")
    # Check if any of the parameters are None
    if None in [user_id, to, subject, body]:
        return jsonify(message="error. Bad request. There are missing required parameters.", status=400)
    tokens = None
    cur = None
    result = None
    try:
        # Check if connection is closed
        if conn is None or conn.closed:
            # Reconnect (you'll need to replace this with your actual connection code)
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
        cur = conn.cursor()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when connecting postgres: {e}', status=500))
        abort(response)
    
    try:
        # Get the JSON string from Postgres database
        cur.execute("""
            SELECT client_id, client_secret, access_token, refresh_token, token_type
            FROM tokens
            WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
    except Exception as e:
        response = make_response(jsonify(message=f'An error occurred when getting token from database: {e}', status=500))
        abort(response)
        conn.rollback()  # Rollback the transaction
    if result:
        tokens = {
            "client_id": result[0],
            "client_secret": result[1],
            "access_token": result[2],
            "refresh_token": result[3],
            "token_type": result[4],
            "token_uri": os.getenv("TOKEN_URI")
        }
    else:
        return jsonify(message='Unauthorized. User authentication required.', status=401)
        #return redirect(url_for('auth'))

    if tokens:
        creds = Credentials.from_authorized_user_info(tokens, SCOPES)
    # Assuming creds is your Credentials object
    if creds and creds.expired and creds.refresh_token:
        # logging.debug(f"access token expired: {creds.token}")
        # Get the new access token     
        creds.refresh(Request())    
        new_access_token = creds.token
        try:           
            # Update the access token in the database
            cur.execute("""
                UPDATE tokens
                SET access_token = %s
                WHERE user_id = %s
            """, (new_access_token, user_id))
        except Exception as e:
            response = make_response(jsonify(message=f'An error occurred when updating access token in the database: {e}', status=500))
            abort(response)
            conn.rollback()  # Rollback the transaction
     
    # Close the cursor 
    if cur is not None:
        cur.close() 
    if conn is not None and not conn.closed:
        # Close the connection
        conn.close()
    try:
        service = build('gmail', 'v1', credentials=creds)
        message = create_message(user_id, to, subject, body)
        send_message(service, "me", message)
        return jsonify(message='Email sent successfully.', status=200)
        
    except HttpError as error:
        return jsonify(message=f'An error occurred: {error}', status=500)
  
def main():
    app.run(debug=False, host="0.0.0.0", port=5003)

if __name__ == "__main__":
    main()

