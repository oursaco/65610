from flask import Flask, request
import google_auth_oauthlib.flow
import requests
import os
import json
import jwt

app = Flask(__name__)

@app.route('/oauth2callback')
def oauth2callback():
    # Get the state parameter from the request
    state = request.args.get('state')
    code = request.args.get('code')
    
    # Create a flow instance
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'service_account_credentials.json',
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        state=state
    )
    
    # Set the redirect URI
    flow.redirect_uri = 'https://localhost:8080/oauth2callback'

    try:
        # Exchange the authorization code for credentials
        flow.fetch_token(code=code)
        credentials = flow.credentials

        # Split the JWT into its parts and decode the payload
        try:
            decoded_jwt = jwt.decode(credentials.id_token, options={"verify_signature": False})
            
            # Save the decoded credentials to a file
            with open('oauth_credentials.json', 'w') as f:
                json.dump(decoded_jwt, f, indent=4)
                
        except jwt.InvalidTokenError as e:
            print(f"Error decoding JWT: {str(e)}")
       
        # Return a simple HTML page with the received data
        return f"""
        <html>
            <body>
                <h1>OAuth Callback Received</h1>
                <h2>Received Data:</h2>
                <p>State: {state}</p>
                <p>Code: {code}</p>
                <h2>Credentials:</h2>
                <p>Token: {credentials.token}</p>
                <p>Refresh Token: {credentials.refresh_token}</p>
                <p>Token URI: {credentials.token_uri}</p>
                <p>Client ID: {credentials.client_id}</p>
                <p>Client Secret: {credentials.client_secret}</p>
                <p>Scopes: {credentials.scopes}</p>
                <p>JWT: {credentials.id_token}</p>
            </body>
        </html>
        """
    except Exception as e:
        return f"""
        <html>
            <body>
                <h1>Error Processing OAuth Callback</h1>
                <p>Error: {str(e)}</p>
            </body>
        </html>
        """

if __name__ == '__main__':
    # Run the Flask app
    app.run(host='localhost', port=8080, ssl_context='adhoc', debug=True) 