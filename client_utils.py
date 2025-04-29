import google.oauth2.credentials
import google_auth_oauthlib.flow
import os
import secrets
import hashlib

CREDENTIALS_PATH = 'service_account_credentials.json'

# return auth url, state
def get_google_auth_url(esk, epk, blinding):
    
    # create nonce combining epk and blinding
    combined = str(epk) + str(blinding)
    nonce = hashlib.sha256(combined.encode()).hexdigest()

    try:
        # Create a flow instance
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CREDENTIALS_PATH,
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'])

        flow.redirect_uri = 'https://localhost:8080/oauth2callback'

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            nonce=nonce)
        
        return authorization_url, state
        
    except Exception as e:
        print(f"Error generating authorization URL: {str(e)}")
        return None, None 

if __name__ == '__main__':
    print(get_google_auth_url())