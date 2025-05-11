from flask import Flask, request, session, redirect
import google_auth_oauthlib.flow
from client_utils import get_google_auth_url 
import hashlib
import requests
import os
import json
import jwt
import secrets
import subprocess

app = Flask(__name__)
app.secret_key = "supersecret"

def fpow(base, exponent, mod):
    result = 1
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exponent >>= 1
    return result

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

        session["jwt"] = credentials.id_token
        session["user"] = decoded_jwt["email"]
        session["aud"] = decoded_jwt["aud"]

        # send stuff to pepper with zk
        # Generate a random 256-bit integer for ephemeral key
        u = secrets.randbits(32)

        # Load pepper constants
        with open('pepper_consts.json', 'r') as f:
            pepper_consts = json.load(f)
        
        mod = pepper_consts['mod']
        g = pepper_consts['g']

        u = secrets.randbits(32) % mod
        session["u"] = u

        # create hash
        email_aud = decoded_jwt['email'] + decoded_jwt['aud']
        hashed = hashlib.sha256(email_aud.encode()).hexdigest()
        print(f"hashed: {str(hashed)}")
        h = (fpow(g, u, mod) * int(hashed, 16)) % mod

        # pretend like we made a zk proof and send to pepper
        return redirect('https://localhost:5000/genpepper?h=' + str(h))

        # code to create json inputs
        # try: 
            # json_input = json.loads(subprocess.check_output(["lib/gen_inputs.exe ", session.get("jwt"), session.get('eph_pk'), session.get("eph_rand")]).decode('utf-8').strip())
            # session["json"] = json_input
            # print(f"result: {str(json_input)}")
        #except Exception as e:
        #    print(f"Unexpected error: {str(e)}", 500)

       
        # Return a simple HTML page with the received data
    except Exception as e:
        return f"""
        <html>
            <body>
                <h1>Error Processing OAuth Callback</h1>
                <p>Error: {str(e)}</p>
            </body>
        </html>
        """

@app.route('/peppercallback')
def pepper():
    with open('pepper_consts.json', 'r') as f:
        pepper_consts = json.load(f)
    vpk = pepper_consts['vpk']
    mod = pepper_consts['mod']
    u = session["u"]
    pepper = request.args.get('pepper')
    session["pepper"] = int(pepper) * fpow(fpow(vpk, mod - 2, mod), u, mod) % mod
    email_aud_pepper = session["user"] + session["aud"] + str(session["pepper"])
    session["addr"] = hashlib.sha256(email_aud_pepper.encode()).hexdigest()
    return redirect('/home')

@app.route('/home')
def home():
    if "user" not in session:
        return redirect("/")
        
    return """
    <html>
        <body>
            <h2>Welcome {}</h2>
            <div style="margin: 20px 0;">
                <h3>Your Session Information:</h3>
                <p><strong>Ephemeral Public Key:</strong> {}</p>
                <p><strong>Ephemeral Secret Key:</strong> {}</p>
                <p><strong>Ephemeral Blinding Key:</strong> {}</p>
                <p><strong>Pepper:</strong> {}</p>
                <p><strong>Address:</strong> {}</p>
            </div>
            <form action="/submit" method="post">
                <div style="margin: 20px 0;">
                    <label for="address">Destination Address:</label><br>
                    <input type="text" id="address" name="address" style="width: 300px; padding: 5px;">
                </div>
                
                <div style="margin: 20px 0;">
                    <label for="quantity">Amount:</label><br>
                    <input type="number" id="quantity" name="quantity" min="1" style="width: 100px; padding: 5px;">
                </div>

                <input type="submit" value="Submit" style="
                    background-color: #4285f4;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                ">
            </form>
        </body>
    </html>
    """.format(session["user"], session.get("eph_pk", "Not available"), session.get("eph_sk", "Not available"), session.get("eph_rand", "Not available"), session.get("pepper", "Not available"), session.get("addr", "Not available"))

@app.route('/')
def main_page():
    # Get auth URL and state from client utils
    # Get nonce from external executable
    try:
        nonce, eph_sk, eph_pk, eph_rand = subprocess.check_output(['lib/gen_nonce.exe']).decode('utf-8').strip().split(" ")
        print(f"nonce: {str(nonce)}")
        print(f"eph_pk: {str(eph_pk)}")
        print(f"eph_sk: {str(eph_sk)}")
        print(f"eph_rand: {str(eph_rand)}")
    except Exception as e:
        print(f"Error getting nonce: {str(e)}")
        nonce = None
    
    if nonce == None:
        return """
        <html>
            <body>
                <h1>Error</h1>
                <p>Could not generate authentication URL</p>
            </body>
        </html>
        """
    session["eph_pk"] = eph_pk
    session["eph_sk"] = eph_sk
    session["eph_rand"] = eph_rand

    auth_url, state = get_google_auth_url(nonce)

    return f"""
    <html>
        <body>
            <a href="{auth_url}" style="
                display: inline-block;
                background-color: #4285f4;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                font-family: Arial, sans-serif;
            ">
                Sign in with Google
            </a>
        </body>
    </html>
    """

@app.route('/submit', methods=['POST'])
def submit():
    address = request.form.get('address')
    quantity = request.form.get('quantity')
    return redirect(f'/send?address={address}&amount={quantity}')

@app.route('/send')
def send():
    src = session.get('addr')
    dst = request.args.get('address')
    amount = request.args.get('amount')
    txn = {"src": src, "dst": dst, "amt": amount}
    signed = subprocess.check_output(["lib/sign_txn.exe ", session.get("eph_sk"), session.get('eph_pk'), str(txn).encode('utf-8')]).decode('utf-8').strip()
    return f"""
    <html>
        <body>
            <h2>Transaction Details</h2>
            <p><strong>Source Address:</strong> {src}</p>
            <p><strong>Destination Address:</strong> {dst}</p>
            <p><strong>Amount:</strong> {amount}</p>
            <p><strong>Signed Transaction:</strong> {signed}</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    # Run the Flask app
    app.run(host='localhost', port=8080, ssl_context='adhoc', debug=True) 