from flask import Flask, request, jsonify, redirect
import sys
import json
import requests

app = Flask(__name__)

def fpow(base, exponent, mod):
    result = 1
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exponent >>= 1
    return result

@app.route('/genpepper')
def login():
    with open('keys.json', 'r') as f:
        keys = json.load(f)
    mod = keys['mod']
    g = keys['g']
    vsk = keys['vsk']

    h = int(request.args.get('h'))

    result = fpow(h, vsk, mod)

    return redirect('https://localhost:8080/peppercallback?pepper=' + str(result))


if __name__ == '__main__':
    app.run(host='localhost', ssl_context='adhoc', debug=True, port=5000) 