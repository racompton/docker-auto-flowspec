#!/usr/bin/env python

from flask import Flask, request
from sys import stdout
#from flask_httpauth import HTTPBasicAuth

#auth = HTTPBasicAuth()
 
app = Flask(__name__)
 
# Setup a command route to listen for prefix advertisements and add authentication verification
@app.route('/', methods=['POST'])
def command():
    command = request.form['command']
    stdout.write('%s\n' % command)
    stdout.flush()
    return '%s\n' % command
'''
@auth.verify_password
def verify_password(username, password):
    if username == "flowspecuser" and password == "flowspecpasswd":
        return True
    else:
        return False
''' 
if __name__ == '__main__':
    #context = ('opt/certs/server-cert.pem', 'opt/certs/server-key.pem')
    #app.run(host='127.0.0.1', port=5000, ssl_context=context, threaded=True, debug=True)
    #app.run(host='0.0.0.0', port=5000)
    app.run()
