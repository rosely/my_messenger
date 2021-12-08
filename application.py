from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_awscognito import AWSCognitoAuthentication
from flask_cors import CORS
from jwt.algorithms import RSAAlgorithm
from flask_socketio import SocketIO, join_room, leave_room
from flask_jwt_extended import (
    JWTManager,
    set_access_cookies,
    verify_jwt_in_request,
    get_jwt_identity,
    decode_token,
)
import json
import os
import requests

def get_cognito_public_keys():
    region = 'us-east-1'
    pool_id = 'us-east-1_t2focHvIB'
    url = f"https://rosely-web-chat.auth.us-east-1.amazoncognito.com/{pool_id}/.well-known/jwks.json"
    

    resp = requests.get(url)
    return json.dumps(json.loads(resp.text)["keys"][1])


app = Flask(__name__)
# app.config.from_object("config")
# app.config["JWT_PUBLIC_KEY"] = RSAAlgorithm.from_jwk(get_cognito_public_keys())
app.config['AWS_DEFAULT_REGION'] = 'us-east-1'
app.config['AWS_COGNITO_DOMAIN'] = 'https://rosely-web-chat.auth.us-east-1.amazoncognito.com/'
app.config['AWS_COGNITO_USER_POOL_ID'] = 'us-east-1_t2focHvIB'
app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'] = '77bh0lg75rdu1bhseuhkvsjq9q'
app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = '10g2o3qsc6iqi3id2f77tgfdpd6m3p2m4o6436ka8n8ki81pqrud'
# app.config['AWS_COGNITO_REDIRECT_URL'] = 'https://100cff30983e458e97902464ea0ffb37.vfs.cloud9.us-east-1.amazonaws.com/loggedin'
app.config['AWS_COGNITO_REDIRECT_URL'] = 'https://100cff30983e458e97902464ea0ffb37.vfs.cloud9.us-east-1.amazonaws.com/loggedin'

app.config['JWT_TOKEN_LOCATION'] = ["cookies"]
app.config['JWT_COOKIE_SECURE'] = True

# We're ok to set this off, as Cognito OAuth state provides protection
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ALGORITHM'] = "RS256"
app.config['JWT_IDENTITY_CLAIM'] = "sub"

def get_cognito_public_keys():
    region =  'us-east-1'
    pool_id = 'us-east-1_t2focHvIB'
    url = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"

    resp = requests.get(url)
    return json.dumps(json.loads(resp.text)["keys"][1])

app.config["JWT_PUBLIC_KEY"] = RSAAlgorithm.from_jwk(get_cognito_public_keys())




CORS(app)
aws_auth = AWSCognitoAuthentication(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")



@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(aws_auth.get_sign_in_url())


@app.route("/loggedin", methods=["GET"])
def logged_in():
    access_token = aws_auth.get_access_token(request.args)
    username = decode_token(access_token).get("username")
    resp = make_response(redirect(url_for("protected", username = username)))
    set_access_cookies(resp, access_token, max_age=30 * 60)
    return resp


@app.route("/chat")
def protected():
    verify_jwt_in_request(optional=True)
    if get_jwt_identity():
        # print("access_token: " + aws_auth.get_access_token(request.args))
        # username = request.args.get('username')
        # room = request.args.get('room')
        username = request.args.get('username')
        room = "friend1"
        return render_template("chat.html", username=username, room=room)
    else:
        return redirect(aws_auth.get_sign_in_url())
        
        
        
        
        
        
        
        
        
        


@socketio.on('send_message')
def handle_send_message_event(data):
    app.logger.info("{} has sent message to the room {}: {}".format(data['username'],
                                                                    data['room'],
                                                                    data['message']))
    socketio.emit('receive_message', data, room=data['room'])


@socketio.on('join_room')
def handle_join_room_event(data):
    app.logger.info("{} has joined the room {}".format(data['username'], data['room']))
    join_room(data['room'])
    socketio.emit('join_room_announcement', data, room=data['room'])


@socketio.on('leave_room')
def handle_leave_room_event(data):
    app.logger.info("{} has left the room {}".format(data['username'], data['room']))
    leave_room(data['room'])
    socketio.emit('leave_room_announcement', data, room=data['room'])
    
        
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    # app.debug = True
    # app.run()
    socketio.run(app, debug=True)