from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_awscognito import AWSCognitoAuthentication
from flask_cors import CORS
from jwt.algorithms import RSAAlgorithm
from flask_jwt_extended import (
    JWTManager,
    set_access_cookies,
    verify_jwt_in_request,
    get_jwt_identity,
)


app = Flask(__name__)
app.config.from_object("config")
app.config["JWT_PUBLIC_KEY"] = RSAAlgorithm.from_jwk(get_cognito_public_keys())

CORS(app)
aws_auth = AWSCognitoAuthentication(app)
jwt = JWTManager(app)

def get_cognito_public_keys():
    region = os.environ["AWS_REGION"]
    pool_id = os.environ["AWS_COGNITO_USER_POOL_ID"]
    url = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"

    resp = requests.get(url)
    return json.dumps(json.loads(resp.text)["keys"][1])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(aws_auth.get_sign_in_url())


@app.route("/loggedin", methods=["GET"])
def logged_in():
    access_token = aws_auth.get_access_token(request.args)
    resp = make_response(redirect(url_for("protected")))
    set_access_cookies(resp, access_token, max_age=30 * 60)
    return resp


@app.route("/secret")
def protected():
    verify_jwt_in_request(optional=True)
    if get_jwt_identity():
        return render_template("secret.html")
    else:
        return redirect(aws_auth.get_sign_in_url())