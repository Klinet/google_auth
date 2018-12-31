import os

import httplib2
from flask import Flask, jsonify, session, request, flash, make_response, json, Blueprint
from google import oauth2
from flask import request, redirect, url_for

from flask_oauth2_login import GoogleLogin

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SECRET_KEY="secret",
    GOOGLE_LOGIN_REDIRECT_SCHEME="http",
)
for config in (
        "GOOGLE_LOGIN_CLIENT_ID",
        "GOOGLE_LOGIN_CLIENT_SECRET",
):
    app.config.from_pyfile('config.py')
    # app.config[config] = os.environ[config]
google_login = GoogleLogin(app)
logout = Blueprint("logout", __name__)


@app.route("/")
def index():
    return """
<html>
<a href="{}">Login with Google</a>
""".format(google_login.authorization_url())


# Add a logout handler.
# Logout
@app.route('/disconnect')
def disconnect():
    """
    Check the authentication provider and then calls the respective disconnect
    function. Also deletes the data saved in session variable.
    """
    if 'provider' in session:
        if session['provider'] == 'google':
            gdisconnect()
            del session['gplus_id']

        del session['provider']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        del session['access_token']

        flash('You have successfully logged out')
        # return redirect(url_for('/'))
        return redirect(url_for('_google_login'))
    else:
        flash('You are not logged in')
        return redirect(url_for('_google_login'))


@google_login.login_success
def login_success(token, profile):
    return jsonify(token=token, profile=profile)


@google_login.login_failure
def login_failure(e):
    return jsonify(error=str(e))


# Logout from google account
@app.route('/gdisconnect')
def gdisconnect():
    """
    Disconnects from Google Sign In API.
    """
    access_token = session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps(
            'No active session for current user'), 401)
        response.headers['Content-Type'] = 'application/json'
        flash('You are not logged out')
        return redirect('/')
        # return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
