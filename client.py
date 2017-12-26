from flask import Flask, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth

CLIENT_ID = '$2b$12$ZDAxFza.3zN6Aur2DgzMW.'
CLIENT_SECRET = '$2b$12$NNUZpv8dtiQG8kUK9N33Bu'

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)


remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url='http://localhost:5002/api/',
    request_token_url=None,
    access_token_url='http://localhost:5002/oauth/token',
    authorize_url='http://localhost:5002/oauth/authorize'
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        resp = remote.get('me')
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(callback=url_for('authorized', next=next_url, _external=True))


@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'], request.args['error_description'])

    print('resp', resp)
    session['remote_oauth'] = (resp['access_token'], '')
    return jsonify(oauth_token=resp['access_token'])


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app.run(port=8001)
