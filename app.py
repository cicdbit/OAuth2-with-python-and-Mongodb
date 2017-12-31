from datetime import datetime, timedelta
from flask import Flask, session, request, render_template, redirect, jsonify
from flask_oauthlib.provider import OAuth2Provider
import bcrypt
from bson.objectid import ObjectId
from pymodm.errors import DoesNotExist
from model import User, Client, Grant, Token


app = Flask(__name__, template_folder='templates')
app.secret_key = 'secret'
oauth = OAuth2Provider(app)


def current_user():
    if 'id' in session:
        uid = session['id']
        try:
            return User.objects.get({'_id': ObjectId(uid)})
        except DoesNotExist as err:
            print('current_user -->', 'User model does not exists for id %s :' % (uid), err)
            return None
    return None


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        try:
            user = User.objects.get({'username': username})
        except DoesNotExist as err:
            print('home -->', 'User model does not exists for username %s :' % (username), err)
            user = User(username, 'password').save(force_insert=True)

        if not user:
            user = User(username, 'password').save(force_insert=True)

        session['id'] = str(user.pk)
        return redirect('/')

    user = current_user()
    return render_template('home.html', user=user)


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')

    client = Client(client_id=bcrypt.gensalt().decode('utf-8'),
                    client_secret=bcrypt.gensalt().decode('utf-8'),
                    user_id=user.pk,
                    redirect_uris=' '.join([
                        'http://localhost:8001/authorized',
                        'http://127.0.0.1:8001/authorized'
                    ]),
                    default_scopes=['email']
                    ).save(force_insert=True)

    return jsonify(client_id=client.client_id,
                   client_secret=client.client_secret)


@oauth.clientgetter
def load_client(client_id):
    try:
        return Client.objects.get({'client_id': client_id})
    except DoesNotExist as err:
        print('load_client -->', 'Client model does not exists for client_id %s :' % (client_id), err)
        return None


@oauth.grantgetter
def load_grant(client_id, code):
    try:
        return Grant.objects.get({'client_id': client_id, 'code': code})
    except DoesNotExist as err:
        print('load_grant', 'Grant model does not exists for client_id %s and code %s:' % (client_id, code), err)
        return None


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=1000)
    grant = Grant(client_id=client_id,
                  code=code['code'],
                  redirect_uri=request.redirect_uri,
                  expires=expires,
                  scopes=' '.join(request.scopes),
                  user=User.objects.get({'_id': ObjectId(request.client.user_id)})
                  ).save(force_insert=True)
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    try:
        if access_token:
            return Token.objects.get({'access_token': access_token})
        elif refresh_token:
            return Token.objects.get({'refresh_tokens': refresh_token})
    except DoesNotExist as err:
        print('load_token -->', 'Token model does not exists:', err)
        return None


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    try:
        toks = Token.objects.get({'client_id': request.client.client_id, 'user_id': request.user.pk})
        for t in toks:
            t.delete()
    except DoesNotExist as err:
        print('Token model does not exists for client_id %s and user_id %s:' % (request.client.client_id, request.user.pk), err)

    expires_in = token['expires_in']
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(client_id=request.client.client_id,
                user=request.user,
                token_type=token['token_type'],
                access_token=token['access_token'],
                refresh_token=token['refresh_token'],
                expires=expires
                ).save(force_insert=True)
    return tok


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')

    if request.method == 'GET':
        client_id = kwargs.get('client_id')

        try:
            client = Client.objects.get({'client_id': client_id})
            kwargs['client'] = client
        except DoesNotExist as err:
            print('authorize -->', 'Client model does not exists for client_id %s:' % (client_id), err)

        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)


if __name__ == '__main__':
    app.run(port=5002, debug=True)
