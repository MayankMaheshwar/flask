from flask import Flask, jsonify, request, make_response
from configurations import DevelopmentConfig
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

app.config['SECRET_KEY'] = 'mayankmaheshwari'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can view this'})


@app.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'This required valid tokens'})


@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == 'password':
        token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(days=1)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could\'nt verify', 401, {'WWW-Authenticate': 'Basic Realm="Login Required"'})


if __name__ == '__main__':
    app.run()
