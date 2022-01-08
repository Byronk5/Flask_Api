
from flask import Flask, jsonify, request, make_response
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
import jwt

app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'app_db',
    'host': 'localhost',
    'port': 27017
}
db = MongoEngine()
db.init_app(app)

app.config['SECRET_KEY'] = 'secret'

# Models


class User(db.Document):
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True, min_length=6)
    created = db.DateTimeField(default=datetime.datetime.now, required=True)
    updated = db.DateTimeField(default=datetime.datetime.now, required=True)


class Profile(db.Document):
    id_user = db.StringField(required=True)
    name = db.StringField()
    surname = db.StringField()
    phone = db.StringField()
    created = db.DateTimeField(default=datetime.datetime.now, required=True)
    updated = db.DateTimeField(default=datetime.datetime.now, required=True)

# Token to Protect Routes


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({"message": "token is missing"}), 401

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.objects(id=data['id']).first()

        except:
            return jsonify({"message": "token is invalid"}), 401

        return func(current_user, *args, **kwargs)

    return decorated

# Register Route


@app.route('/register/', methods=["POST"])
def create_user():
    try:
        data = request.get_json()

        hashed_password = generate_password_hash(
            data['password'])
        new_user = User(email=data['email'],
                        password=hashed_password)
        new_user.save()

        return jsonify({"Message": "New user created!"}), 201

    except Exception as ex:
        print(ex)
        return jsonify({"Message": "Unable to create user!"}), 401


# Login Route


@app.route('/login/', methods=['POST'])
def login():

    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):

        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm ="Wrong Password !"'})

    user = User.objects(email=auth.get('email')).get()

    for pw in user:
        pw = user.password

    if not user:

        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm ="Wrong Password !"'})

    if check_password_hash(pw, auth.get('password')):

        token = jwt.encode({"id": str(user.id), 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(seconds=300)}, app.config['SECRET_KEY'], algorithm="HS256")

        return make_response(jsonify({'token': token}), 201)

    return make_response('could not verify', 403, {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'})


if __name__ == "__main__":
    app.run(debug=True)
