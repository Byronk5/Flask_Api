
from flask import Flask, jsonify, request
from flask_mongoengine import MongoEngine
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

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

        return jsonify({"Message": "New user created!"}), 200

    except Exception as ex:
        print(ex)
        return jsonify({"Message": "Unable to create user!"}), 401


if __name__ == "__main__":
    app.run(debug=True)
