from flask import Flask, jsonify
from flask_mongoengine import MongoEngine

app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'app_db',
    'host': 'localhost',
    'port': 27017
}
db = MongoEngine()
db.init_app(app)

app.config['SECRET_KEY'] = 'secret'


@app.route('/test/', methods=['GET'])
def test():
    return jsonify({"Message": "Working"})


if __name__ == "__main__":
    app.run(debug=True)
