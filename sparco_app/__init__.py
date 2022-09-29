from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

# create the extension

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'

# configure the Postgress database
username = "postgres"
password = "code*7"
dbname = "deployments"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SQLALCHEMY_DATABASE_URI"] = ("postgresql://root:code*7"
                                         "@localhost:5432/deployments")

db = SQLAlchemy(app)

from sparco_app import routes, model

# <--- create db object
with app.app_context():
    db.create_all()
