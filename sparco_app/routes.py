from sparco_app import app, request, jsonify, db, make_response
from sparco_app.model import User
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import datetime
from functools import wraps
import jwt
import os

user_not_found = "User not found"
path = "./frontend/sparco-client/public/images/faces/"


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=["HS256"])
            current_user = User.query.filter_by(
                                public_id=data['public_id']).first()
        except Exception:
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)
    return decorator


@app.route("/api/register", methods=["POST"])
def register():
    user_image = ""
    if request.method == "GET":
        return jsonify({
            "code": "00",
            "data": "",
            "description": "May you please login to your account"
            })
    elif request.method == "POST":
        request_data = request.get_json(force=True)
        hashed_password = generate_password_hash(request_data['password'],
                                                 method='sha256')

        user = User(
                    str(uuid.uuid4()),
                    request_data["username"],
                    hashed_password,
                    request_data["first_name"],
                    request_data["last_name"],
                    request_data["phone"],
                    user_image,
                    1)
        db.session.add(user)
        db.session.commit()
        return jsonify({
            "code": "00",
            "data": "",
            "description": (f" {user.first_name}, have"
                            "successfully registered")
            })


@app.route("/api/login", methods=['POST'])
def login():
    if request.method == "GET":
        return "Return to login page "
    elif request.method == "POST":
        request_data = request.get_json(force=True)
        user = User.query.filter_by(user_name=request_data["username"]).first()
        if user is not None:
            if check_password_hash(user.password, request_data["password"]):
                token = jwt.encode({'public_id': user.public_id, 'exp':
                                   datetime.datetime.utcnow() +
                                   datetime.timedelta(minutes=45)},
                                   app.config['SECRET_KEY'], "HS256")
                return jsonify({
                    'token': token,
                    'access': user.access_right
                    })
            else:
                return make_response('could not verify, login required',  401,
                                     {'Authentication': '"login required"'})
    return make_response('Login failed, please check your credentials',  401,
                         {'Authentication': '"login required"'})


@app.route("/api/get/members", methods=["GET"])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify({
        "code": "00",
        "data": [user.serialized for user in users],
        "description": "Users fetched successfully"
    })


@app.route("/api/get/profiles", methods=["GET"])
@token_required
def get_profiles(current_user):
    users = User.query.filter(User.id != current_user.id).all()
    return jsonify({
        "code": "00",
        "data": [user.serialized for user in users],
        "description": "Users fetched successfully"
    })


@app.route("/api/get/user/<int:id>", methods=["GET"])
@token_required
def get_user(current_user, id):
    print("called this endpoint")
    user = User.query.filter_by(id=id).first()
    if user is None:
        return jsonify({
            "code": "00",
            "data": "",
            "description": user_not_found
        })

    return jsonify({
        "code": "00",
        "data": [user.serialized],
        "description": "User fetched successfully"
    })


@app.route("/api/user/edit", methods=["POST"])
@token_required
def edit_user(current_user):
    request_data = request.get_json(force=True)
    user_id = request_data["id"]
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({
            "code": "01",
            "data": "",
            "description": user_not_found
        })
    user.first_name = request_data['first_name']
    user.last_name = request_data['last_name']
    user.phone = request_data['phone']
    user.access_right = 1
    db.session.commit()

    return jsonify({
            "code": "00",
            "data": [current_user.serialized],
            "description": "User updated succesfully"
    })


@app.route("/api/user/delete/<int:id>")
@token_required
def delete_user(current_user, id):
    user = User.query.filter_by(id=id).first()
    if user is None:
        return jsonify({
            "code": "01",
            "data": "",
            "description": user_not_found
        })


    db.session.delete(user)
    db.session.commit()
    return jsonify({
            "code": "00",
            "data": "",
            "description": "User deleted succesfuly"
        })


@app.route("/api/user/detail")
@token_required
def get_current_user(current_user):
    if current_user is None:
        return jsonify({
            "code": "00",
            "data": "",
            "description": user_not_found
        })

    return jsonify({
        "code": "00",
        "data": [current_user.serialized],
        "description": "User fetched successfully"
    })


@app.route("/api/image/upload", methods=["POST"])
@token_required
def image_upload(current_user):
    if current_user is None:
        return jsonify({
            "code": "00",
            "data": "",
            "description": user_not_found
        })
    user_id = current_user.id
    user = User.query.filter_by(id=user_id).first()
    if user is not None:
        if request.files:
            image = request.files["user_image"]
            filename = secure_filename(image.filename)
            if(os.path.exists(path+filename)):
                return jsonify({
                    "code": "01",
                    "data": None,
                    "description": "Image already exist"
                    })
            image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))
            user.user_image = filename
            db.session.commit()
            return jsonify({
                "code": "00",
                "data": [current_user.serialized],
                "description": "User image updated successfully"
            })
    return jsonify({
                    "code": "01",
                    "data": None,
                    "description": "Request could not be processed"
                })


@app.route("/info")
def info():
    return "Sparco Webservice"
    # https://www.loginradius.com/blog/engineering/guest-post/securing-flask-api-with-jwt/
