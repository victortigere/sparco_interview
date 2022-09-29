from sparco_app import app, request, jsonify, db, make_response
from sparco_app.model import User
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps
import jwt

user_not_found = "User not found"


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


@app.route("/register", methods=["POST"])
def register():
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
                    request_data["user_image"],
                    0)
        db.session.add(user)
        db.session.commit()
        return jsonify({
            "code": "00",
            "data": "",
            "description": (f" {user.first_name}, have"
                            "successfully registered")
            })


@app.route("/login", methods=['POST'])
def login():
    if request.method == "GET":
        return "Return to login page "
    elif request.method == "POST":
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('could not verify', 401,
                                 {'Authentication': 'login required"'})

        user = User.query.filter_by(user_name=auth.username).first()
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id, 'exp':
                               datetime.datetime.utcnow() +
                               datetime.timedelta(minutes=45)},
                               app.config['SECRET_KEY'], "HS256")
            return jsonify({'token': token})

    return make_response('could not verify',  401,
                         {'Authentication': '"login required"'})


@app.route("/get/users", methods=["GET"])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify({
        "code": "00",
        "data": [user.serialized for user in users],
        "description": "Users fetched successfully"
    })


@app.route("/get/user/<int:id>", methods=["GET"])
@token_required
def get_user(current_user, id):
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


@app.route("/user/edit", methods=["POST"])
@token_required
def edit_user(current_user):
    request_data = request.get_json(force=True)
    user = User.query.filter_by(phone=request_data['phone']).first()
    if user is None:
        return jsonify({
            "code": "01",
            "data": "",
            "description": user_not_found
        })

    user.first_name = request_data['first_name']
    user.last_name = request_data['last_name']
    user.phone = request_data['phone']
    user.image = request_data['user_image']
    db.session.commit()

    return jsonify({
            "code": "00",
            "data": [user.serialized],
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


@app.route("/info")
def info():
    return "Sparco Webservice"
