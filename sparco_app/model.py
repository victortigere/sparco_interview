from sparco_app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(80), nullable=False)
    user_name = db.Column(db.String, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, unique=True, nullable=False)
    user_image = db.Column(db.String, nullable=False)
    access_right = db.Column(db.String, nullable=False)

    @property
    def serialized(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'user_image': self.user_image,
        }

    def __init__(self, public_id, user_name, password, first_name,
                 last_name, phone,
                 user_image, access_right):
        self.public_id = public_id
        self.user_name = user_name
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.phone = phone
        self.user_image = user_image
        self.access_right = access_right
