from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import InvalidRequestError


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role=db.Column(db.String(100))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def remove(self):
        db.session.delete(self)
        db.session.commit()
with app.app_context():
    db.create_all()
@app.route('/register', methods=['GET','POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role=data['role']
    user = User(username=username,role=role)
    user.set_password(password)
    existing_user= User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message':'User already exist'})
    elif role!="admin" and role!="user":
        return jsonify({'message':'not a valid role'})
    user.save()
    return jsonify({'message': 'User registered successfully'})
@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/delete', methods=['GET','POST'])
def delete():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role=data['role']
    
    user = User.query.filter_by(username=username).first()
    if user:
        if user.role=="admin" and user.check_password(password):
            user.remove()
            return jsonify({'message': 'user data deleted successfully'}), 200
        else:
            return jsonify({'message': 'user does not have access'}), 401
    else:
        return jsonify({'message':'user does not exist'})
@app.route('/password_update', methods=['GET','POST'])
def password_update():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        user.remove()
        username=data['username']
        password=data['new_password']
        user = User(username=username)
        user.set_password(password)
        user.save()
        return jsonify({'message': 'user data updated successfully'}), 200
    else:
        return jsonify({'message': 'user not exist'}), 401
if __name__ == '__main__':
    app.run(debug=True)