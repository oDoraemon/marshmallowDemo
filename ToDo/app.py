# -*- coding:utf-8 -*-
###
# Created Date: 2018-06-28, 16:24:46
# Author: Chen Yongle
# -----
# Last Modified: 2018-06-28, 17:13:53
# Modified By: Chen Yongle
# -----
# Description:
###
import datetime as dt
from functools import wraps

from flask import Flask, request, g, jsonify
import peewee as pw
from marshmallow import Schema, fields, validate, pre_load, post_dump, post_load, ValidationError

app = Flask(__name__)
db = pw.SqliteDatabase('../todo.db')

class BaseModel(pw.Model):
    class Meta:
        database = db

class User(BaseModel):
    email = pw.CharField(max_length=80, unique=True)
    password = pw.CharField()
    creation_time = pw.DateTimeField()

class Todo(BaseModel):
    content = pw.TextField()
    is_done = pw.BooleanField(default=False)
    user = pw.ForeignKeyField(User)
    posted_on = pw.DateTimeField()

    class Meta:
        order_by = ('-posted_on',)

def create_tables():
    db.connect()
    User.create_table(True)
    Todo.create_table(True)

## SCHEMA ##
class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    email = fields.Str(
        required=True,
        validate=validate.Email(error='Not a valid email address'),
    )
    password = fields.Str(
        required=True,
        validate=[validate.Length(min=6, max=36)],
        load_only=True,
    )
    creation_time = fields.DateTime(dump_only=True)

    @pre_load
    def process_input(self, data):
        data['email'] = data['email'].lower.strip()
        return data
    
    @post_dump(pass_many=True)
    def wrap(self, data, many):
        key = 'users' if many else 'user'
        return {key: data,}

class TodoSchema(Schema):
    id = fields.Int(dump_only=True)
    done = fields.Boolean(attribute='is_done', missing=False)
    user = fields.Nested(UserSchema, exclude=('creation_time', 'password'))
    content = fields.Str(required=True)
    posted_on = fields.DateTime(dump_only=True)

    @post_dump(pass_many=True)
    def wrap(self, data, many):
        key = 'todos' if many else 'todo'
        return {key: data}
    
    @post_load
    def make_object(self, data):
        if not data:
            return None
        return Todo(
            content=data['content'],
            is_done=data['is_done'],
            posted_on=dt.datetime.now(),
        )

user_schema = UserSchema()
todo_schema = TodoSchema()
todos_schema = TodoSchema(many=True)

## Helpers ##

def check_auth(email, password):
    try:
        user = User.get(User.email == email)
    except User.DoesNotExist:
        return False
    return password == user.password

def requies_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            resp = jsonify({'message': 'Authorization needed'})
            resp.status_code = 401
            resp.headers['WWW-Authenticate'] = 'Basic realm="Example"'
            return resp
        kwargs['user'] = User.get(User.email == auth.username)
        return f(*args, **kwargs)
    return decorated

@app.before_request
def before_request():
    g.db = db
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

## API ##
@app.route('/register', methods=['POST'])
def register():
    json_input = request.get_json()
    try:
        data = user_schema.load(json_input)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 422
    try:
        User.get(User.email == data['email'])
    except User.DoesNotExist:
        user = User.create(
            email=data['email'], creation_time=dt.datetime.now(),
            password=data['password'],
        )
        message = 'Successfully created User :{0}'.format(user.email)
    else:
        return jsonify({'errors': 'That email address already exist'}), 400
    
    data = user_schema.dump(user)
    data['message'] = message
    return jsonify(data), 201
