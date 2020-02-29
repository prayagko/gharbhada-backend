from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
import json
import datetime
from bson.objectid import ObjectId
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required, get_jwt_identity)
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from schema import validate_user, validate_property, validate_property_update
import upload
from werkzeug.utils import secure_filename


class JSONEncoder(json.JSONEncoder):
    ''' extend json-encoder class'''

    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime.datetime):
            return str(o)
        return json.JSONEncoder.default(self, o)


app = Flask(__name__)
mongo = PyMongo(app)
app.json_encoder = JSONEncoder
app.config["DEBUG"] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
flask_bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        'ok': False,
        'message': 'Missing Authorization Header'
    }), 401


@app.route('/auth', methods=['POST'])
def auth_user():
    ''' auth endpoint '''
    data = validate_user(request.get_json())
    if data['ok']:
        data = data['data']
        user = mongo.db.users.find_one({'number': data['number']}, {"_id": 0})
        if user and flask_bcrypt.check_password_hash(user['password'], data['password']):
            del user['password']
            access_token = create_access_token(identity=data, expires_delta=False)
            refresh_token = create_refresh_token(identity=data)
            user['token'] = access_token
            user['refresh'] = refresh_token
            return jsonify({'ok': True, 'message': 'User Successfully Authenticated', 'data': user}), 200
        else:
            return jsonify({'ok': False, 'message': 'invalid number or password'}), 401
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400


@app.route('/register', methods=['POST'])
def register():
    ''' register user endpoint '''
    body = request.get_json()
    data = validate_user(body)
    if 'name' in body and (body['name']).strip():
        if data['ok']:
            data = data['data']
            data['password'] = flask_bcrypt.generate_password_hash(
                data['password'])
            user = mongo.db.users.find_one({'number': data['number']}, {"_id": 0})
            if user is not None:
                return jsonify({
                    'ok': False,
                    'message': 'User with number already exists'
                }), 400
            mongo.db.users.insert_one(data)
            return jsonify({'ok': True, 'message': 'User created successfully!'}), 201
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters'}), 400
    else:
        return jsonify({'ok':False, 'message': 'Name field required'}), 400


# @app.route('/refresh', methods=['POST'])
# @jwt_refresh_token_required
# def refresh():
#     ''' refresh token endpoint '''
#     current_user = get_jwt_identity()
#     ret = {
#         'refresh': create_refresh_token(identity=current_user),
#         'token': create_access_token(identity=current_user)
#     }
#     return jsonify({'ok': True, 'data': ret}), 201


@app.route('/user', methods=['GET', 'DELETE', 'PATCH'])
@jwt_required
def user():
    ''' route read user '''
    if request.method == 'GET':
        query = request.args
        data = mongo.db.users.find_one(query, {"_id": 0, "password": 0})
        return jsonify({'ok': True, 'message':'User Successfully retreived', 'data': data}), 200

    data = request.json
    if request.method == 'DELETE':
        if data.get('number', None) is not None:
            if data['number'] == get_jwt_identity()['number']:
                db_response = mongo.db.users.delete_one({'number': data['number']})
                if db_response.deleted_count == 1:
                    mongo.db.properties.delete_many({'number': data['number']})
                    response = {'ok': True, 'message': 'record deleted'}
                else:
                    response = {'ok': True, 'message': 'no record found'}
                return jsonify(response), 200
            else:
                return jsonify({'ok':False, 'message': 'Delete unauthorized'}), 401
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

    if request.method == 'PATCH':
        query = data.get('query', {})
        payload = data.get('payload', {})
        if query != {} and 'number' in query:
            user_check = mongo.db.users.find_one({'number': payload['number']}, {"_id": 0})
            if user_check is not None:
                return jsonify({
                    'ok': False,
                    'message': 'User with number already exists'
                }), 401
            if query['number'] == get_jwt_identity()['number']:
                mongo.db.users.update_one(
                    data['query'], {'$set': payload})
                if 'number' in payload:
                    mongo.db.properties.update_many({
                        'number': query['number']}, {'$set': {'number': payload['number']}})
                return jsonify({'ok': True, 'message': 'record updated'}), 200
            else:
                return jsonify({'ok':False, 'message': 'Update unauthorized'}), 401
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400


@app.route('/property', methods=['GET', 'POST', 'DELETE', 'PATCH'])
@jwt_required
def property():
    ''' route read property '''
    if request.method == 'GET':
        query = request.args
        data = mongo.db.properties.find_one({'_id': ObjectId(query['id'])})
        return jsonify({'ok': True, 'message': 'Property Retreived', 'data': data}), 200

    data = request.get_json()
    if request.method == 'POST':
        user = get_jwt_identity()
        print(user)
        number = user['number']
        poster = mongo.db.users.find_one({'number': number}, {'_id': 0, 'password':0})
        if not poster:
            return jsonify({'ok': False, 'message': 'User does not exist'}), 404
        data['number'] = number
        data['author'] = poster['name']
        data['status'] = 'active'
        print(data)
        data = validate_property(data)
        if data['ok']:
            db_response = mongo.db.properties.insert_one(data['data'])
            return_data = mongo.db.properties.find_one(
                {'_id': db_response.inserted_id})
            return jsonify({'ok': True, 'message': 'Property Successfully Listed', 'data': return_data}), 201
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters:'}), 400

    if request.method == 'DELETE':
        if data.get('id', None) is not None:
            property_check = mongo.db.properties.find_one(
                {'_id': ObjectId(data['id'])})
            if property_check['number'] == get_jwt_identity()['number']:
                db_response = mongo.db.properties.delete_one(
                    {'_id': ObjectId(data['id'])})
                if db_response.deleted_count == 1:
                    response = {'ok': True, 'message': 'record deleted'}
                else:
                    response = {'ok': True, 'message': 'no record found'}
                return jsonify(response), 200
            else:
                jsonify({'ok': False, 'message': 'Delete unauthorized!'}), 401
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

    if request.method == 'PATCH':
        data = validate_property_update(data)
        if data['ok']:
            data = data['data']
            property_check = mongo.db.properties.find_one({'_id': ObjectId(data['id'])})
            if property_check['number'] != get_jwt_identity()['number']:
                return jsonify({'ok': False, 'message': 'Update Unauthorized'}), 401
            mongo.db.properties.update_one(
                {'_id': ObjectId(data['id'])}, {'$set': data['payload']})
            return jsonify({'ok': True, 'message': 'record updated'}), 200
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400


@app.route('/list/property', methods=['GET'])
@jwt_required
def list_properties():
    ''' route to get all the properties for a user '''
    user = get_jwt_identity()

    if user:
        data = mongo.db.properties.find({'number': user['number']})
        return_data = list(data)
        if return_data:
            return jsonify({'ok': True, 'message':'Properties Retreived', 'data': return_data}), 200
        else:
            return jsonify({'ok': True, 'message': 'No properties listed'}), 200


#
@app.route('/search/property', methods=['GET'])
@jwt_required
def search_properties():
    ''' route to search properties using keywords '''
    query = request.args
    user = get_jwt_identity()
    print(user)
    if 'location' in query:
        location = query['location']
        data = mongo.db.properties.find({'location': {'$regex': location, "$options": "-i"}, 'status': 'active'})
        return_data = list(data)
        if return_data:
            return jsonify({
                'ok': True,
                'data': return_data,
                'message': 'Properties Retrieved'
            }), 200
        else:
            return jsonify({'ok': True, 'message': 'No properties found'}), 200
    else:
        return jsonify({'ok': False, 'message': 'Bad Request Parameter'}), 400


@app.route('/upload', methods=['POST'])
# @jwt_required
def upload_image():
    if "image" not in request.files:
        return jsonify({'ok': False, 'message': 'Bad Request Parameter.'}), 400
    file = request.files["image"]
    if file.filename == "":
        return jsonify({'ok': False, 'message': 'Please Select an Image'}), 400

    if file and upload.allowed_file(file.filename):
        file.filename = secure_filename(file.filename)
        output = upload.upload_file_to_s3(file, upload.BUCKET_NAME)
        return jsonify({'ok': True, 'message': 'Image Uploaded', 'url': str(output)}), 201

    else:
        return jsonify({'ok': False, 'message': 'Image could not be uploaded'}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010)



