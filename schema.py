from jsonschema import validate
from jsonschema.exceptions import ValidationError
from jsonschema.exceptions import SchemaError

user_schema = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
        },
        "number": {
            "type": "string",
            "pattern": "^[0-9]{10}$"
        },
        "password": {
            "type": "string",
            "minLength": 5
        }
    },
    "required": ["number", "password"],
    "additionalProperties": False
}


def validate_user(data):
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}


property_schema = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string"
        },
        "description": {
            "type": "string"
        },
        "status": {
            "type": "string",
            "enum": ["active", "inactive"]
        },
        "number": {
            "type": "string",
            "pattern": "^[0-9]{10}$"
        },
        "author": {
            "type": "string"
        },
        "price": {
            "type": "string",
            "pattern": "^(?!$)(?!0+$)\d{0,6}(?:\.(?!0{1,2}$)\d{1,2})?$"
        },
        "location": {
            "type": "string",
        },
        "url":{
            "type": "string",
        }
    },
    "required": ["title", "description", "number", "author", "status", "price", "location", "url"],
}

property_update_schema = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string"
        },
        "payload": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "inactive"]
                },
                "price": {
                    "type": "string",
                    "pattern": "^(?!$)(?!0+$)\d{0,6}(?:\.(?!0{1,2}$)\d{1,2})?$"
                },
                "location": {
                    "type": "string"
                }
            },
            "additionalProperties": False
        }
    },
    "required": ["id", "payload"],
    "additionalProperties": False
}


def validate_property_update(data):
    try:
        validate(data, property_update_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}


def validate_property(data):
    try:
        validate(data, property_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}
