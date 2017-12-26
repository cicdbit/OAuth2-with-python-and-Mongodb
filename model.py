from pymodm import connect, fields, MongoModel

connect('mongodb://localhost:27017/oauth2')

class User(MongoModel):
    username = fields.CharField(required=True)
    password = fields.CharField(required=True)


class Client(MongoModel):
    client_id = fields.CharField(required=True)
    client_secret = fields.CharField(required=True)
    user_id = fields.CharField(required=True)
    redirect_uris = fields.CharField()
    default_redirect_uri = fields.CharField()
    default_scopes = fields.ListField()
    is_confidential = fields.BooleanField(default=False)


class Grant(MongoModel):
    client_id = fields.CharField()
    code = fields.CharField()
    redirect_uri = fields.CharField()
    expires = fields.DateTimeField()
    scopes = fields.CharField()
    user = fields.ReferenceField(User)


class Token(MongoModel):
    client_id = fields.CharField()
    user = fields.ReferenceField(User)
    token_type = fields.CharField()
    access_token = fields.CharField()
    refresh_token = fields.CharField()
    expires = fields.DateTimeField()
