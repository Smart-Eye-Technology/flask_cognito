from collections import OrderedDict
from functools import wraps
from flask import _request_ctx_stack, current_app, jsonify, request
from werkzeug.local import LocalProxy
from cognitojwt import CognitoJWTException, decode as cognito_jwt_decode
from jose.exceptions import JWTError
import logging
import boto3
from botocore.exceptions import ClientError
import os
import json

log = logging.getLogger(__name__)

CONFIG_DEFAULTS = {
    'COGNITO_CHECK_TOKEN_EXPIRATION': True,
    'COGNITO_JWT_HEADER_NAME': 'Authorization',
    'COGNITO_JWT_HEADER_PREFIX': 'Bearer',
}

# user from pool
current_cognito_jwt = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'cogauth_cognito_jwt', None))

# unused - could be a way to add mapping of cognito user to application user
current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'cogauth_current_user', None))

# access initialized cognito extension
_cog = LocalProxy(lambda: current_app.extensions['cognito_auth'])


class CognitoAuthError(Exception):
    def __init__(self, error, description, status_code=401, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers
        

    def __repr__(self):
        return f'CognitoAuthError: {self.error}'

    def __str__(self):
        return f'{self.error} - {self.description}'


class CognitoAuth(object):
    identity_callback = None

    def __init__(self, app=None, identity_handler=None, api_secret=None):
        self.app = app
        self.api_secret=api_secret

        if app is not None:
            self.init_app(app, identity_handler=identity_handler)

    def init_app(self, app, identity_handler=None):
        for k, v in CONFIG_DEFAULTS.items():
            app.config.setdefault(k, v)

        # required configuration
        self.region = self._get_required_config(app, 'COGNITO_REGION')
        self.userpool_id = self._get_required_config(app, 'COGNITO_USERPOOL_ID')
        self.jwt_header_name = self._get_required_config(app, 'COGNITO_JWT_HEADER_NAME')
        self.jwt_header_prefix = self._get_required_config(app, 'COGNITO_JWT_HEADER_PREFIX')

        self.identity_callback = identity_handler

        # optional configuration
        self.check_expiration = app.config.get('COGNITO_CHECK_TOKEN_EXPIRATION', True)
        self.app_client_id = app.config.get('COGNITO_APP_CLIENT_ID')

        # save for localproxy
        app.extensions['cognito_auth'] = self

        # handle CognitoJWTExceptions
        # TODO: make customizable
        app.errorhandler(CognitoAuthError)(self._cognito_auth_error_handler)


    def get_secret(self):

        return '9C6RLL7bHhEw3Mc2VoCffJAQhZFFNMcA' #TODO: Fix this up

        secret_name = self.api_secret
        region_name = os.environ.get('AWS_REGION',"us-east-2")

        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager',region_name=region_name)
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            raise e
        else:
            # Decrypts secret using the associated KMS key.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                secretData = get_secret_value_response['SecretString']
                secretJSON=json.loads(secretData)
                secret=secretJSON['key']
                return secret
        return None 


    def _get_required_config(self, app, config_name):
        val = app.config.get(config_name)
        if not val:
            raise Exception(f"{config_name} not found in app configuration but it is required.")
        return val

    def identity_handler(self, callback):
        if self.identity_callback is not None:
            raise Exception(
                f"Trying to override existing identity_handler on CognitoAuth. You should only set this once.")
        self.identity_callback = callback
        return callback

    def get_token(self):
        """Get token from request."""
        auth_header_name = _cog.jwt_header_name
        auth_header_prefix = _cog.jwt_header_prefix

        # get token value from header
        auth_header_value = request.headers.get(auth_header_name)

        if not auth_header_value:
            # no auth header found
            return None

        parts = auth_header_value.split()

        if not auth_header_prefix:
            if len(parts) > 1:
                raise CognitoAuthError('Invalid Cognito JWT Header', 'Token contains spaces')
            return auth_header_value

        if parts[0].lower() != auth_header_prefix.lower():
            raise CognitoAuthError('Invalid Cognito JWT header',
                                   f'Unsupported authorization type. Header prefix "{parts[0].lower()}" does not match "{auth_header_prefix.lower()}"')
        elif len(parts) == 1:
            raise CognitoAuthError('Invalid Cognito JWT header', 'Token missing')
        elif len(parts) > 2:
            raise CognitoAuthError('Invalid Cognito JWT header', 'Token contains spaces')

        return parts[1]

    def get_user(self, jwt_payload):
        """Get application user identity from Cognito JWT payload."""
        if not self.identity_callback:
            return None
        return self.identity_callback(jwt_payload)

    def _cognito_auth_error_handler(self, error):
        log.info('Authentication Failure', exc_info=error)
        return jsonify(OrderedDict([
            ('error', error.error),
            ('description', error.description),
        ])), error.status_code, error.headers

    def decode_token(self, token):
        """Decode token."""
        try:
            return cognito_jwt_decode(
                token=token,
                region=self.region,
                app_client_id=self.app_client_id,
                userpool_id=self.userpool_id,
                testmode=not self.check_expiration,
            )
        except (ValueError, JWTError):
            raise CognitoJWTException('Malformed Authentication Token')

def cognito_auth_required(APIKeys: bool = False):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            _cognito_auth_required(APIKeys)
            return function(*args, **kwargs)
        return wrapper
    return decorator

def cognito_check_groups(groups: list):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            _cognito_check_groups(groups)
            return function(*args, **kwargs)
        return wrapper
    return decorator

## This adds an alias to the above function to resolve issue #16    
cognito_group_permissions = cognito_check_groups

def _cognito_check_groups(groups: list):
    """
        Does the actual work of verifying the user group to restrict access to some resources.
        :param groups a list with the name of the groups of Cognito Identity Pool
        :raise an exception if there is no group
    """

    if 'cognito:groups' not in current_cognito_jwt or current_cognito_jwt['cognito:groups'] is None:
        raise CognitoAuthError('Not Authorized',
                            'User doesn\'t have access to this resource',
                            status_code=403)

    if all([i not in current_cognito_jwt['cognito:groups'] for i in groups]):
        raise CognitoAuthError('Not Authorized',
                            'User doesn\'t have access to this resource',
                            status_code=403)


def _cognito_auth_required(APIKeys: bool = False):
    """Does the actual work of verifying the Cognito JWT data in the current request.
    This is done automatically for you by `cognito_jwt_required()` but you could call it manually.
    Doing so would be useful in the context of optional JWT access in your APIs.
    """
    authorized=False

    #Handle API Key validation
    if APIKeys:
        key= request.headers.get('x-api-key')
        if(key is not None):
            #validate auth
            secretValue=_cog.get_secret()
            if(key==secretValue):
                print("Authorized by x-api-key")
                authorized=True
            else:
                authorized=False
        else:
            authorized=False
    
    #If API key auth failed, try JWT
    if not authorized:
        token = _cog.get_token()
        if token is not None:
            try:
                # check if token is signed by userpool
                payload = _cog.decode_token(token=token)
                print("Authorized by JWT Bearer")
                authorized=True
            except CognitoJWTException as e:
                authorized=False
        else:
            authorized=False
    
    #Final catch to end auth
    if not authorized:
        raise Exception("Not Authorized")

    _request_ctx_stack.top.cogauth_cognito_jwt = payload
    _request_ctx_stack.top.cogauth_current_user = _cog.get_user(payload)
