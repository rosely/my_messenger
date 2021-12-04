import os

AWS_DEFAULT_REGION = 'us-east-1'
JWT_TOKEN_LOCATION = ["cookies"]
JWT_COOKIE_SECURE = True

# We're ok to set this off, as Cognito OAuth state provides protection
JWT_COOKIE_CSRF_PROTECT = False
JWT_ALGORITHM = "RS256"
JWT_IDENTITY_CLAIM = "sub"

# SECRET_KEY = os.environ["SECRET_KEY"]
# JWT_PRIVATE_KEY = os.environ["JWT_PRIVATE_KEY"]
# #  We're using Cognito to generate keys, so this is never used
# JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]




AWS_COGNITO_DOMAIN = 'https://rosely-web-chat.auth.us-east-1.amazoncognito.com/'
AWS_COGNITO_USER_POOL_ID = 'us-east-1_t2focHvIB'
AWS_COGNITO_USER_POOL_CLIENT_ID = '77bh0lg75rdu1bhseuhkvsjq9q'
AWS_COGNITO_USER_POOL_CLIENT_SECRET = '10g2o3qsc6iqi3id2f77tgfdpd6m3p2m4o6436ka8n8ki81pqrud'
AWS_COGNITO_REDIRECT_URL = '/loggedin'