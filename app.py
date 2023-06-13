import os

from flask import Flask, send_from_directory
from flask import render_template
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restful import Api
from flask_sslify import SSLify

from acces_control import require_access
from datab import db, secret_key, secret_key2, admin_pass, email_pass, email_user, url, production
from resources.accounts import Accounts, AccountsList, money
from resources.email import eMail, eMail2, eMail3, mail, limiter2
# from resources.cerrarS import closes
from resources.login import Login, limiter
from resources.posts import Posts
from resources.ssrf import Product, Stock
from resources.xml import XML_HTTP

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['Admin_Pass'] = admin_pass
app.config['SECRET_KEY2'] = secret_key2




CORS(app, resources={r'/*': {'origins': '*'}})
if(production == 1):
    app.config['SQLALCHEMY_DATABASE_URI'] = url

else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CORS_SUPPORTS_CREDENTIALS'] = True
api = Api(app)
migrate = Migrate(app, db)
db.init_app(app)
sslify = SSLify(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = email_user
app.config['MAIL_PASSWORD'] = email_pass
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True


mail.init_app(app)
limiter.init_app(app)
limiter2.init_app(app)

api.add_resource(Accounts, '/account')
api.add_resource(AccountsList, '/accounts')

api.add_resource(Login, '/login')

api.add_resource(eMail, '/email')
api.add_resource(eMail2, '/email2')
api.add_resource(eMail3, '/email3')
api.add_resource(Posts, '/posts')

api.add_resource(XML_HTTP, '/sendxml')
api.add_resource(Product, '/product')
api.add_resource(Stock, '/stock')
#api.add_resource(closes, '/closes')


api.add_resource(money,'/money')#/<string:username>

from flask_wtf.csrf import  CSRFProtect

csrf = CSRFProtect(app)


@app.route('/')
def render_vue():
   return render_template('index.html')

@app.route('/inside')
def inside():
    return render_template("index.html")
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'none'"
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.before_request
@require_access
def acces_control():
    pass


if __name__ == '__main__':
    if (production == 1):
        app.run()
    else:
        app.run(host='127.0.0.1', port=5000, ssl_context=('cert.pem', 'key.pem'))



