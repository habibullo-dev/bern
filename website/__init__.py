from flask import Flask
from flask_wtf import CSRFProtect
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config["WTF_CSRF_ENABLED"] = True

    csrf = CSRFProtect(app)
    
    from .auth import auth as auth_blueprint
    from .main import main as main_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(main_blueprint)

    return app