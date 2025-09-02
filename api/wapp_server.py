from flask import Flask
from extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'votre_cle_secrete_ici'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////python-docker/db/users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'wapp_api.login_page'

    from api_views import wapp_api
    from api_parse import parse_api

    app.register_blueprint(wapp_api, url_prefix='/')
    app.register_blueprint(parse_api, url_prefix='/api/parse')
    app.config['CELERY_BROKER_URL'] = 'redis://redis:6379/0'
    app.config['CELERY_RESULT_BACKEND'] = 'redis://redis:6379/0'

    # Créer les tables de la base de données
    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8880)

    # curl -X POST https://WFAPP.localhost/api/parse/parse_archive \
    # -F upload=/home/hro/Documents/working_zone/archive_orc/DFIR-ORC_WorkStation_DESKTOP-9I162HO1.7z \
    # -F data='{"caseName":"test"}'
