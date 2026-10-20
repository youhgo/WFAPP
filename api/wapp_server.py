import os
from flask import Flask
from extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////python-docker/db/users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'wapp_api.login_page'

    from api_views import wapp_api
    from api_parse import parse_api

    app.register_blueprint(wapp_api, url_prefix='/')
    app.register_blueprint(parse_api, url_prefix='/api/parse')
    app.config['CELERY_BROKER_URL'] = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    app.config['CELERY_RESULT_BACKEND'] = os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')

    # Créer les tables de la base de données et initialiser l'administrateur
    with app.app_context():
        db.create_all()
        from models import User
        import secrets

        admin_user = os.environ.get("WAPP_ADMIN_USER", "admin").strip().strip('"\'')
        admin_pass = os.environ.get("WAPP_ADMIN_PASSWORD", "").strip().strip('"\'')

        # Nettoyage de l'utilisateur par defaut non securise wapp:changeme si un autre admin est configure
        legacy_wapp = User.query.filter_by(username="wapp").first()
        if legacy_wapp and legacy_wapp.check_password("changeme") and admin_user != "wapp":
            db.session.delete(legacy_wapp)
            db.session.commit()
            print("[SECURITY] Removed insecure default 'wapp:changeme' user.", flush=True)

        existing_admin = User.query.filter_by(username=admin_user).first()
        if not existing_admin:
            if not admin_pass:
                admin_pass = secrets.token_urlsafe(16)
                print(f"\n======================================================\n[SECURITY] Initial Admin User Created:\n  Username: {admin_user}\n  Password: {admin_pass}\n======================================================\n", flush=True)
            else:
                print(f"\n[SECURITY] Initial Admin User Created: {admin_user}\n", flush=True)

            new_admin = User(username=admin_user, is_admin=True)
            new_admin.set_password(admin_pass)
            db.session.add(new_admin)
            db.session.commit()
        elif admin_pass:
            existing_admin.set_password(admin_pass)
            existing_admin.is_admin = True
            db.session.commit()

    import click

    @app.cli.command("create-admin")
    @click.option("--username", default="admin", help="Admin username")
    @click.option("--password", prompt=True, hide_input=True, help="Admin password")
    def create_admin_cmd(username, password):
        """Create or update an admin user."""
        from models import User
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, is_admin=True)
                db.session.add(user)
            user.set_password(password)
            user.is_admin = True
            db.session.commit()
            click.echo(f"Admin user '{username}' configured successfully.")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8880)

    # curl -X POST https://WFAPP.localhost/api/parse/parse_archive \
    # -F upload=/home/hro/Documents/working_zone/archive_orc/DFIR-ORC_WorkStation_DESKTOP-9I162HO1.7z \
    # -F data='{"caseName":"test"}'
