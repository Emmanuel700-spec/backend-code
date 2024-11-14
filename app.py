import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import logging
from wtforms import SelectField
from flask_admin.form.widgets import Select2Widget

def create_app():
    # Initialize Flask application
    app = Flask(__name__)

    # Set the secret key for sessions and CSRF protection
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))

    # Set the database URI from environment variables for production/deployment
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://moringa:Group5@localhost:5432/moringa_database')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize SQLAlchemy, LoginManager, Flask-Admin, and Migrate
    db = SQLAlchemy(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'  # Default login view
    migrate = Migrate(app, db)

    # Initialize Flask-Admin
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

    # User model
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(120), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
        role = db.Column(db.String(50), nullable=False, default='user')  # admin, tech_writer, user

        def __repr__(self):
            return f'<User {self.username}>'

        # Hash password before storing it
        def set_password(self, password):
            self.password = generate_password_hash(password)

        # Check if entered password is correct
        def check_password(self, password):
            return check_password_hash(self.password, password)

    # Content model (posts)
    class Content(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(200), nullable=False)
        body = db.Column(db.Text, nullable=False)
        category = db.Column(db.String(50), nullable=False)
        is_approved = db.Column(db.Boolean, default=False)
        is_flagged = db.Column(db.Boolean, default=False)  # Ensure this column exists
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        user = db.relationship('User', backref=db.backref('contents', lazy=True))

        def __repr__(self):
            return f'<Content {self.title}>'

    # Category model
    class Category(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(50), unique=True, nullable=False)
        description = db.Column(db.String(200))  

        def __repr__(self):
            return f'<Category {self.name}>'

    # Load user for login_manager
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Routes (same as before)

    # Home route (redirect to register if not logged in, or show approved content)
    @app.route('/')
    def index():
        if not current_user.is_authenticated:
            return redirect(url_for('register'))  # Redirect to register page if not logged in
        contents = Content.query.filter_by(is_approved=True, is_flagged=False).all()
        return render_template('index.html', contents=contents)

    # Register route
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form.get('role', 'user')  # Default role is 'user'
            if role not in ['admin', 'tech_writer', 'user']:
                flash('Invalid role selected!', 'danger')
                return redirect(url_for('register'))
            
            # Check if the email or username already exists
            existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
            if existing_user:
                flash('Username or email already exists!', 'danger')
                return redirect(url_for('register'))
            
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html')

    # Login route
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):  # Check if the hashed password matches
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid login credentials', 'danger')  # If password doesn't match
        return render_template('login.html')

    # Admin routes and views (same as before)
    
    # Flask-Admin View for Users and Content models
    class AdminModelView(ModelView):
        def is_accessible(self):
            return current_user.is_authenticated and current_user.role == 'admin'

        form_overrides = {
            'role': SelectField  # This is where the role field is a select field (e.g., admin, tech_writer, user)
        }

        form_widget_args = {
            'role': {
                'widget': Select2Widget()
            }
        }

    class CategoryAdminView(ModelView):
        column_searchable_list = ['name']  # Only use existing fields
        column_filters = ['name', 'description']  # Add any filters if needed

    # Add views for models in Flask Admin
    admin.add_view(AdminModelView(User, db.session))
    admin.add_view(AdminModelView(Content, db.session))
    admin.add_view(CategoryAdminView(Category, db.session))

    return app

# Set up logging for production
def setup_logging():
    logging.basicConfig(level=logging.INFO)
    # In production, you may want to log to a file instead of console
    if os.environ.get('FLASK_ENV') == 'production':
        file_handler = logging.FileHandler('app.log')
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

def setup_database(app):
    """Create the database tables if they don't exist."""
    with app.app_context():
        db.create_all()

def run_app(app):
    """Run the Flask application with Gunicorn in production."""
    # For production, it's best to use a WSGI server like gunicorn.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)  # Set debug to False for production

if __name__ == '__main__':
    app = create_app()
    setup_logging()  # Set up logging configuration
    setup_database(app)  # Initialize database
    run_app(app)  # Start the app

