import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from wtforms import SelectField
from flask_admin.form.widgets import Select2Widget

# Initialize Flask application
app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://moringa:Group5@localhost:5432/moringa_database')


# Initialize SQLAlchemy, LoginManager, Flask-Admin, and Migrate
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Default login view
migrate = Migrate(app, db)

# Initialize Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

# Users model
class Users(UserMixin, db.Model):
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', backref=db.backref('contents', lazy=True))

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
    return Users.query.get(int(user_id))

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
        existing_user = Users.query.filter((Users.email == email) | (Users.username == username)).first()
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = Users(username=username, email=email, password=hashed_password, role=role)
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
        user = Users.query.filter_by(email=email).first()
        
        if user and user.check_password(password):  # Check if the hashed password matches
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid login credentials', 'danger')  # If password doesn't match
    return render_template('login.html')

# Admin Dashboard route
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    contents = Content.query.all()
    users = Users.query.all()
    return render_template('admin/dashboard.html', contents=contents, users=users)

# Admin Category Management
@app.route('/admin/categories')
@login_required
def categories():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))

    categories = Category.query.all()  # Retrieve all categories from the database
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/categories/create', methods=['POST'])
@login_required
def create_category():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))

    name = request.form.get('name')
    description = request.form.get('description')

    if name and description:
        try:
            new_category = Category(name=name, description=description)
            db.session.add(new_category)
            db.session.commit()
            flash('Category created successfully!', 'success')
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('categories'))
    else:
        flash('All fields are required!', 'danger')
    return redirect(url_for('categories'))


@app.route('/admin/settings')
@login_required
def admin_settings():
    # Add code to render the settings page with relevant data, if needed
    return render_template('admin/settings.html')

# Flag content as inappropriate
@app.route('/admin/settings/flag_content', methods=['POST'])
def flag_content():
    content_id = request.form['content_id']
    content = Content.query.get(content_id)
    if content:
        content.is_flagged = True  # Corrected column name
        db.session.commit()
        flash(f'Content ID {content_id} flagged successfully.')
    else:
        flash('Content not found.')
    return redirect(url_for('admin/settings'))

# Approve content for publishing
@app.route('/admin/settings/approve_content', methods=['POST'])
def approve_content():
    content_id = request.form['content_id']
    content = Content.query.get(content_id)
    if content:
        content.is_approved = True  # Corrected column name
        db.session.commit()
        flash(f'Content ID {content_id} approved successfully.')
    else:
        flash('Content not found.')
    return redirect(url_for('admin/settings'))

# Add a new content category
@app.route('/admin/settings/add_category', methods=['POST'])
def add_category():
    category_name = request.form['category_name']
    new_category = Category(name=category_name)
    db.session.add(new_category)
    db.session.commit()
    flash(f'Category {category_name} added successfully.')
    return redirect(url_for('admin/settings'))

@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    users = Users.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/reports')
def reports():
    return render_template('admin/reports.html')

@app.route('/admin/content/new', methods=['GET', 'POST'])
@login_required
def new_content():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))

    redirect_url = request.args.get('url', '/admin/content/')  # Default to '/admin/content/' if not provided
    if request.method == 'POST':
        content_title = request.form['content_title']
        content_body = request.form['content_body']
        category = request.form['category']

        new_content = Content(title=content_title, body=content_body, category=category, user_id=current_user.id)
        db.session.add(new_content)
        db.session.commit()
        flash(f'Content "{content_title}" added successfully.')
        return redirect(redirect_url)

    return render_template('admin/new_content.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

