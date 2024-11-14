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

# Set the PostgreSQL URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://moringa:Group5@localhost:5432/moringa_database'
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

# Admin Dashboard route
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    contents = Content.query.all()
    users = User.query.all()
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

# Admin settings page
@app.route('/admin/settings')
def admin_settings():
    return render_template('admin/settings.html')

@app.route('/admin/settings/add_user', methods=['POST'])
def add_user():
    username = request.form.get('username')
    user_type = request.form.get('user_type')

    # Ensure the model accepts the keyword arguments
    new_user = User(username=username, user_type=user_type)
    db.session.add(new_user)
    db.session.commit()

    return redirect('/admin/settings')  # Or wherever you want to redirect after adding the user


# Flag content as inappropriate
@app.route('/admin/settings/flag_content', methods=['POST'])
def flag_content():
    content_id = request.form['content_id']
    content = Content.query.get(content_id)
    if content:
        content.flagged = True
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
        content.approved = True
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
    
    users = User.query.all()
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
        content_title = request.form['title']
        content_body = request.form['body']
        new_content = Content(title=content_title, body=content_body, category='default', user_id=current_user.id)
        db.session.add(new_content)
        db.session.commit()
        flash('Content created successfully!', 'success')
        return redirect(f'{redirect_url}?sort=3')  # Redirect back with sorting query param
    
    return render_template('admin/new_content.html', redirect_url=redirect_url)


@app.route('/logout')
def logout():
    # Clear the user session or any authentication data
    session.pop('user_id', None)  # Assuming you're storing the user ID in the session
    session.pop('user_type', None)  # Remove other session data as needed

    return redirect(url_for('login'))  # Redirect to login page or home page

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

if __name__ == "__main__":
    app.run(debug=True, port=5001)

