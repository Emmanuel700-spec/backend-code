from app import app, db, User, Category, Content
from werkzeug.security import generate_password_hash

# Create sample categories
def create_categories():
    categories = ['Technology', 'Science', 'Health', 'Business', 'Education']
    for category_name in categories:
        # Check if the category already exists to avoid duplicates
        if not Category.query.filter_by(name=category_name).first():
            category = Category(name=category_name)
            db.session.add(category)
    db.session.commit()
    print("Categories seeded.")

# Create sample users
def create_users():
    users = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin123',
            'role': 'admin'
        },
        {
            'username': 'tech_writer1',
            'email': 'techwriter1@example.com',
            'password': 'password123',
            'role': 'tech_writer'
        },
        {
            'username': 'user1',
            'email': 'user1@example.com',
            'password': 'user123',
            'role': 'user'
        }
    ]
    
    for user_data in users:
        # Check if user already exists
        if not User.query.filter_by(email=user_data['email']).first():
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password=generate_password_hash(user_data['password']),
                role=user_data['role']
            )
            db.session.add(user)
    db.session.commit()
    print("Users seeded.")

# Create sample content
def create_content():
    tech_writer = User.query.filter_by(username='tech_writer1').first()
    categories = Category.query.all()

    contents = [
        {
            'title': 'The Future of AI',
            'body': 'Artificial Intelligence is rapidly evolving...',
            'category': categories[0],
            'user': tech_writer
        },
        {
            'title': 'How to Stay Healthy',
            'body': 'Maintaining good health involves...',
            'category': categories[2],
            'user': tech_writer
        }
    ]
    
    for content_data in contents:
        # Check if the content already exists to avoid duplicates
        if not Content.query.filter_by(title=content_data['title']).first():
            content = Content(
                title=content_data['title'],
                body=content_data['body'],
                category=content_data['category'].name,
                user=content_data['user']
            )
            db.session.add(content)
    db.session.commit()
    print("Content seeded.")

if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
        
        # Seed the database
        create_categories()
        create_users()
        create_content()

    print("Database seeding complete.")
