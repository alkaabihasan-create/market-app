import os
import re
import secrets
from flask_mail import Mail, Message  # <--- NEW IMPORT
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import uuid # Needed for unique filenames

# Flask & Extensions
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, cast, Integer
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# --- EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'alkaabihasan@gmail.com'  # <--- PUT YOUR REAL GMAIL HERE
app.config['MAIL_PASSWORD'] = 'nlbk hvzs syqj whhf'   # <--- PUT YOUR 16-CHAR APP PASSWORD HERE
mail = Mail(app)
# --- CONFIGURATION ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SECRET_KEY'] = 'thisisasecretkey' 

# --- SMART DATABASE CONNECTION ---
database_url = os.environ.get('DATABASE_URL')

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///elanat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# --- HELPER FUNCTIONS ---
def is_strong_password(password):
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[0-9]", password): return False
    return True

# --- DATABASE MODELS ---

# ASSOCIATION TABLE FOR FAVORITES
user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('item_id', db.Integer, db.ForeignKey('item.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    phone = db.Column(db.String(20), nullable=False) 
    password = db.Column(db.String(80), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=False)
    
    # MAIN IMAGE (Kept for Home Page/Dashboard compatibility)
    image = db.Column(db.String(100), nullable=False)
    
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('items', lazy=True))
    
    # RELATIONSHIP TO NEW IMAGE TABLE
    # This allows us to say item.gallery to get all images
    gallery = db.relationship('ItemImage', backref='item', lazy=True, cascade="all, delete-orphan")

# NEW TABLE: STORES MULTIPLE IMAGES PER ITEM
class ItemImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_file = db.Column(db.String(100), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

# --- FAVORITES ROUTES ---

@app.route('/favorite/<int:item_id>')
@login_required
def toggle_favorite(item_id):
    item = Item.query.get_or_404(item_id)
    if item in current_user.favorites:
        current_user.favorites.remove(item)
        flash('Removed from wishlist.', 'info')
    else:
        current_user.favorites.append(item)
        flash('Added to wishlist!', 'success')
    db.session.commit()
    # Redirect back to the page they came from
    return redirect(request.referrer or url_for('home'))

@app.route('/wishlist')
@login_required
def wishlist():
    items = current_user.favorites.all()
    return render_template('wishlist.html', items=items)

@app.route('/')
def home():
    query = request.args.get('q')
    if query:
        search_term = f"%{query}%"
        items = Item.query.filter(
            (Item.name.ilike(search_term)) | 
            (Item.description.ilike(search_term))
        ).all()
    else:
        items = Item.query.all()
    return render_template('home.html', items=items)

@app.route('/item/<int:id>')
def item_detail(id):
    item = Item.query.get_or_404(id)
    return render_template('detail.html', item=item)

@app.route('/sell', methods=['GET', 'POST'])
@login_required
def sell():
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        category = request.form['category']
        description = request.form['description']
        condition = request.form['condition']
        tags = request.form['tags']
        
        # MULTI-FILE UPLOAD HANDLING
        # We look for a list of files named 'images' (we will update HTML next)
        images = request.files.getlist('images')

        if images:
            # 1. Create the Item first (we need its ID)
            # We use the FIRST image as the "Main Image" for thumbnails
            first_image_filename = ""
            saved_filenames = []

            for index, img in enumerate(images):
                if img.filename == '': continue # Skip empty
                
                filename = secure_filename(img.filename)
                unique_filename = str(uuid.uuid4()) + "_" + filename
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                
                # Path for DB
                db_path = 'static/uploads/' + unique_filename
                saved_filenames.append(db_path)

                # Capture the first one for the main 'image' column
                if index == 0:
                    first_image_filename = db_path

            # Create Item
            new_item = Item(
                name=name, price=price, category=category, 
                condition=condition, tags=tags, description=description, 
                image=first_image_filename, # Main Thumbnail
                owner=current_user
            )
            db.session.add(new_item)
            db.session.commit() # Commit to generate item.id

            # 2. Now save all images to the Gallery table
            for filepath in saved_filenames:
                gallery_img = ItemImage(image_file=filepath, item_id=new_item.id)
                db.session.add(gallery_img)
            
            db.session.commit()

            flash('Item listed successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('sell.html')

# --- AUTH ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        if not re.match(r'^[a-zA-Z0-9_.]+$', username):
            flash('Username format invalid.', 'error')
            return render_template('register.html')
        if len(username) < 3 or len(username) > 20:
            flash('Username length invalid.', 'error')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username taken.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email registered.', 'error')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, phone=phone, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Failed.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- FORGOT PASSWORD ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate Token
            token = secrets.token_hex(16)
            user.reset_token = token
            user.token_expiry = datetime.now() + timedelta(hours=1)
            db.session.commit()
            
            # Create Link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # SEND REAL EMAIL
            try:
                msg = Message('Password Reset Request', 
                              sender='your_email@gmail.com',  # <--- MATCH YOUR CONFIG EMAIL
                              recipients=[user.email])
                
                msg.body = f'''To reset your password, visit the following link:
{reset_link}

If you did not make this request, simply ignore this email.
'''
                mail.send(msg)
                flash('Email sent! Please check your inbox.', 'success')
                
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('There was an issue sending the email. Try again later.', 'error')
                
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')
            
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.token_expiry < datetime.now():
        flash('Invalid/Expired token.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form['password']
        if not is_strong_password(new_password):
            flash('Password weak.', 'error')
            return redirect(request.url)
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_token = None
        user.token_expiry = None
        db.session.commit()
        flash('Password reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# --- DELETE & DASHBOARD ---
@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    item = Item.query.get_or_404(id)
    if item.owner_id != current_user.id:
        flash("Permission denied.", "error")
        return redirect(url_for('dashboard'))
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted.", "success")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_items = Item.query.filter_by(owner_id=current_user.id).all()
    return render_template('dashboard.html', items=user_items)

# --- ADMIN ---
@app.route('/admin')
@login_required
def admin():
    admin_email = 'alkaabihasan@gmail.com' 
    if current_user.email.lower() != admin_email.lower():
        flash("Access denied.", "error")
        return redirect(url_for('home'))
    total_users = User.query.count()
    total_items = Item.query.count()
    total_value = db.session.query(func.sum(cast(Item.price, Integer))).scalar() or 0
    return render_template('admin.html', users=total_users, items=total_items, value=total_value)

# --- API ---
@app.route('/api/search')
def search_api():
    query = request.args.get('q', '')
    db_query = Item.query
    if query:
        search_term = f"%{query}%"
        db_query = db_query.filter(
            (Item.name.ilike(search_term)) | 
            (Item.description.ilike(search_term)) |
            (Item.tags.ilike(search_term))
        )
    items = db_query.all()
    results = []
    for item in items:
        results.append({
            'id': item.id,
            'name': item.name,
            'price': item.price,
            'image': item.image,
            'category': item.category,
            'condition': item.condition
        })
    return jsonify(results)

# --- CREATE DB ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)