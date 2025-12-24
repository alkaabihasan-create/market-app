import os
import re  # <--- THIS WAS MISSING
import secrets # Used for the forgot password token
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, cast, Integer
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

def is_strong_password(password):
    # Rule: 8 chars, 1 uppercase, 1 lowercase, 1 number
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[0-9]", password): return False
    return True

app = Flask(__name__)

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'thisisasecretkey' # Needed for secure login sessions
# --- SMART DATABASE CONNECTION ---

# 1. Try to get the database URL from the Render server
database_url = os.environ.get('DATABASE_URL')

# 2. Fix for Render: They give "postgres://" but Python needs "postgresql://"
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# 3. If on Render, use the Cloud DB. If on Laptop, use 'elanat.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///elanat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Go here if user tries to do something allowed only for members

# --- DATABASE MODELS ---

# 1. The User Table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    
    # --- NEW: Phone Number ---
    phone = db.Column(db.String(20), nullable=False) 
    
    password = db.Column(db.String(80), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    items = db.relationship('Item', backref='owner', lazy=True)

# 2. The Item Table (Updated to link to a User)
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    # Link to the User table
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# This helps Flask find the user by ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def home():
    # 1. Get the search term from the URL (e.g., /?q=Toyota)
    query = request.args.get('q')

    if query:
        # 2. If user searched, filter items (Case Insensitive)
        # We look in the Name OR the Description
        search_term = f"%{query}%"
        items = Item.query.filter(
            (Item.name.ilike(search_term)) | 
            (Item.description.ilike(search_term))
        ).all()
    else:
        # 3. No search? Show everything
        items = Item.query.all()

    return render_template('home.html', items=items)

@app.route('/item/<int:id>')
def item_detail(id):
    item = Item.query.get_or_404(id)
    return render_template('detail.html', item=item)

@app.route('/sell', methods=['GET', 'POST'])
@login_required # <--- NEW: Only logged in users can see this page!
def sell_item():
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        category = request.form.get('category')
        description = request.form['description']
        
        image_url = "https://via.placeholder.com/300"
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = f"/static/uploads/{filename}"

        # Assign the 'owner' to the current logged-in user
        new_item = Item(name=name, price=price, category=category, description=description, image=image_url, owner=current_user)
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('sell.html')

# --- AUTHENTICATION ROUTES ---

# --- AUTH ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        # --- VALIDATION CHECKS ---
        
        # 1. Check Username Format (Letters, Numbers, Underscore, Dot ONLY)
        if not re.match(r'^[a-zA-Z0-9_.]+$', username):
            flash('Username can only contain letters, numbers, underscores, and dots.', 'error')
            return render_template('register.html')

        # 2. Check Username Length
        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters.', 'error')
            return render_template('register.html')

        # 3. Check if Username is already taken
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists. Please choose another.', 'error')
            return render_template('register.html')

        # 4. Check if Email is already taken
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash('Email already registered. Please login.', 'error')
            return redirect(url_for('login'))

        # --- CREATE ACCOUNT ---
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, phone=phone, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please login.', 'success')
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
            flash('Login Failed. Check your email and password.', 'error')
            
    return render_template('login.html')
# --- FORGOT PASSWORD FLOW ---

import secrets # To generate random tokens

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a secure token
            token = secrets.token_hex(16)
            user.reset_token = token
            user.token_expiry = datetime.now() + timedelta(hours=1) # Valid for 1 hour
            db.session.commit()
            
            # IN REAL LIFE: You would send an email here.
            # FOR LOCAL DEV: We will print the link to the VS Code Terminal.
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"\n --- SIMULATED EMAIL --- \n Reset Link: {reset_link} \n -----------------------\n")
            
            flash('Reset link sent! Check your email (or terminal).', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')

    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    # Check if token exists and is not expired
    if not user or user.token_expiry < datetime.now():
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form['password']
        
        if not is_strong_password(new_password):
            flash('Password too weak! Needs 8+ chars, uppercase, lowercase, & number.', 'error')
            return redirect(request.url) # Reload same page
            
        # Update Password & Clear Token
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_token = None
        user.token_expiry = None
        db.session.commit()
        
        flash('Password reset! You can now login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')


# --- DELETE ITEM ---
@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    # 1. Find the item
    item = Item.query.get_or_404(id)

    # 2. SECURITY: Check if the current user actually owns this item
    # (We don't want User A deleting User B's items!)
    if item.owner_id != current_user.id:
        flash("You do not have permission to delete this item.", "error")
        return redirect(url_for('dashboard'))

    # 3. Delete it
    db.session.delete(item)
    db.session.commit()
    
    flash("Item deleted successfully.", "success")
    return redirect(url_for('dashboard'))


# --- ADMIN DASHBOARD ---
@app.route('/admin')
@login_required
def admin():
    # 1. This is the fix: We put YOUR actual email here
    admin_email = 'alkaabihasan@gmail.com' 
    
    # 2. Security Check (Case Insensitive)
    if current_user.email.lower() != admin_email.lower():
        # If someone else tries to enter, kick them out silently
        flash("Access denied. Admin only.", "error")
        return redirect(url_for('home'))

    # 3. Calculate Stats
    total_users = User.query.count()
    total_items = Item.query.count()
    # Calculate sum (Convert "String" Price to "Integer" first)
    total_value = db.session.query(func.sum(cast(Item.price, Integer))).scalar() or 0

    return render_template('admin.html', 
                         users=total_users, 
                         items=total_items, 
                         value=total_value)


# Create DB if not exists
with app.app_context():
    db.create_all()


# --- DASHBOARD & DELETE ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard():
    # Get items owned by current user
    user_items = Item.query.filter_by(owner_id=current_user.id).all()
    return render_template('dashboard.html', items=user_items)




if __name__ == '__main__':
    app.run(debug=True)