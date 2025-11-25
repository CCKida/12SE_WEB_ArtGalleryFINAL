from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
import os
from PIL import Image
import secrets
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///artgallery.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)  # Add a secret key for CSRF

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Form Classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class EditProfileForm(FlaskForm):
    display_name = StringField('Display Name', validators=[Length(max=100)])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    profile_image = FileField('Profile Picture')
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', 
                                   validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ArtworkForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    image = FileField('Artwork Image', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('painting', 'Painting'),
        ('drawing', 'Drawing'),
        ('digital', 'Digital Art'),
        ('photography', 'Photography'),
        ('sculpture', 'Sculpture'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    tags = StringField('Tags (comma-separated)')
    submit = SubmitField('Upload Artwork')

# Ensure upload folder exists
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    display_name = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    profile_image = db.Column(db.String(120), default='default.jpg')
    artworks = db.relationship('Artwork', backref='artist', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(120), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.String(200))
    likes = db.relationship('Like', backref='artwork', lazy=True, cascade='all, delete-orphan')

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artwork.id'), nullable=False)
    date_liked = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/uploads', picture_fn)
    
    # Resize image
    output_size = (1200, 1200)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

# Routes
@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)
    artworks = Artwork.query.order_by(Artwork.date_posted.desc()).paginate(page=page, per_page=6)
    return render_template('home.html', artworks=artworks)

@app.route('/artwork/<int:artwork_id>')
def artwork(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    is_liked = False
    if current_user.is_authenticated:
        is_liked = Like.query.filter_by(user_id=current_user.id, artwork_id=artwork.id).first() is not None
    return render_template('artwork.html', artwork=artwork, is_liked=is_liked)

def save_artwork_image(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/uploads/artworks', picture_fn)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(picture_path), exist_ok=True)
    
    # Resize image
    output_size = (1200, 1200)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    
    # Save the image
    i.save(picture_path)
    
    return picture_fn

@app.route('/artwork/new', methods=['GET', 'POST'])
@login_required
def new_artwork():
    form = ArtworkForm()
    if form.validate_on_submit():
        if form.image.data:
            try:
                image_file = save_artwork_image(form.image.data)
                artwork = Artwork(
                    title=form.title.data,
                    description=form.description.data or '',
                    image_file=image_file,
                    category=form.category.data,
                    tags=form.tags.data,
                    user_id=current_user.id
                )
                db.session.add(artwork)
                db.session.commit()
                flash('Your artwork has been created!', 'success')
                return redirect(url_for('artwork', artwork_id=artwork.id))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while uploading your artwork. Please try again.', 'danger')
                app.logger.error(f'Error creating artwork: {str(e)}')
    
    return render_template('create_artwork.html', title='Upload Artwork', form=form)

@app.route('/artwork/<int:artwork_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_artwork(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    if artwork.artist != current_user:
        flash('You are not authorized to edit this artwork.', 'danger')
        return redirect(url_for('artwork', artwork_id=artwork.id))
        
    if request.method == 'POST':
        artwork.title = request.form.get('title')
        artwork.description = request.form.get('description')
        artwork.category = request.form.get('category')
        artwork.tags = request.form.get('tags', '')
        
        if 'image' in request.files and request.files['image'].filename:
            # Delete old image
            old_image = os.path.join(app.root_path, 'static/uploads', artwork.image_file)
            if os.path.exists(old_image) and artwork.image_file != 'default.jpg':
                os.remove(old_image)
            # Save new image
            image_file = request.files['image']
            artwork.image_file = save_picture(image_file)
            
        db.session.commit()
        flash('Artwork updated successfully!', 'success')
        return redirect(url_for('artwork', artwork_id=artwork.id))
        
    return render_template('edit_artwork.html', artwork=artwork)

@app.route('/artwork/<int:artwork_id>/delete', methods=['POST'])
@login_required
def delete_artwork(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    if artwork.artist != current_user:
        flash('You are not authorized to delete this artwork.', 'danger')
        return redirect(url_for('artwork', artwork_id=artwork.id))
        
    # Delete image file
    image_path = os.path.join(app.root_path, 'static/uploads', artwork.image_file)
    if os.path.exists(image_path) and artwork.image_file != 'default.jpg':
        os.remove(image_path)
        
    db.session.delete(artwork)
    db.session.commit()
    flash('Artwork deleted successfully!', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/like/<int:artwork_id>', methods=['POST'])
@login_required
def like_artwork(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    like = Like.query.filter_by(user_id=current_user.id, artwork_id=artwork.id).first()
    
    if like:
        db.session.delete(like)
        db.session.commit()
        return jsonify({'liked': False, 'count': len(artwork.likes) - 1})
    else:
        like = Like(user_id=current_user.id, artwork_id=artwork.id)
        db.session.add(like)
        db.session.commit()
        return jsonify({'liked': True, 'count': len(artwork.likes) + 1})

@app.route('/user/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    artworks = Artwork.query.filter_by(user_id=user.id).order_by(Artwork.date_posted.desc()).paginate(page=page, per_page=12)
    return render_template('profile.html', user=user, artworks=artworks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            display_name=form.username.data,
            profile_image='default.jpg'
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
            
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.display_name = request.form.get('display_name', current_user.username)
        current_user.bio = request.form.get('bio', '')
        
        if 'profile_image' in request.files and request.files['profile_image'].filename:
            # Delete old image if it's not the default
            if current_user.profile_image != 'default.jpg':
                old_image = os.path.join(app.root_path, 'static/uploads', current_user.profile_image)
                if os.path.exists(old_image):
                    os.remove(old_image)
            # Save new image
            image_file = request.files['profile_image']
            current_user.profile_image = save_picture(image_file)
            
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile', username=current_user.username))
        
    return render_template('edit_profile.html')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    page = request.args.get('page', 1, type=int)
    
    artworks = Artwork.query
    
    if query:
        search = f"%{query}%"
        artworks = artworks.filter(
            (Artwork.title.ilike(search)) | 
            (Artwork.description.ilike(search)) |
            (Artwork.tags.ilike(search))
        )
        
    if category:
        artworks = artworks.filter_by(category=category)
        
    artworks = artworks.order_by(Artwork.date_posted.desc()).paginate(page=page, per_page=12)
    
    return render_template('search.html', artworks=artworks, query=query, category=category)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('edit_profile'))
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('edit_profile'))
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return redirect(url_for('edit_profile'))
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('edit_profile'))
    
    return redirect(url_for('edit_profile'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
