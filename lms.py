import os
import pathlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message 
from dotenv import load_dotenv 

# --- Load Environment Variables for Email Config ---
load_dotenv()

BASE_DIR = pathlib.Path(__file__).parent.resolve()
UPLOAD_ROOT = BASE_DIR / 'uploads'
PROFILE_PICS_DIR = BASE_DIR / 'static' / 'profiles'
TEMPLATES_DIR = BASE_DIR / 'templates'
DB_PATH = BASE_DIR / 'lms.db'

SECRET_KEY = os.environ.get('LMS_SECRET_KEY', 'dev-secret-key')
ALLOWED_EXTENSIONS = {'mp4', 'mkv', 'webm', 'wav', 'mp3', 'ogg', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', 'txt', 'csv', 'json', 'py', 'ipynb', 'html', 'css', 'js'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5 GB

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT', 587)
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)
db = SQLAlchemy(app)

# ---------------- Models ----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_pic = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    about = db.Column(db.Text, nullable=True)
    enrollments = db.relationship('Enrollment', backref='user', cascade='all, delete-orphan')
    progress = db.relationship('StudentProgress', backref='student', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Trainer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    expertise = db.Column(db.String(200), nullable=True)
    profile_pic = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    about = db.Column(db.Text, nullable=True)
    batches = db.relationship('Batch', backref='trainer', lazy=True)

class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'), nullable=True)
    recordings = db.relationship('Recording', backref='batch', cascade='all, delete-orphan')
    enrollments = db.relationship('Enrollment', backref='batch', cascade='all, delete-orphan')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)

class Recording(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    original_name = db.Column(db.String(500), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'))
    notes = db.Column(db.Text, nullable=True)
    progress = db.relationship('StudentProgress', backref='recording', lazy=True)

class StudentProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    recording_id = db.Column(db.Integer, db.ForeignKey('recording.id'), index=True)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)

class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open') # Open, In Progress, Closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='queries', lazy=True)
    batch = db.relationship('Batch', backref='queries', lazy=True)

class OTP_Token(db.Model): # NEW MODEL FOR OTP
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    
# ---------------- Helpers ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_and_send_otp(user_id, email):
    # Generates a 6-char hex token and sets expiry (e.g., 10 minutes)
    token = secrets.token_hex(3).upper() 
    expires = datetime.utcnow() + timedelta(minutes=10)
    
    # Clear old tokens for this user
    OTP_Token.query.filter_by(user_id=user_id).delete()
    
    otp_entry = OTP_Token(user_id=user_id, token=token, expires_at=expires)
    db.session.add(otp_entry)
    db.session.commit()
    
    # --- ACTUAL EMAIL SENDING LOGIC ---
    try:
        msg = Message("LMS Password Reset Code", recipients=[email])
        msg.body = f"Your One-Time Password for password reset is: {token}. It is valid for 10 minutes."
        mail.send(msg)
        flash(f"A recovery code has been sent to {email}. (Valid for 10 minutes).", 'warning')
        return token
    except Exception as e:
        # If email fails, still proceed but alert the developer/user (Optional)
        print(f"EMAIL SENDING FAILED: {e}") 
        flash("Email sending failed. Please check your MAIL_USERNAME/PASSWORD or try again later.", 'danger')
        flash(f"FOR DEV TESTING: Your OTP is {token}", 'info')
        return None 

# ---------------- Context helpers ----------------
@app.context_processor
def inject_helpers():
    def current_user():
        uid = session.get('user_id')
        if not uid:
            return None
        return User.query.get(uid)
    
    def is_admin():
        u = current_user()
        return u and u.role == 'admin'
    
    def is_trainer():
        u = current_user()
        return u and u.role == 'trainer'

    return dict(current_user=current_user, is_admin=is_admin, is_trainer=is_trainer)

# ---------------- Routes ----------------

@app.route('/')
def index():
    batches = Batch.query.order_by(Batch.created_at.desc()).all()
    return render_template('index.html', batches=batches)

@app.route('/register', methods=['GET','POST'])
def register():
    admin_exists = User.query.filter_by(role='admin').first() is not None
    
    if request.method=='POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role','student')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered','danger')
            return redirect(url_for('register'))
        
        if role == 'admin' and admin_exists:
            flash('An admin already exists. Cannot create another admin.','danger')
            return redirect(url_for('register'))

        u = User(name=name,email=email,role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Account created. Please login.','success')
        return redirect(url_for('login'))

    return render_template('register.html', admin_exists=admin_exists)


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(password):
            flash('Invalid credentials','danger')
            return redirect(url_for('login'))
        session['user_id'] = u.id
        flash('Logged in','success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash("If an account exists, a recovery email has been sent.", 'info')
            return redirect(url_for('login'))
            
        # Generate and send OTP 
        generate_and_send_otp(user.id, user.email)
        
        session['reset_email'] = email 
        
        return redirect(url_for('reset_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    
    if not email:
        flash("Please start the password recovery process first.", 'danger')
        return redirect(url_for('forgot_password'))
        
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", 'danger')
        session.pop('reset_email', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token'].upper()
        new_password = request.form['new_password']
        
        # 1. Verify Token and Expiry
        otp_entry = OTP_Token.query.filter_by(user_id=user.id, token=token).first()
        
        if not otp_entry or otp_entry.expires_at < datetime.utcnow():
            flash("Invalid or expired recovery code.", 'danger')
            return redirect(url_for('reset_password'))
            
        if len(new_password) < 6:
            flash("New password must be at least 6 characters long.", 'danger')
            return redirect(url_for('reset_password'))

        # 2. Update Password and Clear Token
        user.set_password(new_password)
        db.session.delete(otp_entry)
        db.session.commit()
        
        session.pop('reset_email', None)
        flash("Password successfully reset. You can now log in.", 'success')
        
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)


@app.route('/logout')
def logout():
    session.pop('user_id',None)
    flash('Logged out','info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    uid = session.get('user_id')
    if not uid:
        flash('Login first', 'danger')
        return redirect(url_for('login'))
    
    u = User.query.get(uid)
    
    if u.role == 'admin':
        students = User.query.filter(User.role == 'student').all()
        batches = Batch.query.all()
        trainers = Trainer.query.all()
        
        # --- ADMIN METRICS ---
        unassigned_batches = Batch.query.filter(Batch.trainer_id == None).all()
        one_week_ago = datetime.utcnow() - timedelta(days=7)
        new_students_count = User.query.filter(User.role == 'student', User.created_at >= one_week_ago).count()
        pending_queries_count = Query.query.filter_by(status='Open').count() 
        
        return render_template('admin_metrics.html', 
                               students=students, 
                               batches=batches, 
                               trainers=trainers,
                               unassigned_batches=unassigned_batches,
                               new_students_count=new_students_count,
                               pending_queries_count=pending_queries_count) 
    
    elif u.role == 'trainer':
        trainer = Trainer.query.filter_by(email=u.email).first()
        # FIX 2: Check if trainer object exists (stability fix)
        if not trainer:
            flash('Trainer profile link broken. Please contact admin.', 'danger')
            return redirect(url_for('logout'))
            
        batches = Batch.query.filter_by(trainer_id=trainer.id).all()
        assigned_batch_ids = [b.id for b in batches] 
        
        trainer_queries = Query.query.filter(Query.batch_id.in_(assigned_batch_ids), Query.status=='Open').order_by(Query.created_at.asc()).all() 
        total_recordings_assigned = sum(len(b.recordings) for b in batches)
        
        return render_template('trainer_dashboard.html', 
                               trainer=trainer, 
                               batches=batches,
                               total_recordings_assigned=total_recordings_assigned,
                               trainer_queries=trainer_queries) 
        
    else: # Student
        enrollments = Enrollment.query.filter_by(user_id=u.id).all()
        
        # Student Metrics: Calculate overall progress and next lesson
        total_available = 0
        total_completed = 0
        next_lesson = None
        
        for e in enrollments:
            all_recordings = e.batch.recordings
            total_recordings = len(all_recordings)
            
            completed_recordings = StudentProgress.query.filter_by(user_id=u.id, completed=True).join(Recording).filter(Recording.batch_id == e.batch.id).count()
            
            e.progress_count = f"{completed_recordings}/{total_recordings}"
            total_available += total_recordings
            total_completed += completed_recordings

            # Determine Next Lesson (find the first uncompleted recording)
            if next_lesson is None:
                for rec in all_recordings:
                    progress = StudentProgress.query.filter_by(user_id=u.id, recording_id=rec.id, completed=True).first()
                    if not progress:
                        next_lesson = {'batch_name': e.batch.name, 'recording_name': rec.original_name, 'recording_id': rec.id, 'batch_id': e.batch.id}
                        break
                
        overall_progress_percent = (total_completed / total_available * 100) if total_available > 0 else 0
        
        return render_template('student_dashboard.html', 
                               enrollments=enrollments,
                               overall_progress_percent=round(overall_progress_percent),
                               next_lesson=next_lesson)

@app.route('/admin_dashboard')
def admin_dashboard():
    if not inject_helpers()['is_admin']():
        abort(403)
    students = User.query.filter(User.role == 'student').all()
    batches = Batch.query.all()
    trainers = Trainer.query.all()
    # Renders the full management page with all forms and lists
    return render_template('admin_dashboard.html', students=students, batches=batches, trainers=trainers)

@app.route('/view_all_batches')
def view_all_batches():
    if not inject_helpers()['is_admin']():
        abort(403)
    batches = Batch.query.all()
    return render_template('view_all_batches.html', batches=batches)

@app.route('/view_all_students')
def view_all_students():
    if not inject_helpers()['is_admin']():
        abort(403)
    students = User.query.filter(User.role == 'student').all()
    return render_template('view_all_students.html', students=students)

@app.route('/view_all_trainers')
def view_all_trainers():
    if not inject_helpers()['is_admin']():
        abort(403)
    trainers = Trainer.query.all()
    return render_template('view_all_trainers.html', trainers=trainers)

@app.route('/create_batch', methods=['POST'])
def create_batch():
    if not inject_helpers()['is_admin']():
        abort(403)
    name = request.form['name']
    desc = request.form.get('description')
    if Batch.query.filter_by(name=name).first():
        flash('Batch with this name already exists','danger')
    else:
        b = Batch(name=name, description=desc)
        db.session.add(b)
        db.session.commit()
        flash('Batch created successfully','success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_batch/<int:batch_id>')
def delete_batch(batch_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    b = Batch.query.get_or_404(batch_id)
    folder = UPLOAD_ROOT / str(b.id)
    if folder.exists():
        for f in folder.iterdir(): os.remove(f)
        os.rmdir(folder)
    db.session.delete(b)
    db.session.commit()
    flash('Batch deleted','info')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_batch/<int:batch_id>', methods=['GET', 'POST'])
def edit_batch(batch_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    
    batch = Batch.query.get_or_404(batch_id)

    if request.method == 'POST':
        new_name = request.form['name']
        new_desc = request.form.get('description', '')
        
        existing = Batch.query.filter(Batch.name == new_name, Batch.id != batch.id).first()
        if existing:
            flash('Another batch with this name already exists', 'danger')
            return redirect(url_for('admin_dashboard'))

        batch.name = new_name
        batch.description = new_desc
        db.session.commit()
        flash('Batch updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_batch.html', batch=batch)

@app.route('/enroll_student', methods=['POST'])
def enroll_student():
    if not inject_helpers()['is_admin']():
        abort(403)
    
    user_id_str = request.form.get('user_id')
    batch_id_str = request.form.get('batch_id')
    
    # 1. Input Validation
    if not user_id_str or not batch_id_str:
        flash('Please select both a student and a batch.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        user_id = int(user_id_str)
        batch_id = int(batch_id_str)
    except ValueError:
        flash('Invalid selection data.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 2. Enrollment Logic
    if Enrollment.query.filter_by(user_id=user_id, batch_id=batch_id).first():
        flash('Student already enrolled','info')
    else:
        e = Enrollment(user_id=user_id, batch_id=batch_id)
        db.session.add(e)
        db.session.commit()
        flash('Student enrolled','success')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/create_trainer', methods=['POST'])
def create_trainer():
    if not inject_helpers()['is_admin']():
        abort(403)
    name = request.form['name']
    email = request.form['email']
    expertise = request.form.get('expertise', '')
    
    # Check if a Trainer with this email already exists
    if Trainer.query.filter_by(email=email).first():
        flash('A trainer with this email already exists.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Check if a User with this email already exists
    if User.query.filter_by(email=email).first():
        flash('A user with this email already exists. Please use a different email or delete the existing user.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        trainer = Trainer(name=name, email=email, expertise=expertise)
        trainer_user = User(name=name, email=email, role='trainer')
        trainer_user.set_password('trainer123')
        
        db.session.add(trainer)
        db.session.add(trainer_user)
        db.session.commit()
        
        flash("Trainer and user account created successfully! Default password is 'trainer123'.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('admin_dashboard'))

@app.route('/assign_trainer', methods=['POST'])
def assign_trainer():
    if not inject_helpers()['is_admin']():
        abort(403)
    batch_id = request.form['batch_id']
    trainer_id = request.form['trainer_id']

    batch = Batch.query.get_or_404(batch_id)
    trainer = Trainer.query.get_or_404(trainer_id)
    
    # 1. Check if the assigned trainer is the one currently in place
    if batch.trainer_id == trainer.id:
        flash(f"Trainer {trainer.name} is already assigned to batch {batch.name}.", 'info')
        return redirect(url_for('admin_dashboard'))
    
    # 2. Check if a different trainer is currently assigned
    elif batch.trainer_id is not None and batch.trainer_id != trainer.id:
        # If a different trainer is assigned, proceed with replacement and inform the admin.
        old_trainer_name = batch.trainer.name
        batch.trainer_id = trainer_id
        db.session.commit()
        flash(f"Trainer {old_trainer_name} has been replaced by {trainer.name} for batch {batch.name}.", 'warning')
        return redirect(url_for('admin_dashboard'))
    
    # 3. No trainer currently assigned, assign the new one
    else:
        batch.trainer_id = trainer_id
        db.session.commit()
        flash(f"Trainer {trainer.name} assigned to batch {batch.name} successfully!", "success")
        return redirect(url_for('admin_dashboard'))

@app.route('/batch/<int:batch_id>/change_trainer', methods=['GET', 'POST'])
def change_batch_trainer(batch_id):
    if not inject_helpers()['is_admin']():
        abort(403)
        
    batch = Batch.query.get_or_404(batch_id)
    trainers = Trainer.query.all()

    if request.method == 'POST':
        trainer_id = request.form['trainer_id']
        
        # 1. Input Validation
        if trainer_id == 'none':
            # Option to unassign the current trainer
            if batch.trainer_id is not None:
                old_trainer_name = batch.trainer.name
                batch.trainer_id = None
                db.session.commit()
                flash(f"Trainer {old_trainer_name} has been successfully unassigned from batch {batch.name}.", 'warning')
            return redirect(url_for('view_batch_enrollments', batch_id=batch.id))

        try:
            new_trainer_id = int(trainer_id)
            new_trainer = Trainer.query.get(new_trainer_id)
            if not new_trainer:
                flash("Selected trainer not found.", 'danger')
                return redirect(url_for('change_batch_trainer', batch_id=batch.id))

        except ValueError:
            flash("Invalid trainer selection.", 'danger')
            return redirect(url_for('change_batch_trainer', batch_id=batch.id))

        # 2. Replacement Logic
        if batch.trainer_id == new_trainer_id:
            flash(f"Trainer {new_trainer.name} is already assigned to this batch.", 'info')
        
        elif batch.trainer_id is not None:
            # Replace existing trainer
            old_trainer_name = batch.trainer.name
            batch.trainer_id = new_trainer_id
            db.session.commit()
            flash(f"Trainer {old_trainer_name} has been replaced by {new_trainer.name} for batch {batch.name}.", 'warning')
            
        else:
            # Assign new trainer (was unassigned)
            batch.trainer_id = new_trainer_id
            db.session.commit()
            flash(f"Trainer {new_trainer.name} assigned to batch {batch.name} successfully!", "success")
        
        return redirect(url_for('view_batch_enrollments', batch_id=batch.id))

    return render_template('change_batch_trainer.html', batch=batch, trainers=trainers)

@app.route('/batch/<int:batch_id>')
def view_batch(batch_id):
    uid = session.get('user_id')
    batch = Batch.query.get_or_404(batch_id)

    # PUBLIC ACCESS: If not logged in, show the descriptive landing page
    if not uid:
        # Use a simple template for public view
        return render_template('public_batch_view.html', batch=batch)
        
    user = User.query.get(uid)
    recordings = Recording.query.filter_by(batch_id=batch.id).all()
    
    is_enrolled = Enrollment.query.filter_by(user_id=user.id, batch_id=batch_id).first() is not None
    is_assigned_trainer = batch.trainer and batch.trainer.email == user.email

    if user.role == 'student' and not is_enrolled and not inject_helpers()['is_admin']():
        flash('You are not enrolled in this batch.', 'danger')
        return redirect(url_for('dashboard'))
    elif user.role == 'trainer' and not is_assigned_trainer and not inject_helpers()['is_admin']():
        flash('You are not assigned to this batch.', 'danger')
        return redirect(url_for('dashboard'))

    # Get completion status for student
    progress_data = {}
    if user.role == 'student':
        for r in recordings:
            progress = StudentProgress.query.filter_by(user_id=user.id, recording_id=r.id).first()
            progress_data[r.id] = progress.completed if progress else False

    # Define permissions based on user role
    can_upload_delete = inject_helpers()['is_trainer']() and is_assigned_trainer
    can_view_content = can_upload_delete or is_enrolled or inject_helpers()['is_admin']()

    if not can_view_content:
        flash("You are not authorized to view this content.", 'danger')
        return redirect(url_for('dashboard'))


    return render_template('batch.html', 
                           batch=batch, 
                           recordings=recordings, 
                           progress_data=progress_data,
                           can_upload_delete=can_upload_delete) # Pass permission to template


@app.route('/batch/<int:batch_id>/upload', methods=['POST'])
def upload(batch_id):
    # Only Admin and Assigned Trainer can reach this route based on UI, but only trainer can upload.
    # We restrict access immediately in the function body.
    
    batch = Batch.query.get_or_404(batch_id)
    user = inject_helpers()['current_user']()
    is_assigned_trainer = batch.trainer and batch.trainer.email == user.email
    
    # FINAL AUTHORIZATION CHECK: Must be an assigned trainer
    if not (inject_helpers()['is_trainer']() and is_assigned_trainer):
        flash("Only the assigned trainer can upload recordings to this batch.", 'danger')
        abort(403) # Return 403 Forbidden to the client
        
    file = request.files.get('file')
    notes = request.form.get('notes')
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        folder = UPLOAD_ROOT / str(batch.id)
        folder.mkdir(exist_ok=True)
        filepath = folder / filename
        file.save(filepath)
        r = Recording(filename=filename, original_name=file.filename, batch_id=batch.id, notes=notes)
        db.session.add(r)
        db.session.commit()
        flash('Uploaded successfully','success')
    else:
        flash('Invalid file type or no file selected. Please check allowed formats.', 'danger')
    return redirect(url_for('view_batch', batch_id=batch.id))

@app.route('/uploads/<int:batch_id>/<filename>')
def download(batch_id, filename):
    return send_from_directory(UPLOAD_ROOT / str(batch_id), filename)

@app.route('/delete_recording/<int:rec_id>')
def delete_recording(rec_id):
    r = Recording.query.get_or_404(rec_id)
    batch = r.batch
    user = inject_helpers()['current_user']()
    is_assigned_trainer = batch.trainer and batch.trainer.email == user.email
    
    # FINAL AUTHORIZATION CHECK: Must be an assigned trainer
    if not (inject_helpers()['is_trainer']() and is_assigned_trainer):
        flash("Only the assigned trainer can delete content.", 'danger')
        abort(403)

    filepath = UPLOAD_ROOT / str(r.batch_id) / r.filename
    if filepath.exists(): 
        os.remove(filepath)
    db.session.delete(r)
    db.session.commit()
    flash('Recording deleted','info')
    return redirect(url_for('view_batch', batch_id=r.batch_id))

@app.route('/batch/<int:batch_id>/enrollments')
def view_batch_enrollments(batch_id):
    if not (inject_helpers()['is_admin']() or inject_helpers()['is_trainer']()):
        abort(403)
    batch = Batch.query.get_or_404(batch_id)
    enrollments = Enrollment.query.filter_by(batch_id=batch.id).order_by(Enrollment.enrolled_at.desc()).all()
    
    for e in enrollments:
        total_recordings = len(batch.recordings)
        completed_recordings = StudentProgress.query.filter_by(user_id=e.user.id, completed=True).join(Recording).filter(Recording.batch_id == batch.id).count()
        e.progress = f"{completed_recordings} / {total_recordings}"
    
    return render_template('batch_enrollments.html', batch=batch, enrollments=enrollments)

@app.route('/student/<int:user_id>/batches')
def view_student_batches(user_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    student = User.query.get_or_404(user_id)
    enrollments = Enrollment.query.filter_by(user_id=student.id).join(Batch).all()
    return render_template('student_batches.html', student=student, enrollments=enrollments)

@app.route('/search_student_batches')
def search_student_batches():
    if not inject_helpers()['is_admin']():
        abort(403)
    query = request.args.get('query', '').strip()
    student = None
    if '@' in query:
        student = User.query.filter_by(email=query).first()
    else:
        if query.isdigit():
            enrollment = Enrollment.query.get(int(query))
            if enrollment:
                student = enrollment.user
    if not student:
        flash('Student not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    enrollments = Enrollment.query.filter_by(user_id=student.id).join(Batch).all()
    return render_template('student_batches.html', student=student, enrollments=enrollments)

@app.route('/search_trainer')
def search_trainer():
    if not inject_helpers()['is_admin']():
        abort(403)
    query = request.args.get('query', '').strip()
    trainer = None
    
    if '@' in query:
        trainer = Trainer.query.filter_by(email=query).first()
    
    if not trainer:
        flash('Trainer not found by email.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Trainer is found, render a results page.
    return render_template('trainer_search_result.html', trainer=trainer)


@app.route('/delete_enrollment/<int:enroll_id>')
def delete_enrollment(enroll_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    enrollment = Enrollment.query.get_or_404(enroll_id)
    db.session.delete(enrollment)
    db.session.commit()
    flash(f"Student {enrollment.user.name} removed from batch {enrollment.batch.name}", "success")
    return redirect(url_for('admin_dashboard'))

# Route to handle general profile update (name, phone, about, etc.)
def handle_profile_update(user, trainer=None):
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '' and file and allowed_file(file.filename):
            prefix = 'trainer' if trainer else user.role
            id_val = trainer.id if trainer else user.id
            filename = secure_filename(f"{prefix}_{id_val}_{file.filename}")
            PROFILE_PICS_DIR.mkdir(parents=True, exist_ok=True)
            file.save(os.path.join(PROFILE_PICS_DIR, filename))
            
            # Update both user and trainer profiles if applicable
            user.profile_pic = filename
            if trainer:
                trainer.profile_pic = filename

    user.name = request.form['name']
    user.phone = request.form.get('phone')
    user.address = request.form.get('address')
    user.about = request.form.get('about')
    
    if trainer:
        trainer.name = request.form['name']
        trainer.phone = request.form.get('phone')
        trainer.address = request.form.get('address')
        trainer.about = request.form.get('about')
        # Trainer specific field
        trainer.expertise = request.form.get('expertise')
        
    db.session.commit()
    flash('Profile updated successfully!', 'success')

# Route to handle email and password changes (Security)
@app.route('/profile/security', methods=['POST'])
def update_security():
    user = inject_helpers()['current_user']()
    if not user: abort(403)
    
    current_password = request.form['current_password']
    new_password = request.form.get('new_password')
    new_email = request.form.get('new_email')
    
    # 1. Password Verification
    if not user.check_password(current_password):
        flash('Incorrect current password.', 'danger')
        return redirect(url_for('profile'))

    # 2. Handle Password Change
    if new_password:
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return redirect(url_for('profile'))
        user.set_password(new_password)
        flash('Password updated successfully.', 'success')
        
    # 3. Handle Email Change
    if new_email and new_email != user.email:
        # Check if email is already in use by another user
        if User.query.filter(User.email == new_email, User.id != user.id).first():
            flash('Email address is already in use by another account.', 'danger')
            return redirect(url_for('profile'))
        
        # Update User email
        user.email = new_email
        
        # If Trainer, update Trainer email as well
        if user.role == 'trainer':
            trainer = Trainer.query.filter_by(email=user.email).first()
            if trainer:
                trainer.email = new_email
        
        flash('Email updated successfully.', 'success')

    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    user = inject_helpers()['current_user']()
    if not user:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))
    
    if user.role == 'admin':
        return redirect(url_for('admin_profile'))
    elif user.role == 'trainer':
        return redirect(url_for('trainer_profile'))
    else:
        return redirect(url_for('student_profile'))

@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if not inject_helpers()['is_admin'](): abort(403)
    user = inject_helpers()['current_user']()
    if request.method == 'POST':
        handle_profile_update(user)
        return redirect(url_for('admin_profile'))
    return render_template('admin_profile.html', user=user)

@app.route('/trainer/profile', methods=['GET', 'POST'])
def trainer_profile():
    user = inject_helpers()['current_user']()
    if not user or user.role != 'trainer': abort(403)
    trainer = Trainer.query.filter_by(email=user.email).first_or_404()
    if request.method == 'POST':
        handle_profile_update(user, trainer=trainer)
        return redirect(url_for('trainer_profile'))
    return render_template('trainer_profile.html', trainer=trainer, user=user)

@app.route('/student/profile', methods=['GET', 'POST'])
def student_profile():
    user = inject_helpers()['current_user']()
    if not user or user.role != 'student': abort(403)
    if request.method == 'POST':
        handle_profile_update(user)
        return redirect(url_for('student_profile'))
    return render_template('student_profile.html', user=user)

@app.route('/admin/change_password/<int:user_id>', methods=['GET', 'POST'])
def admin_change_password(user_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    
    student = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form['new_password']
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
        else:
            student.set_password(new_password)
            db.session.commit()
            flash(f"Password for {student.name} has been updated successfully.", "success")
            return redirect(url_for('view_all_students'))

    return render_template('change_password.html', student=student)

@app.route('/api/progress/update', methods=['POST'])
def update_progress():
    user = inject_helpers()['current_user']()
    if not user or user.role != 'student':
        return {"status": "error", "message": "Unauthorized"}, 401
    
    data = request.get_json()
    recording_id = data.get('recording_id')
    
    progress = StudentProgress.query.filter_by(user_id=user.id, recording_id=recording_id).first()
    if not progress:
        progress = StudentProgress(user_id=user.id, recording_id=recording_id)
        db.session.add(progress)
        
    progress.completed = True
    progress.completed_at = datetime.utcnow()
    
    db.session.commit()
    return {"status": "success", "message": "Progress updated"}, 200
    
@app.route('/delete_student/<int:user_id>')
def delete_student(user_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot delete an admin user.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.name} and all their enrollments have been deleted.", "success")
    return redirect(url_for('view_all_students'))

@app.route('/delete_trainer/<int:trainer_id>')
def delete_trainer(trainer_id):
    if not inject_helpers()['is_admin']():
        abort(403)
        
    trainer = Trainer.query.get_or_404(trainer_id)
    
    # 1. Handle assigned batches: Unassign the trainer first.
    Batch.query.filter_by(trainer_id=trainer.id).update({Batch.trainer_id: None})
    
    # 2. Find and delete the corresponding User account
    user_to_delete = User.query.filter_by(email=trainer.email, role='trainer').first()
    
    # 3. Delete profile picture (optional but good practice)
    if trainer.profile_pic:
        pic_path = PROFILE_PICS_DIR / trainer.profile_pic
        if pic_path.exists():
            os.remove(pic_path)

    # 4. Delete Trainer and User records
    if user_to_delete:
        db.session.delete(user_to_delete)
        
    db.session.delete(trainer)
    db.session.commit()
    
    flash(f"Trainer '{trainer.name}' and their corresponding user account have been deleted.", "success")
    return redirect(url_for('view_all_trainers'))

# NEW ROUTE FOR EMBEDDED YOUTUBE/VIDEO SEARCH
@app.route('/youtube_search')
def youtube_search():
    if not session.get('user_id'):
        # Allow logged-out users to search but restrict content later
        pass 
    
    query = request.args.get('search_query')
    if not query:
        flash("Please enter a search query.", 'danger')
        return redirect(url_for('dashboard'))
        
    # Use Google Video Search to find relevant results (most reliable for embedding)
    # We use a large frame to show results without leaving the LMS
    search_url = f"https://www.google.com/search?q={query}+tutorial&tbm=vid&igu=1" 
    # igu=1 helps ensure the page loads within the iframe on some mobile browsers
    
    return render_template('youtube_viewer.html', search_url=search_url, query=query)


# ---------------- Initialize ----------------
if __name__ == '__main__':
    pathlib.Path('templates').mkdir(exist_ok=True)
    pathlib.Path('static').mkdir(exist_ok=True)
    pathlib.Path('uploads').mkdir(exist_ok=True)
    pathlib.Path('static/profiles').mkdir(exist_ok=True)
    
    with app.app_context():
        db.create_all()

    app.run(debug=True)
