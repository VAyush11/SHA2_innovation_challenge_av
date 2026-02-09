<<<<<<< HEAD
"""
main.py - Home Rehab Coach Flask Application
With SQLite database integration
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, close_db, query_db, execute_db
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Required for sessions
=======
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import os
from optim import get_top3_recommendations, optimize_all_patients, build_demo_data, load_dataset

# Create instance folder if it doesn't exist
os.makedirs('instance', exist_ok=True)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key

# Use absolute path for database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "rehab_app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

# Initialize extensions
db = SQLAlchemy(app)
Session(app)
CORS(app, supports_credentials=True)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'landing'

# ==================== DATABASE MODELS ====================

# User model (with Flask-Login integration)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email_id = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'patient', 'caregiver', 'clinician'
    password = db.Column(db.String(255), nullable=False)
    joining_date = db.Column(db.String(50), nullable=False)  # Changed to String to match SQLite TEXT
    address = db.Column(db.Text)
    
    # Relationship with user_visits
    visits = db.relationship('UserVisit', backref='user', lazy=True)
    
    def get_id(self):
        return str(self.user_id)
    
    def __repr__(self):
        return f'<User {self.name} - {self.role}>'

# UserVisit model
class UserVisit(db.Model):
    __tablename__ = 'user_visits'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    visit_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<UserVisit {self.user_id} at {self.visit_time}>'

# ==================== FLASK-LOGIN USER LOADER ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== AUTHENTICATION API ====================

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email_id')
    password = data.get('password')
    
    print(f"Login attempt - Email: {email}")  # Debug log
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    
    # Find user by email
    user = User.query.filter_by(email_id=email).first()
    
    if not user:
        print(f"User not found for email: {email}")  # Debug log
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    print(f"User found: {user.name}, Role: {user.role}")  # Debug log
    print(f"Stored password: {user.password}")  # Debug log
    print(f"Entered password: {password}")  # Debug log
    
    # Check password (plain text for now - use hashed passwords in production)
    if user.password != password:
        print("Password mismatch!")  # Debug log
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    print("Password matched! Logging in user...")  # Debug log
    
    # Log the user in with Flask-Login
    login_user(user)
    
    # Log the visit
    visit = UserVisit(user_id=user.user_id, visit_time=datetime.utcnow())
    db.session.add(visit)
    db.session.commit()
    
    # Store user info in session
    session['user_id'] = user.user_id
    session['user_role'] = user.role
    session['user_name'] = user.name
    
    # Return success with user role for routing
    return jsonify({
        'success': True,
        'role': user.role,
        'name': user.name,
        'user_id': user.user_id
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/api/current-user', methods=['GET'])
def get_current_user():
    """Get current logged-in user information"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user_id': current_user.user_id,
            'name': current_user.name,
            'email': current_user.email_id,
            'role': current_user.role
        }), 200
    else:
        return jsonify({'authenticated': False}), 401
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688

# Register database cleanup function
app.teardown_appcontext(close_db)


# ==================== AUTHENTICATION HELPERS ====================

def login_required(f):
    """
    Decorator to protect routes that require login.
    Usage: Add @login_required below @app.route()
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    """
    Decorator to restrict routes to specific roles.
    Usage: @role_required('doctor')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('landing'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_current_user():
    """Get the currently logged-in user from database."""
    if 'user_id' in session:
        return query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
    return None


# ==================== AUTH ROUTES ====================

@app.route('/')
def landing():
    """Landing Page"""
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Page"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Find user by email
        user = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
        
        if user and check_password_hash(user['password'], password):
            # Login successful - store user info in session
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['role'] = user['role']
            
            flash(f'Welcome back, {user["name"]}!', 'success')
            
            # Redirect based on role
            if user['role'] == 'doctor':
                return redirect(url_for('clinician_dashboard'))
            elif user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user['role'] == 'caregiver':
                return redirect(url_for('caregiver_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup Page"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        role = request.form['role']
        
        # Check if email already exists
        existing_user = query_db('SELECT id FROM users WHERE email = ?', (email,), one=True)
        if existing_user:
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('login'))
        
        # Hash password and create user
        hashed_password = generate_password_hash(password)
        user_id = execute_db(
            'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
            (email, hashed_password, name, role)
        )
        
        # If patient, create patients record
        if role == 'patient':
            condition = request.form.get('condition', 'General Rehab')
            execute_db(
                'INSERT INTO patients (user_id, condition) VALUES (?, ?)',
                (user_id, condition)
            )
        
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('landing'))


# ==================== PATIENT ROUTES ====================

@app.route('/patient/dashboard')
@login_required
<<<<<<< HEAD
@role_required('patient')
def patient_dashboard():
    """Patient Home Dashboard"""
    user = get_current_user()
    
    # Get patient's medical info
    patient_info = query_db(
        'SELECT * FROM patients WHERE user_id = ?',
        (session['user_id'],),
        one=True
    )
    
    # Get patient's workouts
    workouts = query_db('''
        SELECT w.*, e.name as exercise_name, e.description
        FROM workouts w
        JOIN exercises e ON w.exercise_id = e.id
        WHERE w.patient_id = ? AND w.is_active = 1
    ''', (session['user_id'],))
    
    # Get recent sessions
    recent_sessions = query_db('''
        SELECT s.*, e.name as exercise_name
        FROM sessions s
        JOIN workouts w ON s.workout_id = w.id
        JOIN exercises e ON w.exercise_id = e.id
        WHERE s.patient_id = ?
        ORDER BY s.completed_at DESC
        LIMIT 5
    ''', (session['user_id'],))
    
    return render_template('patient/dashboard.html',
                         user=user,
                         patient=patient_info,
                         workouts=workouts,
                         recent_sessions=recent_sessions)


@app.route('/patient/session')
@login_required
@role_required('patient')
def rehab_session():
    """Rehab Session Screen"""
    # Get today's workouts
    workouts = query_db('''
        SELECT w.*, e.name as exercise_name, e.description, e.category
        FROM workouts w
        JOIN exercises e ON w.exercise_id = e.id
        WHERE w.patient_id = ? AND w.is_active = 1
    ''', (session['user_id'],))
    
    return render_template('patient/session.html', workouts=workouts)


@app.route('/patient/checkin', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def pain_checkin():
    """Pain & Effort Check-In Screen"""
    if request.method == 'POST':
        workout_id = request.form['workout_id']
        pain_before = request.form.get('pain_before', 0)
        pain_after = request.form.get('pain_after', 0)
        effort_level = request.form.get('effort_level', 5)
        quality_score = request.form.get('quality_score', 70)
        sets_completed = request.form.get('sets_completed', 0)
        reps_completed = request.form.get('reps_completed', 0)
        notes = request.form.get('notes', '')
        
        # Save session to database
        execute_db('''
            INSERT INTO sessions 
            (patient_id, workout_id, pain_before, pain_after, effort_level, 
             quality_score, sets_completed, reps_completed, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], workout_id, pain_before, pain_after,
              effort_level, quality_score, sets_completed, reps_completed, notes))
        
        flash('Session recorded successfully!', 'success')
        return redirect(url_for('session_summary'))
    
=======
def patient_dashboard():
    """Patient Home Dashboard"""
    if current_user.role != 'patient':
        return redirect(url_for('landing'))
    return render_template('patient/dashboard.html')

@app.route('/patient/session')
@login_required
def rehab_session():
    """Rehab Session Screen (Core Screen)"""
    if current_user.role != 'patient':
        return redirect(url_for('landing'))
    return render_template('patient/session.html')

@app.route('/patient/checkin')
@login_required
def pain_checkin():
    """Pain & Effort Check-In Screen"""
    if current_user.role != 'patient':
        return redirect(url_for('landing'))
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688
    return render_template('patient/checkin.html')


@app.route('/patient/summary')
@login_required
<<<<<<< HEAD
@role_required('patient')
def session_summary():
    """Session Summary Screen"""
    # Get the most recent session
    latest_session = query_db('''
        SELECT s.*, e.name as exercise_name
        FROM sessions s
        JOIN workouts w ON s.workout_id = w.id
        JOIN exercises e ON w.exercise_id = e.id
        WHERE s.patient_id = ?
        ORDER BY s.completed_at DESC
        LIMIT 1
    ''', (session['user_id'],), one=True)
    
    return render_template('patient/summary.html', session_data=latest_session)


@app.route('/patient/progress')
@login_required
@role_required('patient')
def progress_history():
    """Progress & History Screen"""
    # Get all sessions for this patient
    all_sessions = query_db('''
        SELECT s.*, e.name as exercise_name
        FROM sessions s
        JOIN workouts w ON s.workout_id = w.id
        JOIN exercises e ON w.exercise_id = e.id
        WHERE s.patient_id = ?
        ORDER BY s.completed_at DESC
    ''', (session['user_id'],))
    
    # Get patient stats
    patient_info = query_db(
        'SELECT * FROM patients WHERE user_id = ?',
        (session['user_id'],),
        one=True
    )
    
    return render_template('patient/progress.html',
                         sessions=all_sessions,
                         patient=patient_info)

=======
def session_summary():
    """Session Summary Screen"""
    if current_user.role != 'patient':
        return redirect(url_for('landing'))
    return render_template('patient/summary.html')

@app.route('/patient/progress')
@login_required
def progress_history():
    """Progress & History Screen"""
    if current_user.role != 'patient':
        return redirect(url_for('landing'))
    return render_template('patient/progress.html')
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688

# ==================== CLINICIAN ROUTES ====================

@app.route('/clinician/dashboard')
@login_required
<<<<<<< HEAD
@role_required('doctor')
def clinician_dashboard():
    """Clinician Dashboard - Shows all patients assigned to this doctor"""
    # Get all patients for this doctor with their info
    patients = query_db('''
        SELECT 
            u.id, u.name, u.email,
            p.condition, p.current_week, p.adherence_rate, 
            p.avg_pain_level, p.avg_quality_score, p.streak_days
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN doctor_patient dp ON u.id = dp.patient_id
        WHERE dp.doctor_id = ?
        ORDER BY p.adherence_rate ASC
    ''', (session['user_id'],))
    
    # Count stats
    total_patients = len(patients)
    needs_attention = sum(1 for p in patients if p['adherence_rate'] < 50 or p['avg_pain_level'] > 6)
    avg_adherence = sum(p['adherence_rate'] for p in patients) / total_patients if total_patients > 0 else 0
    
    # Get upcoming appointments
    appointments = query_db('''
        SELECT a.*, u.name as patient_name
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
        LIMIT 5
    ''', (session['user_id'],))
    
    return render_template('clinician/dashboard.html',
                         patients=patients,
                         total_patients=total_patients,
                         needs_attention=needs_attention,
                         avg_adherence=round(avg_adherence),
                         upcoming_appointments=len(appointments))


@app.route('/clinician/patient/<int:patient_id>')
@login_required
@role_required('doctor')
def patient_detail(patient_id):
    """Patient Detail View"""
    # Get patient info
    patient = query_db('''
        SELECT u.*, p.*
        FROM users u
        JOIN patients p ON u.id = p.user_id
        WHERE u.id = ?
    ''', (patient_id,), one=True)
    
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('clinician_dashboard'))
    
    # Get patient's workouts
    workouts = query_db('''
        SELECT w.*, e.name as exercise_name, e.category
        FROM workouts w
        JOIN exercises e ON w.exercise_id = e.id
        WHERE w.patient_id = ? AND w.is_active = 1
    ''', (patient_id,))
    
    # Get recent sessions
    sessions = query_db('''
        SELECT s.*, e.name as exercise_name
        FROM sessions s
        JOIN workouts w ON s.workout_id = w.id
        JOIN exercises e ON w.exercise_id = e.id
        WHERE s.patient_id = ?
        ORDER BY s.completed_at DESC
        LIMIT 10
    ''', (patient_id,))
    
    return render_template('clinician/patient_detail.html',
                         patient=patient,
                         workouts=workouts,
                         sessions=sessions)


@app.route('/clinician/plan-editor', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def plan_editor():
    """Rehab Plan Editor"""
    if request.method == 'POST':
        patient_id = request.form['patient_id']
        exercise_id = request.form['exercise_id']
        sets = request.form.get('sets', 3)
        reps = request.form.get('reps', 10)
        frequency = request.form.get('frequency', 'Daily')
        instructions = request.form.get('instructions', '')
        
        # Add workout to patient's plan
        execute_db('''
            INSERT INTO workouts 
            (patient_id, exercise_id, sets, reps, frequency, instructions)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (patient_id, exercise_id, sets, reps, frequency, instructions))
        
        flash('Exercise added to patient\'s plan!', 'success')
    
    # Get all patients for this doctor
    patients = query_db('''
        SELECT u.id, u.name, p.condition
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN doctor_patient dp ON u.id = dp.patient_id
        WHERE dp.doctor_id = ?
    ''', (session['user_id'],))
    
    # Get all exercises
    exercises = query_db('SELECT * FROM exercises ORDER BY category, name')
    
    # Get selected patient's current workouts (if any)
    selected_patient_id = request.args.get('patient_id')
    current_workouts = []
    if selected_patient_id:
        current_workouts = query_db('''
            SELECT w.*, e.name as exercise_name, e.category
            FROM workouts w
            JOIN exercises e ON w.exercise_id = e.id
            WHERE w.patient_id = ? AND w.is_active = 1
        ''', (selected_patient_id,))
    
    return render_template('clinician/plan_editor.html',
                         patients=patients,
                         exercises=exercises,
                         current_workouts=current_workouts,
                         selected_patient_id=selected_patient_id)


@app.route('/clinician/consultation', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def consultation():
    """Consultation & Scheduling Screen"""
    if request.method == 'POST':
        patient_id = request.form['patient_id']
        appointment_date = request.form['appointment_date']
        appointment_time = request.form['appointment_time']
        duration = request.form.get('duration', 30)
        notes = request.form.get('notes', '')
        
        # Create appointment
        execute_db('''
            INSERT INTO appointments 
            (doctor_id, patient_id, appointment_date, appointment_time, duration, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], patient_id, appointment_date, appointment_time, duration, notes))
        
        flash('Appointment scheduled successfully!', 'success')
    
    # Get all patients for this doctor
    patients = query_db('''
        SELECT u.id, u.name
        FROM users u
        JOIN doctor_patient dp ON u.id = dp.patient_id
        WHERE dp.doctor_id = ?
    ''', (session['user_id'],))
    
    # Get upcoming appointments
    appointments = query_db('''
        SELECT a.*, u.name as patient_name
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
    ''', (session['user_id'],))
    
    return render_template('clinician/consultation.html',
                         patients=patients,
                         appointments=appointments)

=======
def clinician_dashboard():
    """Clinician Dashboard"""
    if current_user.role != 'clinician':
        return redirect(url_for('landing'))
    return render_template('clinician/dashboard.html')

@app.route('/clinician/patient/<patient_id>')
@login_required
def patient_detail(patient_id):
    """Patient Detail View"""
    if current_user.role != 'clinician':
        return redirect(url_for('landing'))
    return render_template('clinician/patient_detail.html', patient_id=patient_id)

@app.route('/clinician/plan-editor')
@login_required
def plan_editor():
    """Rehab Plan Editor"""
    if current_user.role != 'clinician':
        return redirect(url_for('landing'))
    return render_template('clinician/plan_editor.html')

@app.route('/clinician/consultation')
@login_required
def consultation():
    """Consultation & Scheduling Screen"""
    if current_user.role != 'clinician':
        return redirect(url_for('landing'))
    return render_template('clinician/consultation.html')
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688

# ==================== CAREGIVER ROUTES ====================

@app.route('/caregiver/dashboard')
@login_required
<<<<<<< HEAD
@role_required('caregiver')
def caregiver_dashboard():
    """Caregiver Dashboard"""
    # Get patients this caregiver monitors
    monitored_patients = query_db('''
        SELECT 
            u.id, u.name,
            p.condition, p.adherence_rate, p.avg_pain_level, 
            p.avg_quality_score, p.streak_days,
            cp.relationship
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN caregiver_patient cp ON u.id = cp.patient_id
        WHERE cp.caregiver_id = ?
    ''', (session['user_id'],))
    
    # Get recent sessions for monitored patients
    patient_ids = [p['id'] for p in monitored_patients]
    recent_sessions = []
    if patient_ids:
        placeholders = ','.join('?' * len(patient_ids))
        recent_sessions = query_db(f'''
            SELECT s.*, u.name as patient_name, e.name as exercise_name
            FROM sessions s
            JOIN users u ON s.patient_id = u.id
            JOIN workouts w ON s.workout_id = w.id
            JOIN exercises e ON w.exercise_id = e.id
            WHERE s.patient_id IN ({placeholders})
            ORDER BY s.completed_at DESC
            LIMIT 10
        ''', patient_ids)
    
    return render_template('caregiver/dashboard.html',
                         patients=monitored_patients,
                         recent_sessions=recent_sessions)

=======
def caregiver_dashboard():
    """Caregiver Dashboard"""
    if current_user.role != 'caregiver':
        return redirect(url_for('landing'))
    return render_template('caregiver/dashboard.html')
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688

# ==================== ROLE SELECTION ====================

@app.route('/select-role')
def select_role():
    """Role Selection Screen"""
    return render_template('role_select.html')

<<<<<<< HEAD

# ==================== API ROUTES (for AJAX) ====================

@app.route('/api/remove-workout/<int:workout_id>', methods=['POST'])
@login_required
@role_required('doctor')
def remove_workout(workout_id):
    """Remove a workout from patient's plan (soft delete)."""
    execute_db('UPDATE workouts SET is_active = 0 WHERE id = ?', (workout_id,))
    flash('Exercise removed from plan.', 'success')
    return redirect(request.referrer or url_for('plan_editor'))


@app.route('/api/cancel-appointment/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    """Cancel an appointment."""
    execute_db("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appointment_id,))
    flash('Appointment cancelled.', 'success')
    return redirect(request.referrer or url_for('consultation'))


# ==================== DATABASE INITIALIZATION ====================

@app.cli.command('init-db')
def init_db_command():
    """
    CLI command to initialize database.
    Run with: flask init-db
    """
    from database import init_db
    init_db(app)
    print('Database initialized!')
=======
# ==================== OPTIMIZATION API ====================

@app.route('/api/optimize', methods=['POST'])
@login_required
def api_optimize():
    """Run appointment optimization for a single patient."""
    data = request.get_json()
    if data is None:
        return jsonify({"error": "Request body must be JSON"}), 400

    patient_id = data.get("patient_id")
    patients = data.get("patients")
    doctors = data.get("doctors")
    timeslots = data.get("timeslots")
    weights = data.get("weights")

    if not all([patient_id, patients, doctors, timeslots]):
        return jsonify({
            "error": "Missing required fields: patient_id, patients, doctors, timeslots"
        }), 400

    recs, notification = get_top3_recommendations(
        patient_id=patient_id,
        patients=patients,
        doctors=doctors,
        timeslots=timeslots,
        weights=weights,
    )

    return jsonify({
        "patient_id": patient_id,
        "recommendations": recs,
        "notification": notification,
    })


@app.route('/api/optimize/all', methods=['POST'])
@login_required
def api_optimize_all():
    """Run appointment optimization for all patients."""
    data = request.get_json()
    if data is None:
        return jsonify({"error": "Request body must be JSON"}), 400

    patients = data.get("patients")
    doctors = data.get("doctors")
    timeslots = data.get("timeslots")
    weights = data.get("weights")

    if not all([patients, doctors, timeslots]):
        return jsonify({
            "error": "Missing required fields: patients, doctors, timeslots"
        }), 400

    results = optimize_all_patients(
        patients=patients,
        doctors=doctors,
        timeslots=timeslots,
        weights=weights,
    )

    return jsonify({"results": results})


@app.route('/api/optimize/demo', methods=['GET'])
def api_optimize_demo():
    """Run optimization with built-in demo data. No input needed."""
    patients, doctors, timeslots = build_demo_data()
    results = optimize_all_patients(patients, doctors, timeslots)
    return jsonify({"results": results})
>>>>>>> 7b9ad655126d7d200d8f599d1f1a5909e8bef688


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
        print(f"Database location: {os.path.join(basedir, 'instance', 'rehab_app.db')}")
    
    app.run(debug=True)
