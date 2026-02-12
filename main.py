"""
main.py - Home Rehab Coach Flask Application
With SQLite database integration, Video Call features, and CV/ML Pipeline
"""

import sys
import os
# Ensure current directory is in sys.path for local imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, close_db, query_db, execute_db
from functools import wraps
from datetime import datetime, date
import uuid

# Import optimization module (from computer_vision branch)
try:
    from optim import get_top3_recommendations, optimize_all_patients, build_demo_data, load_dataset
    OPTIM_AVAILABLE = True
except ImportError:
    OPTIM_AVAILABLE = False
    print("[WARNING] optim module not found - optimization features disabled")

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Required for sessions

# Register database cleanup function
app.teardown_appcontext(close_db)


# ==================== AUTHENTICATION HELPERS ====================

def login_required(f):
    """Decorator to protect routes that require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    """Decorator to restrict routes to specific roles."""
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
        
        if user:
            password_match = check_password_hash(user['password'], password)
            
            if password_match:
                # Login successful - store user info in session
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                session.permanent = True  # Make session persistent
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                
                # Redirect based on role
                if user['role'] == 'doctor':
                    return redirect(url_for('clinician_dashboard'))
                elif user['role'] == 'patient':
                    return redirect(url_for('patient_dashboard'))
                elif user['role'] == 'caregiver':
                    return redirect(url_for('caregiver_dashboard'))
        
        flash('Invalid email or password.', 'error')
    
    return render_template('login.html')


# API Login endpoint (for computer_vision branch compatibility)
@app.route('/api/login', methods=['POST'])
def api_login():
    """API Login endpoint"""
    data = request.get_json()
    email = data.get('email_id') or data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    
    user = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    # Check password (support both hashed and plain text for compatibility)
    password_match = False
    try:
        password_match = check_password_hash(user['password'], password)
    except:
        password_match = (user['password'] == password)
    
    if not password_match:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    # Store in session
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['role'] = user['role']
    
    # Map role names for compatibility
    role_map = {'doctor': 'clinician', 'patient': 'patient', 'caregiver': 'caregiver'}
    
    return jsonify({
        'success': True,
        'role': role_map.get(user['role'], user['role']),
        'name': user['name'],
        'user_id': user['id']
    }), 200


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """API Logout endpoint"""
    session.clear()
    return jsonify({'success': True}), 200


@app.route('/api/current-user', methods=['GET'])
def api_current_user():
    """Get current logged-in user information"""
    if 'user_id' in session:
        user = get_current_user()
        if user:
            return jsonify({
                'authenticated': True,
                'user_id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }), 200
    return jsonify({'authenticated': False}), 401


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
        
        # If patient, create patients record and assign to selected doctor
        if role == 'patient':
            condition = request.form.get('condition', 'General Rehab')
            execute_db(
                'INSERT INTO patients (user_id, condition) VALUES (?, ?)',
                (user_id, condition)
            )
            # Assign to selected doctor, or first available if none selected
            selected_doctor_id = request.form.get('doctor_id')
            if selected_doctor_id:
                execute_db(
                    'INSERT OR IGNORE INTO doctor_patient (doctor_id, patient_id) VALUES (?, ?)',
                    (int(selected_doctor_id), user_id)
                )
            else:
                # Fallback: assign to first available doctor
                doctor = query_db('SELECT id FROM users WHERE role = ? LIMIT 1', ('doctor',), one=True)
                if doctor:
                    execute_db(
                        'INSERT OR IGNORE INTO doctor_patient (doctor_id, patient_id) VALUES (?, ?)',
                        (doctor['id'], user_id)
                    )
        
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    
    # GET request - fetch available doctors for the dropdown
    doctors = query_db('SELECT id, name FROM users WHERE role = ?', ('doctor',))
    return render_template('signup.html', doctors=doctors)


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('landing'))


# ==================== PATIENT ROUTES ====================

@app.route('/patient/dashboard')
@login_required
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
    
    # Get upcoming appointments (simpler query - just get all scheduled)
    upcoming_appointments = query_db('''
        SELECT a.*, u.name as doctor_name
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        WHERE a.patient_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
        LIMIT 3
    ''', (session['user_id'],))
    
    return render_template('patient/dashboard.html',
                         user=user,
                         patient=patient_info,
                         workouts=workouts if workouts else [],
                         recent_sessions=recent_sessions if recent_sessions else [],
                         upcoming_appointments=upcoming_appointments if upcoming_appointments else [])


@app.route('/patient/session')
@login_required
@role_required('patient')
def rehab_session():
    """Rehab Session Screen"""
    workouts = query_db('''
        SELECT w.*, e.name as exercise_name, e.description, e.category
        FROM workouts w
        JOIN exercises e ON w.exercise_id = e.id
        WHERE w.patient_id = ? AND w.is_active = 1
    ''', (session['user_id'],))
    
    return render_template('patient/session.html', workouts=workouts if workouts else [])


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
        
        execute_db('''
            INSERT INTO sessions 
            (patient_id, workout_id, pain_before, pain_after, effort_level, 
             quality_score, sets_completed, reps_completed, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], workout_id, pain_before, pain_after,
              effort_level, quality_score, sets_completed, reps_completed, notes))
        
        flash('Session recorded successfully!', 'success')
        return redirect(url_for('session_summary'))
    
    return render_template('patient/checkin.html')


@app.route('/patient/summary')
@login_required
@role_required('patient')
def session_summary():
    """Session Summary Screen"""
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
    all_sessions = query_db('''
        SELECT s.*, e.name as exercise_name
        FROM sessions s
        JOIN workouts w ON s.workout_id = w.id
        JOIN exercises e ON w.exercise_id = e.id
        WHERE s.patient_id = ?
        ORDER BY s.completed_at DESC
    ''', (session['user_id'],))
    
    patient_info = query_db(
        'SELECT * FROM patients WHERE user_id = ?',
        (session['user_id'],),
        one=True
    )
    
    return render_template('patient/progress.html',
                         sessions=all_sessions if all_sessions else [],
                         patient=patient_info)


@app.route('/patient/appointments')
@login_required
@role_required('patient')
def patient_appointments():
    """Patient's Appointments View"""
    # Get all upcoming appointments
    appointments = query_db('''
        SELECT a.*, u.name as doctor_name
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        WHERE a.patient_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
    ''', (session['user_id'],))
    
    # Get past appointments
    past_appointments = query_db('''
        SELECT a.*, u.name as doctor_name
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        WHERE a.patient_id = ? AND (a.status = 'completed' OR a.status = 'cancelled')
        ORDER BY a.appointment_date DESC, a.appointment_time DESC
        LIMIT 10
    ''', (session['user_id'],))
    
    return render_template('patient/appointments.html',
                         appointments=appointments if appointments else [],
                         past_appointments=past_appointments if past_appointments else [])


@app.route('/patient/book-appointment', methods=['POST'])
@login_required
@role_required('patient')
def patient_book_appointment():
    """Patient books an appointment with a recommended doctor."""
    doctor_name = request.form.get('doctor_name', '').strip()
    appointment_date = request.form['appointment_date']
    appointment_time = request.form['appointment_time']
    duration = request.form.get('duration', 30)
    notes = request.form.get('notes', '')

    # Find doctor by name
    doctor = query_db(
        "SELECT id FROM users WHERE role = 'doctor' AND name LIKE ?",
        (f'%{doctor_name}%',), one=True
    )
    if not doctor:
        doctor_name_clean = doctor_name.replace('Dr.', '').strip()
        doctor = query_db(
            "SELECT id FROM users WHERE role = 'doctor' AND name LIKE ?",
            (f'%{doctor_name_clean}%',), one=True
        )

    if not doctor:
        flash('Doctor not found. Please try again.', 'error')
        return redirect(url_for('patient_appointments'))

    doctor_id = doctor['id']
    patient_id = session['user_id']
    room_id = f"rehab-{doctor_id}-{patient_id}-{uuid.uuid4().hex[:8]}"

    try:
        execute_db('''
            INSERT INTO appointments
            (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled')
        ''', (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id))
        flash('Appointment booked successfully! Your doctor will be notified.', 'success')
    except Exception as e:
        flash('Failed to book appointment. Please try again.', 'error')
        print(f'[ERROR] Patient book appointment failed: {e}')

    return redirect(url_for('patient_appointments'))


# ==================== CLINICIAN ROUTES ====================

@app.route('/clinician/dashboard')
@login_required
@role_required('doctor')
def clinician_dashboard():
    """Clinician Dashboard"""
    # Get patients assigned to this doctor
    patients = query_db('''
        SELECT 
            u.id, u.name, u.email,
            p.condition, p.current_week, p.adherence_rate, 
            p.avg_pain_level, p.avg_quality_score, p.completed_sessions
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN doctor_patient dp ON p.user_id = dp.patient_id
        WHERE dp.doctor_id = ?
        ORDER BY p.adherence_rate ASC
    ''', (session['user_id'],))
    
    # If no assigned patients, show ALL patients (for demo/new doctors)
    if not patients:
        patients = query_db('''
            SELECT 
                u.id, u.name, u.email,
                p.condition, p.current_week, p.adherence_rate, 
                p.avg_pain_level, p.avg_quality_score, p.completed_sessions
            FROM users u
            JOIN patients p ON u.id = p.user_id
            ORDER BY p.adherence_rate ASC
        ''')
    
    patients = patients if patients else []
    total_patients = len(patients)
    needs_attention = sum(1 for p in patients if p['adherence_rate'] < 50 or p['avg_pain_level'] > 6)
    avg_adherence = sum(p['adherence_rate'] for p in patients) / total_patients if total_patients > 0 else 0
    
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
                         upcoming_appointments=len(appointments) if appointments else 0)


@app.route('/clinician/patient/<int:patient_id>')
@login_required
@role_required('doctor')
def patient_detail(patient_id):
    """Patient Detail View"""
    patient = query_db('''
        SELECT u.*, p.*
        FROM users u
        JOIN patients p ON u.id = p.user_id
        WHERE u.id = ?
    ''', (patient_id,), one=True)
    
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('clinician_dashboard'))
    
    workouts = query_db('''
        SELECT w.*, e.name as exercise_name, e.category
        FROM workouts w
        JOIN exercises e ON w.exercise_id = e.id
        WHERE w.patient_id = ? AND w.is_active = 1
    ''', (patient_id,))
    
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
                         workouts=workouts if workouts else [],
                         sessions=sessions if sessions else [])


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
        
        execute_db('''
            INSERT INTO workouts 
            (patient_id, exercise_id, sets, reps, frequency, instructions)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (patient_id, exercise_id, sets, reps, frequency, instructions))
        
        flash('Exercise added to patient\'s plan!', 'success')
    
    # Get patients assigned to this doctor
    patients = query_db('''
        SELECT u.id, u.name, p.condition
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN doctor_patient dp ON p.user_id = dp.patient_id
        WHERE dp.doctor_id = ?
    ''', (session['user_id'],))
    
    # If no assigned patients, show ALL patients
    if not patients:
        patients = query_db('''
            SELECT u.id, u.name, p.condition
            FROM users u
            JOIN patients p ON u.id = p.user_id
        ''')
    
    exercises = query_db('SELECT * FROM exercises ORDER BY category, name')
    
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
                         patients=patients if patients else [],
                         exercises=exercises if exercises else [],
                         current_workouts=current_workouts if current_workouts else [],
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
        
        # Generate unique room ID for video call
        room_id = f"rehab-{session['user_id']}-{patient_id}-{uuid.uuid4().hex[:8]}"
        
        execute_db('''
            INSERT INTO appointments 
            (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], patient_id, appointment_date, appointment_time, duration, notes, room_id))
        
        flash('Appointment scheduled successfully!', 'success')
        return redirect(url_for('consultation'))
    
    # Get patients assigned to this doctor
    patients = query_db('''
        SELECT u.id, u.name
        FROM users u
        JOIN patients p ON u.id = p.user_id
        JOIN doctor_patient dp ON p.user_id = dp.patient_id
        WHERE dp.doctor_id = ?
    ''', (session['user_id'],))

    # If no assigned patients, show ALL patients (for demo/new doctors)
    if not patients or len(patients) == 0:
        patients = query_db('''
            SELECT u.id, u.name
            FROM users u
            JOIN patients p ON u.id = p.user_id
        ''')

    print('[DEBUG] Consultation patients:', patients)

    appointments = query_db('''
        SELECT a.*, u.name as patient_name, p.condition, p.adherence_rate, p.avg_pain_level, p.avg_quality_score
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        LEFT JOIN patients p ON u.id = p.user_id
        WHERE a.doctor_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
    ''', (session['user_id'],))
    
    return render_template('clinician/consultation.html',
                         patients=patients if patients else [],
                         appointments=appointments if appointments else [])


# ==================== VIDEO CALL ROUTES ====================

@app.route('/video-call/<int:appointment_id>')
@login_required
def video_call(appointment_id):
    """Video Call Room"""
    appointment = query_db('''
        SELECT a.*, 
               doc.name as doctor_name,
               pat.name as patient_name,
               p.condition, p.adherence_rate, p.avg_pain_level, p.avg_quality_score
        FROM appointments a
        JOIN users doc ON a.doctor_id = doc.id
        JOIN users pat ON a.patient_id = pat.id
        LEFT JOIN patients p ON pat.id = p.user_id
        WHERE a.id = ?
    ''', (appointment_id,), one=True)
    
    if not appointment:
        flash('Appointment not found.', 'error')
        return redirect(url_for('landing'))
    
    # Check if user is authorized (must be doctor or patient of this appointment)
    if session['user_id'] != appointment['doctor_id'] and session['user_id'] != appointment['patient_id']:
        flash('You are not authorized to join this call.', 'error')
        return redirect(url_for('landing'))
    
    # Get or generate room_id
    room_id = appointment['room_id'] if appointment['room_id'] else f"rehab-call-{appointment_id}"
    
    # Update room_id if it wasn't set
    if not appointment['room_id']:
        execute_db('UPDATE appointments SET room_id = ? WHERE id = ?', (room_id, appointment_id))
    
    return render_template('video_call.html',
                         appointment=appointment,
                         room_id=room_id,
                         user_name=session['user_name'],
                         is_doctor=(session['role'] == 'doctor'))


@app.route('/video-call/quick/<int:patient_id>')
@login_required
@role_required('doctor')
def quick_call(patient_id):
    """Start a quick video call without scheduling"""
    patient = query_db('SELECT * FROM users WHERE id = ?', (patient_id,), one=True)
    
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('clinician_dashboard'))
    
    # Create an instant appointment
    room_id = f"quick-call-{session['user_id']}-{patient_id}-{uuid.uuid4().hex[:8]}"
    today = date.today().isoformat()
    now = datetime.now().strftime('%H:%M')
    
    appointment_id = execute_db('''
        INSERT INTO appointments 
        (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled')
    ''', (session['user_id'], patient_id, today, now, 30, 'Quick call', room_id))
    
    return redirect(url_for('video_call', appointment_id=appointment_id))


# ==================== CAREGIVER ROUTES ====================

@app.route('/caregiver/dashboard')
@login_required
@role_required('caregiver')
def caregiver_dashboard():
    """Caregiver Dashboard"""
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
    
    patient_ids = [p['id'] for p in monitored_patients] if monitored_patients else []
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
                         patients=monitored_patients if monitored_patients else [],
                         recent_sessions=recent_sessions if recent_sessions else [])


# ==================== ROLE SELECTION ====================

@app.route('/select-role')
def select_role():
    """Role Selection Screen"""
    return render_template('role_select.html')


# ==================== API ROUTES ====================

@app.route('/api/appointments', methods=['GET'])
@login_required
def get_appointments():
    """Get appointments for current user"""
    if session['role'] == 'doctor':
        appointments = query_db('''
            SELECT a.*, u.name as patient_name
            FROM appointments a
            JOIN users u ON a.patient_id = u.id
            WHERE a.doctor_id = ? AND a.status = 'scheduled'
            ORDER BY a.appointment_date, a.appointment_time
        ''', (session['user_id'],))
    else:
        appointments = query_db('''
            SELECT a.*, u.name as doctor_name
            FROM appointments a
            JOIN users u ON a.doctor_id = u.id
            WHERE a.patient_id = ? AND a.status = 'scheduled'
            ORDER BY a.appointment_date, a.appointment_time
        ''', (session['user_id'],))
    
    return jsonify([dict(a) for a in appointments] if appointments else [])


@app.route('/api/appointments', methods=['POST'])
@login_required
@role_required('doctor')
def create_appointment():
    """Create a new appointment"""
    data = request.get_json()
    
    patient_id = data.get('patient_id')
    appointment_date = data.get('appointment_date')
    appointment_time = data.get('appointment_time')
    duration = data.get('duration', 30)
    notes = data.get('notes', '')
    
    if not all([patient_id, appointment_date, appointment_time]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    room_id = f"rehab-{session['user_id']}-{patient_id}-{uuid.uuid4().hex[:8]}"
    
    appointment_id = execute_db('''
        INSERT INTO appointments 
        (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (session['user_id'], patient_id, appointment_date, appointment_time, duration, notes, room_id))
    
    return jsonify({
        'success': True,
        'appointment_id': appointment_id,
        'room_id': room_id
    })


@app.route('/api/appointments/<int:appointment_id>', methods=['DELETE'])
@login_required
def cancel_appointment_api(appointment_id):
    """Cancel an appointment"""
    execute_db("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appointment_id,))
    return jsonify({'success': True})


@app.route('/api/appointments/<int:appointment_id>/complete', methods=['POST'])
@login_required
def complete_appointment(appointment_id):
    """Mark appointment as completed"""
    execute_db("UPDATE appointments SET status = 'completed' WHERE id = ?", (appointment_id,))
    
    # Check if this is an API call or form submission
    if request.is_json:
        return jsonify({'success': True})
    else:
        flash('Appointment marked as completed.', 'success')
        return redirect(url_for('consultation'))


@app.route('/api/remove-workout/<int:workout_id>', methods=['POST'])
@login_required
@role_required('doctor')
def remove_workout(workout_id):
    """Remove a workout from patient's plan"""
    execute_db('UPDATE workouts SET is_active = 0 WHERE id = ?', (workout_id,))
    flash('Exercise removed from plan.', 'success')
    return redirect(request.referrer or url_for('plan_editor'))


@app.route('/api/cancel-appointment/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    """Cancel an appointment (form-based)"""
    execute_db("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appointment_id,))
    flash('Appointment cancelled.', 'success')
    return redirect(request.referrer or url_for('consultation'))


# ==================== OPTIMIZATION API (from computer_vision branch) ====================

@app.route('/api/optimize', methods=['POST'])
@login_required
def api_optimize():
    """Run appointment optimization for a single patient."""
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503
    
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
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503
    
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
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503
    
    patients, doctors, timeslots = build_demo_data()
    results = optimize_all_patients(patients, doctors, timeslots)
    return jsonify({"results": results})


@app.route('/api/optimize/consultation', methods=['GET'])
@login_required
def api_optimize_consultation():
    """Return patient list + per-patient optimization results for the
    consultation scheduling page.

    Uses demo data for now. To switch to a custom dataset, swap the
    data source lines below.
    """
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503

    # === DATA SOURCE (swap when custom dataset is ready) ===
    patients, doctors, timeslots = build_demo_data()
    # patients, doctors, timeslots = load_dataset('Optim_dataset/your_dataset.json')

    results = optimize_all_patients(patients, doctors, timeslots)

    patient_list = [
        {"id": p["id"], "label": p["label"], "score": p["score"]}
        for p in patients
    ]

    return jsonify({
        "patients": patient_list,
        "results": results,
    })


@app.route('/api/optimize/patient/<int:patient_id>', methods=['GET'])
@login_required
@role_required('doctor')
def api_optimize_patient(patient_id):
    """Return top 3 optimization suggestions for a specific patient."""
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503

    # Use demo data for now; replace with real data as needed
    patients, doctors, timeslots = build_demo_data()
    # Find the patient in the demo data
    patient = next((p for p in patients if p['id'] == patient_id), None)
    if not patient:
        return jsonify({"error": "Patient not found in optimization data"}), 404

    recs, notification = get_top3_recommendations(
        patient_id=patient_id,
        patients=patients,
        doctors=doctors,
        timeslots=timeslots,
        weights=None
    )
    return jsonify({
        "patient_id": patient_id,
        "recommendations": recs,
        "notification": notification
    })


@app.route('/api/patient/recommendations', methods=['GET'])
@login_required
@role_required('patient')
def api_patient_recommendations():
    """Return optimized doctor/appointment recommendations for the logged-in patient."""
    if not OPTIM_AVAILABLE:
        return jsonify({"error": "Optimization module not available"}), 503

    # Get the logged-in patient's information
    patient_id = session['user_id']

    # Get patient rehab data to determine their optimization patient_id
    patient_data = query_db(
        'SELECT * FROM patients WHERE user_id = ?',
        (patient_id,),
        one=True
    )

    if not patient_data:
        return jsonify({"error": "Patient profile not found"}), 404

    # Use demo data for now (map based on patient condition or use a default)
    # In production, this would map to the actual patient_id in the optimization system
    patients, doctors, timeslots = build_demo_data()

    # For demo: use patient_1 as default (could be enhanced to map based on condition)
    optim_patient_id = "patient_1"  # Default to patient_1 for demo

    # Try to find matching patient in demo data based on rehab score
    rehab_score = patient_data['avg_quality_score']
    if rehab_score < 4.0:
        optim_patient_id = "patient_1"  # Low score patient
    elif rehab_score >= 7.0:
        optim_patient_id = "patient_2"  # High score patient
    else:
        optim_patient_id = "patient_3"  # Medium score patient

    # Get recommendations
    recs, notification = get_top3_recommendations(
        patient_id=optim_patient_id,
        patients=patients,
        doctors=doctors,
        timeslots=timeslots,
        weights=None
    )

    return jsonify({
        "patient_name": patient_data['condition'],
        "recommendations": recs,
        "notification": notification
    })


# ==================== CV/ML LIVE FEEDBACK API (from computer_vision branch) ====================

# Global/session state for CV feedback
SESSION_STATE = {
    "scores": [],
    "threshold": 30.0,
    "cooldown_until": 0
}

@app.route("/api/session/start", methods=["POST"])
def api_session_start():
    """Start a new exercise session for CV tracking"""
    data = request.get_json(force=True) or {}
    SESSION_STATE["scores"] = []
    SESSION_STATE["threshold"] = float(data.get("threshold", 30.0))
    SESSION_STATE["cooldown_until"] = 0
    return jsonify({"ok": True, "threshold": SESSION_STATE["threshold"]})


@app.route("/api/live_feedback", methods=["POST"])
def api_live_feedback():
    """
    Live feedback endpoint for CV/ML exercise analysis.
    Input: { "frame_b64": "data:image/jpeg;base64,...." }
    Output: score + form status + feedback list
    
    Note: Requires CV modules to be installed and configured.
    """
    try:
        # Try to import CV modules
        from cv_utils import decode_dataurl_to_bgr, pose_to_kimore_like_features, model_predict_score, get_llm_feedback
        
        data = request.get_json(force=True)
        frame_b64 = data.get("frame_b64")
        
        if not frame_b64:
            return jsonify({"error": "Missing frame_b64"}), 400

        # 1) decode frame -> np array (BGR)
        frame = decode_dataurl_to_bgr(frame_b64)

        # 2) extract pose -> features
        X = pose_to_kimore_like_features(frame)

        # 3) model predict -> score in 0..50
        score = float(model_predict_score(X))
        SESSION_STATE["scores"].append(score)

        # 4) form status
        status = "CORRECT" if score >= SESSION_STATE["threshold"] else "WRONG"

        # 5) LLM feedback only if wrong
        feedback = []
        if status == "WRONG":
            feedback = get_llm_feedback(frame)

        return jsonify({
            "frame_score": round(score, 2),
            "form_status": status,
            "llm_feedback": feedback
        })
    except ImportError:
        # CV modules not available - return mock response for testing
        return jsonify({
            "frame_score": 35.0,
            "form_status": "CORRECT",
            "llm_feedback": [],
            "warning": "CV modules not installed - returning mock data"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== DATABASE INITIALIZATION ====================

@app.cli.command('init-db')
def init_db_command():
    """CLI command to initialize database: flask init-db"""
    from database import init_db
    init_db(app)
    print('Database initialized!')


def ensure_tables_exist():
    """Create tables if they don't exist (safe - no data loss)"""
    import sqlite3
    conn = sqlite3.connect('rehab_coach.db')
    cursor = conn.cursor()
    
    # Create tables only if they don't exist (preserves existing data)
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('doctor', 'patient', 'caregiver')),
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            condition TEXT NOT NULL,
            surgery_date DATE,
            current_week INTEGER DEFAULT 1,
            adherence_rate REAL DEFAULT 0,
            avg_pain_level REAL DEFAULT 0,
            avg_quality_score REAL DEFAULT 0,
            completed_sessions INTEGER DEFAULT 0,
            streak_days INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS doctor_patient (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            assigned_date DATE DEFAULT CURRENT_DATE,
            FOREIGN KEY (doctor_id) REFERENCES users(id),
            FOREIGN KEY (patient_id) REFERENCES users(id),
            UNIQUE(doctor_id, patient_id)
        );
        
        CREATE TABLE IF NOT EXISTS caregiver_patient (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caregiver_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            relationship TEXT,
            FOREIGN KEY (caregiver_id) REFERENCES users(id),
            FOREIGN KEY (patient_id) REFERENCES users(id),
            UNIQUE(caregiver_id, patient_id)
        );
        
        CREATE TABLE IF NOT EXISTS exercises (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            difficulty INTEGER DEFAULT 1,
            video_url TEXT
        );
        
        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            exercise_id INTEGER NOT NULL,
            sets INTEGER DEFAULT 3,
            reps INTEGER DEFAULT 10,
            frequency TEXT DEFAULT 'Daily',
            instructions TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (exercise_id) REFERENCES exercises(id)
        );
        
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            workout_id INTEGER NOT NULL,
            pain_before INTEGER DEFAULT 0,
            pain_after INTEGER DEFAULT 0,
            effort_level INTEGER DEFAULT 5,
            quality_score REAL DEFAULT 0,
            sets_completed INTEGER DEFAULT 0,
            reps_completed INTEGER DEFAULT 0,
            notes TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (workout_id) REFERENCES workouts(id)
        );
        
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            appointment_date DATE NOT NULL,
            appointment_time TEXT NOT NULL,
            duration INTEGER DEFAULT 30,
            status TEXT DEFAULT 'scheduled',
            notes TEXT,
            room_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES users(id),
            FOREIGN KEY (patient_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    conn.close()


# Ensure tables exist on startup
ensure_tables_exist()


if __name__ == '__main__':
    port = 8000
    # Allow port override via command line argument: python main.py --port 5050
    if '--port' in sys.argv:
        idx = sys.argv.index('--port')
        if idx + 1 < len(sys.argv):
            try:
                port = int(sys.argv[idx + 1])
            except ValueError:
                pass
    app.run(debug=True, host='0.0.0.0', port=port, ssl_context=("cert.pem", "key.pem"))
