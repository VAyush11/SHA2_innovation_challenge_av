from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask import request, jsonify
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

# ==================== PATIENT ROUTES ====================

@app.route('/')
def landing():
    """Landing / Login Page"""
    return render_template('landing.html')

@app.route('/patient/dashboard')
@login_required
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
    return render_template('patient/checkin.html')

@app.route('/patient/summary')
@login_required
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

# ==================== CLINICIAN ROUTES ====================

@app.route('/clinician/dashboard')
@login_required
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

@app.route('/caregiver/dashboard')
@login_required
def caregiver_dashboard():
    """Caregiver Dashboard"""
    if current_user.role != 'caregiver':
        return redirect(url_for('landing'))
    return render_template('caregiver/dashboard.html')

# ==================== ROLE SELECTION ====================

@app.route('/select-role')
def select_role():
    """Role Selection Screen"""
    return render_template('role_select.html')

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

# Global/session state (simple demo)
SESSION_STATE = {
  "scores": [],
  "threshold": 30.0,
  "cooldown_until": 0
}

@app.route("/api/session/start", methods=["POST"])
def api_session_start():
    data = request.get_json(force=True) or {}
    SESSION_STATE["scores"] = []
    SESSION_STATE["threshold"] = float(data.get("threshold", 30.0))
    SESSION_STATE["cooldown_until"] = 0
    return jsonify({"ok": True, "threshold": SESSION_STATE["threshold"]})

@app.route("/api/live_feedback", methods=["POST"])
def api_live_feedback():
    """
    Input: { "frame_b64": "data:image/jpeg;base64,...." }
    Output: score + form status + feedback list
    """
    data = request.get_json(force=True)
    frame_b64 = data["frame_b64"]

    # 1) decode frame -> np array (BGR)
    frame = decode_dataurl_to_bgr(frame_b64)

    # 2) extract pose -> (100,100) (or your expected shape)
    X = pose_to_kimore_like_features(frame)   # your function

    # 3) model predict -> score in 0..50
    score = float(model_predict_score(X))     # your function
    SESSION_STATE["scores"].append(score)

    # 4) form status
    status = "CORRECT" if score >= SESSION_STATE["threshold"] else "WRONG"

    # 5) LLM feedback only if wrong (and optionally cooldown)
    feedback = []
    if status == "WRONG":
        feedback = get_llm_feedback(frame)  # returns list[str]

    return jsonify({
        "frame_score": round(score, 2),
        "form_status": status,
        "llm_feedback": feedback
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
        print(f"Database location: {os.path.join(basedir, 'instance', 'rehab_app.db')}")
    
    app.run(debug=True)