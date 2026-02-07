from flask import Flask, render_template, request, redirect, url_for, jsonify
from optim import get_top3_recommendations, optimize_all_patients, build_demo_data, load_dataset

app = Flask(__name__)

# ==================== PATIENT ROUTES ====================

@app.route('/')
def landing():
    """Landing / Login Page"""
    return render_template('landing.html')

@app.route('/patient/dashboard')
def patient_dashboard():
    """Patient Home Dashboard"""
    return render_template('patient/dashboard.html')

@app.route('/patient/session')
def rehab_session():
    """Rehab Session Screen (Core Screen)"""
    return render_template('patient/session.html')

@app.route('/patient/checkin')
def pain_checkin():
    """Pain & Effort Check-In Screen"""
    return render_template('patient/checkin.html')

@app.route('/patient/summary')
def session_summary():
    """Session Summary Screen"""
    return render_template('patient/summary.html')

@app.route('/patient/progress')
def progress_history():
    """Progress & History Screen"""
    return render_template('patient/progress.html')

# ==================== CLINICIAN ROUTES ====================

@app.route('/clinician/dashboard')
def clinician_dashboard():
    """Clinician Dashboard"""
    return render_template('clinician/dashboard.html')

@app.route('/clinician/patient/<patient_id>')
def patient_detail(patient_id):
    """Patient Detail View"""
    return render_template('clinician/patient_detail.html', patient_id=patient_id)

@app.route('/clinician/plan-editor')
def plan_editor():
    """Rehab Plan Editor"""
    return render_template('clinician/plan_editor.html')

@app.route('/clinician/consultation')
def consultation():
    """Consultation & Scheduling Screen"""
    return render_template('clinician/consultation.html')

# ==================== CAREGIVER ROUTES ====================

@app.route('/caregiver/dashboard')
def caregiver_dashboard():
    """Caregiver Dashboard"""
    return render_template('caregiver/dashboard.html')

# ==================== ROLE SELECTION ====================

@app.route('/select-role')
def select_role():
    """Role Selection Screen"""
    return render_template('role_select.html')

# ==================== OPTIMIZATION API ====================

@app.route('/api/optimize', methods=['POST'])
def api_optimize():
    """Run appointment optimization for a single patient.

    Expects JSON body with:
        patient_id (str): ID of the patient to optimize for.
        patients (list[dict]): Patient data.
        doctors (list[dict]): Doctor data.
        timeslots (list[dict]): Timeslot data.
        weights (dict, optional): Objective weights.

    Returns JSON with top-3 recommendations and notification (if any).
    """
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
def api_optimize_all():
    """Run appointment optimization for all patients.

    Expects JSON body with:
        patients (list[dict]): Patient data.
        doctors (list[dict]): Doctor data.
        timeslots (list[dict]): Timeslot data.
        weights (dict, optional): Objective weights.

    Returns JSON with results keyed by patient_id.
    """
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


if __name__ == '__main__':
    app.run(debug=True)