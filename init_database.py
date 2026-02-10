"""
init_database.py - Initialize the database with proper schema and test data
Run this ONLY ONCE to set up the database, or with --reset flag to wipe and recreate
"""

import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

# Check if database already exists
if os.path.exists('rehab_coach.db'):
    if '--reset' in sys.argv:
        os.remove('rehab_coach.db')
        print("Removed old database (--reset flag used)")
    else:
        print("⚠️  Database already exists!")
        print("   Your data is safe. To wipe and recreate, run:")
        print("   python3 init_database.py --reset")
        print("")
        print("   To just start the app, run:")
        print("   python3 main.py")
        sys.exit(0)

conn = sqlite3.connect('rehab_coach.db')
cursor = conn.cursor()

# Create all tables
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
print("✅ Database tables created!")

# Add sample data
# Create a doctor
cursor.execute('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
    ('doctor@test.com', generate_password_hash('password123'), 'Dr. Smith', 'doctor'))
doctor_id = cursor.lastrowid
print(f"Created doctor with ID: {doctor_id}")

# Create a patient
cursor.execute('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
    ('patient@test.com', generate_password_hash('password123'), 'John Patient', 'patient'))
patient_id = cursor.lastrowid
print(f"Created patient with ID: {patient_id}")

# Create patient record
cursor.execute('INSERT INTO patients (user_id, condition, adherence_rate, avg_pain_level, avg_quality_score) VALUES (?, ?, ?, ?, ?)',
    (patient_id, 'Knee Replacement', 75, 4, 82))

# Assign patient to doctor
cursor.execute('INSERT INTO doctor_patient (doctor_id, patient_id) VALUES (?, ?)',
    (doctor_id, patient_id))

# Add sample exercises
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Knee Extension', 'Straighten your leg while seated', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Quad Sets', 'Tighten thigh muscles while leg is straight', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Heel Slides', 'Slide heel toward buttocks while lying down', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Straight Leg Raises', 'Lift straight leg while lying down', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Ankle Pumps', 'Move ankle up and down', 'Ankle'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Hip Flexor Stretch', 'Stretch hip flexors for mobility', 'Hip'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Hamstring Curl', 'Curl heel toward buttocks while standing', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Wall Slides', 'Squat against wall with back supported', 'Knee'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Calf Raises', 'Rise onto toes while standing', 'Ankle'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Shoulder Rotation', 'Rotate shoulder in circular motion', 'Shoulder'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Arm Raises', 'Lift arms overhead slowly', 'Shoulder'))
cursor.execute('INSERT INTO exercises (name, description, category) VALUES (?, ?, ?)',
    ('Back Extension', 'Gently arch back while lying face down', 'Back'))

# Assign some workouts to patient
cursor.execute('INSERT INTO workouts (patient_id, exercise_id, sets, reps, frequency, instructions) VALUES (?, ?, ?, ?, ?, ?)',
    (patient_id, 1, 3, 10, 'Daily', 'Keep back straight. Stop if pain exceeds 4/10.'))
cursor.execute('INSERT INTO workouts (patient_id, exercise_id, sets, reps, frequency, instructions) VALUES (?, ?, ?, ?, ?, ?)',
    (patient_id, 2, 3, 15, 'Daily', 'Hold for 5 seconds each rep.'))
cursor.execute('INSERT INTO workouts (patient_id, exercise_id, sets, reps, frequency, instructions) VALUES (?, ?, ?, ?, ?, ?)',
    (patient_id, 3, 2, 10, '3x per week', 'Move slowly and controlled.'))

# Add a sample upcoming appointment
import uuid
room_id = f"rehab-{doctor_id}-{patient_id}-{uuid.uuid4().hex[:8]}"
cursor.execute('''INSERT INTO appointments 
    (doctor_id, patient_id, appointment_date, appointment_time, duration, notes, room_id, status) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
    (doctor_id, patient_id, '2026-02-15', '10:00', 30, 'Weekly check-in', room_id, 'scheduled'))

# Create a caregiver
cursor.execute('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
    ('caregiver@test.com', generate_password_hash('password123'), 'Jane Caregiver', 'caregiver'))
caregiver_id = cursor.lastrowid

# Link caregiver to patient
cursor.execute('INSERT INTO caregiver_patient (caregiver_id, patient_id, relationship) VALUES (?, ?, ?)',
    (caregiver_id, patient_id, 'Spouse'))

conn.commit()
conn.close()

print("\n" + "="*50)
print("✅ Database initialized successfully!")
print("="*50)
print("\n📋 Test Accounts Created:")
print("-" * 30)
print("👨‍⚕️ Doctor:    doctor@test.com / password123")
print("🧑‍🦽 Patient:   patient@test.com / password123")
print("👨‍👩‍👧 Caregiver: caregiver@test.com / password123")
print("-" * 30)
print("\nNow run: python3 main.py")
