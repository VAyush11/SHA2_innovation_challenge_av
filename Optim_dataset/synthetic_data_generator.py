"""
Synthetic Data Generator for Rehab Appointment Optimization System
Generates realistic test data for patients, doctors, and timeslots
"""

import random
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Seed for reproducibility
random.seed(42)

# Constants
SPECIALTIES = ["MSK", "Post-op", "Neuro", "Sports"]
DAYS_OF_WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIME_SLOTS = ["9:00 AM", "10:00 AM", "11:00 AM", "1:00 PM", "2:00 PM", "3:00 PM", "4:00 PM", "5:00 PM"]

# Realistic NYC-area coordinates (lat, long)
NYC_LOCATIONS = [
    (40.7589, -73.9851),  # Times Square area
    (40.7128, -74.0060),  # Financial District
    (40.7614, -73.9776),  # Central Park South
    (40.7282, -73.7949),  # Queens
    (40.6782, -73.9442),  # Brooklyn
    (40.8448, -73.8648),  # Bronx
    (40.7489, -73.9680),  # Midtown East
    (40.7580, -73.9855),  # Hell's Kitchen
]

DOCTOR_NAMES = [
    "Dr. Sarah Chen",
    "Dr. Mark Johnson", 
    "Dr. Emily Rodriguez",
    "Dr. James Williams",
    "Dr. Lisa Park",
    "Dr. Michael Brown"
]

PATIENT_FIRST_NAMES = [
    "Jane", "John", "Maria", "David", "Sarah", "Michael", 
    "Jennifer", "Robert", "Linda", "William", "Patricia", "James",
    "Elizabeth", "Thomas", "Susan", "Christopher", "Jessica", "Daniel",
    "Nancy", "Matthew"
]

PATIENT_LAST_NAMES = [
    "Doe", "Smith", "Johnson", "Williams", "Brown", "Jones",
    "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez",
    "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor",
    "Moore", "Jackson"
]


def generate_patients(n_patients: int = 20) -> List[Dict[str, Any]]:
    """
    Generate synthetic patient data with realistic variety
    
    Parameters:
    - n_patients: Number of patients to generate (default: 20)
    
    Returns:
    - List of patient dictionaries
    """
    patients = []
    
    # Score distribution: 
    # 20% critical (< 3.0)
    # 30% concerning (3.0 - 5.0)
    # 50% normal (> 5.0)
    
    for i in range(n_patients):
        patient_id = f"patient_{i+1}"
        
        # Determine score category
        rand = random.random()
        if rand < 0.20:  # 20% critical
            score = round(random.uniform(1.0, 2.9), 1)
            urgency = "High"
        elif rand < 0.50:  # 30% concerning
            score = round(random.uniform(3.0, 4.9), 1)
            urgency = "Medium"
        else:  # 50% normal
            score = round(random.uniform(5.0, 9.5), 1)
            urgency = "Low"
        
        # Generate name
        first_name = random.choice(PATIENT_FIRST_NAMES)
        last_name = random.choice(PATIENT_LAST_NAMES)
        name = f"{first_name} {last_name}"
        
        # Random specialty need
        specialty_needed = random.choice(SPECIALTIES)
        
        # Random location
        location = random.choice(NYC_LOCATIONS)
        
        # Max distance based on urgency and score
        if urgency == "High":
            max_distance = random.randint(15, 25)  # Willing to travel farther when critical
        elif urgency == "Medium":
            max_distance = random.randint(10, 18)
        else:
            max_distance = random.randint(5, 15)
        
        # Availability pattern (realistic constraints)
        # 70% available most days, 20% limited availability, 10% very limited
        avail_rand = random.random()
        if avail_rand < 0.70:
            # Available most days, some time preferences
            available_days = random.sample(DAYS_OF_WEEK, k=random.randint(4, 5))
            available_times = random.sample(TIME_SLOTS, k=random.randint(5, 7))
        elif avail_rand < 0.90:
            # Limited availability
            available_days = random.sample(DAYS_OF_WEEK, k=random.randint(2, 3))
            available_times = random.sample(TIME_SLOTS, k=random.randint(3, 5))
        else:
            # Very limited (e.g., working full-time)
            available_days = random.sample(DAYS_OF_WEEK, k=random.randint(1, 2))
            available_times = random.sample(TIME_SLOTS[:2] + TIME_SLOTS[-2:], k=2)  # Morning or evening only
        
        # Time preferences (slight preference for certain times)
        preferred_times = random.sample(available_times, k=min(2, len(available_times)))
        
        patient = {
            "patient_id": patient_id,
            "name": name,
            "score": score,
            "urgency": urgency,
            "specialty_needed": specialty_needed,
            "location": {
                "lat": location[0],
                "long": location[1]
            },
            "max_distance_km": max_distance,
            "available_days": available_days,
            "available_times": available_times,
            "preferred_times": preferred_times
        }
        
        patients.append(patient)
    
    return patients


def generate_doctors(n_doctors: int = 6) -> List[Dict[str, Any]]:
    """
    Generate synthetic doctor data with realistic availability patterns
    
    Parameters:
    - n_doctors: Number of doctors to generate (default: 6)
    
    Returns:
    - List of doctor dictionaries
    """
    doctors = []
    
    for i in range(min(n_doctors, len(DOCTOR_NAMES))):
        doctor_id = f"doctor_{i+1}"
        name = DOCTOR_NAMES[i]
        
        # Each doctor has 1-2 specialties
        n_specialties = random.randint(1, 2)
        specialties = random.sample(SPECIALTIES, k=n_specialties)
        
        # Clinic location
        clinic_location = random.choice(NYC_LOCATIONS)
        clinic_names = [
            "Manhattan Rehab Center",
            "West Side PT Clinic", 
            "Brooklyn Sports Medicine",
            "Queens Physical Therapy",
            "Midtown Wellness Center",
            "Downtown Recovery Institute"
        ]
        clinic_name = random.choice(clinic_names)
        
        # Availability pattern
        # 60% full-time (4-5 days), 40% part-time (2-3 days)
        if random.random() < 0.60:
            available_days = random.sample(DAYS_OF_WEEK, k=random.randint(4, 5))
            available_times = TIME_SLOTS  # All time slots
        else:
            available_days = random.sample(DAYS_OF_WEEK, k=random.randint(2, 3))
            # Part-time might only work certain hours
            start_idx = random.randint(0, len(TIME_SLOTS) - 4)
            available_times = TIME_SLOTS[start_idx:start_idx + 4]
        
        doctor = {
            "doctor_id": doctor_id,
            "name": name,
            "specialties": specialties,
            "clinic_name": clinic_name,
            "clinic_location": {
                "lat": clinic_location[0],
                "long": clinic_location[1]
            },
            "available_days": available_days,
            "available_times": available_times
        }
        
        doctors.append(doctor)
    
    return doctors


def generate_timeslots(days: int = 5) -> List[Dict[str, Any]]:
    """
    Generate timeslot data for next N days
    
    Parameters:
    - days: Number of days to generate (default: 5 for work week)
    
    Returns:
    - List of timeslot dictionaries
    """
    timeslots = []
    start_date = datetime.now().date() + timedelta(days=1)  # Start tomorrow
    
    slot_id = 1
    for day_offset in range(days):
        current_date = start_date + timedelta(days=day_offset)
        day_name = DAYS_OF_WEEK[day_offset % 5]  # Wrap around for work week
        
        for time in TIME_SLOTS:
            timeslot = {
                "timeslot_id": f"slot_{slot_id}",
                "day": day_name,
                "time": time,
                "date": current_date.strftime("%Y-%m-%d"),
                "datetime": f"{current_date.strftime('%Y-%m-%d')} {time}"
            }
            timeslots.append(timeslot)
            slot_id += 1
    
    return timeslots


def generate_continuity_relationships(
    patients: List[Dict], 
    doctors: List[Dict], 
    probability: float = 0.25
) -> Dict[str, List[str]]:
    """
    Generate patient-doctor continuity relationships (previous interactions)
    
    Parameters:
    - patients: List of patient dictionaries
    - doctors: List of doctor dictionaries
    - probability: Probability that a patient has seen a specific doctor (default: 0.25)
    
    Returns:
    - Dictionary mapping patient_id to list of doctor_ids they've seen before
    """
    continuity = {}
    
    for patient in patients:
        # Each patient has seen 0-2 doctors before
        has_history = random.random() < 0.60  # 60% of patients have continuity
        
        if has_history:
            # Filter doctors by matching specialty
            matching_doctors = [
                d for d in doctors 
                if patient["specialty_needed"] in d["specialties"]
            ]
            
            if matching_doctors:
                n_previous = random.randint(1, min(2, len(matching_doctors)))
                previous_doctors = random.sample(matching_doctors, k=n_previous)
                continuity[patient["patient_id"]] = [d["doctor_id"] for d in previous_doctors]
            else:
                continuity[patient["patient_id"]] = []
        else:
            continuity[patient["patient_id"]] = []
    
    return continuity


def calculate_distance(loc1: Dict, loc2: Dict) -> float:
    """
    Calculate approximate distance between two lat/long coordinates in km
    Using simplified Euclidean approximation (good enough for demo)
    
    Parameters:
    - loc1: Dictionary with 'lat' and 'long' keys
    - loc2: Dictionary with 'lat' and 'long' keys
    
    Returns:
    - Distance in kilometers
    """
    # Rough approximation: 1 degree ≈ 111 km at this latitude
    lat_diff = (loc1["lat"] - loc2["lat"]) * 111
    long_diff = (loc1["long"] - loc2["long"]) * 85  # Adjusted for NYC latitude
    
    distance = (lat_diff**2 + long_diff**2)**0.5
    return round(distance, 1)


def generate_distance_matrix(patients: List[Dict], doctors: List[Dict]) -> Dict[str, Dict[str, float]]:
    """
    Generate distance matrix between all patients and doctor clinics
    
    Parameters:
    - patients: List of patient dictionaries
    - doctors: List of doctor dictionaries
    
    Returns:
    - Nested dictionary: distances[patient_id][doctor_id] = distance_km
    """
    distances = {}
    
    for patient in patients:
        distances[patient["patient_id"]] = {}
        for doctor in doctors:
            dist = calculate_distance(patient["location"], doctor["clinic_location"])
            distances[patient["patient_id"]][doctor["doctor_id"]] = dist
    
    return distances


def generate_complete_dataset(
    n_patients: int = 20,
    n_doctors: int = 6,
    n_days: int = 5
) -> Dict[str, Any]:
    """
    Generate complete synthetic dataset with all relationships
    
    Parameters:
    - n_patients: Number of patients to generate
    - n_doctors: Number of doctors to generate
    - n_days: Number of days for timeslots
    
    Returns:
    - Dictionary containing all generated data
    """
    print(f"Generating synthetic data...")
    print(f"  - {n_patients} patients")
    print(f"  - {n_doctors} doctors")
    print(f"  - {n_days} days of timeslots")
    
    patients = generate_patients(n_patients)
    doctors = generate_doctors(n_doctors)
    timeslots = generate_timeslots(n_days)
    continuity = generate_continuity_relationships(patients, doctors)
    distances = generate_distance_matrix(patients, doctors)
    
    # Calculate statistics
    critical_count = sum(1 for p in patients if p["urgency"] == "High")
    concerning_count = sum(1 for p in patients if p["urgency"] == "Medium")
    normal_count = sum(1 for p in patients if p["urgency"] == "Low")
    
    dataset = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "n_patients": len(patients),
            "n_doctors": len(doctors),
            "n_timeslots": len(timeslots),
            "patient_distribution": {
                "critical": critical_count,
                "concerning": concerning_count,
                "normal": normal_count
            }
        },
        "patients": patients,
        "doctors": doctors,
        "timeslots": timeslots,
        "continuity_relationships": continuity,
        "distance_matrix": distances
    }
    
    print(f"\n✅ Data generation complete!")
    print(f"   Critical patients: {critical_count}")
    print(f"   Concerning patients: {concerning_count}")
    print(f"   Normal patients: {normal_count}")
    print(f"   Total timeslots: {len(timeslots)}")
    
    return dataset


def save_dataset(dataset: Dict[str, Any], filename: str = "synthetic_data.json"):
    """
    Save dataset to JSON file
    
    Parameters:
    - dataset: Generated dataset dictionary
    - filename: Output filename
    """
    with open(filename, 'w') as f:
        json.dump(dataset, f, indent=2)
    print(f"\n💾 Dataset saved to {filename}")


def generate_test_scenarios() -> Dict[str, Dict[str, Any]]:
    """
    Generate specific test scenarios for edge cases
    
    Returns:
    - Dictionary of test scenario names to datasets
    """
    scenarios = {}
    
    # Scenario 1: High demand, limited capacity
    scenarios["high_demand"] = generate_complete_dataset(
        n_patients=30,
        n_doctors=4,
        n_days=3
    )
    
    # Scenario 2: Many critical patients
    patients_critical = generate_patients(10)
    # Force all to be critical
    for p in patients_critical:
        p["score"] = round(random.uniform(1.0, 2.9), 1)
        p["urgency"] = "High"
    
    scenarios["all_critical"] = {
        "metadata": {"scenario": "All critical patients"},
        "patients": patients_critical,
        "doctors": generate_doctors(6),
        "timeslots": generate_timeslots(5),
        "continuity_relationships": generate_continuity_relationships(patients_critical, generate_doctors(6)),
        "distance_matrix": generate_distance_matrix(patients_critical, generate_doctors(6))
    }
    
    # Scenario 3: Limited availability (everyone has conflicts)
    patients_limited = generate_patients(15)
    for p in patients_limited:
        p["available_days"] = random.sample(DAYS_OF_WEEK, k=2)  # Only 2 days available
        p["available_times"] = random.sample(TIME_SLOTS, k=2)  # Only 2 times
    
    scenarios["limited_availability"] = {
        "metadata": {"scenario": "Limited patient availability"},
        "patients": patients_limited,
        "doctors": generate_doctors(5),
        "timeslots": generate_timeslots(5),
        "continuity_relationships": generate_continuity_relationships(patients_limited, generate_doctors(5)),
        "distance_matrix": generate_distance_matrix(patients_limited, generate_doctors(5))
    }
    
    # Scenario 4: Remote patients (high distance)
    patients_remote = generate_patients(12)
    for p in patients_remote:
        p["location"] = {
            "lat": 40.7128 + random.uniform(-0.3, 0.3),  # Spread out more
            "long": -74.0060 + random.uniform(-0.3, 0.3)
        }
        p["max_distance_km"] = random.randint(20, 35)  # Willing to travel far
    
    doctors_remote = generate_doctors(5)
    scenarios["remote_patients"] = {
        "metadata": {"scenario": "Geographically dispersed patients"},
        "patients": patients_remote,
        "doctors": doctors_remote,
        "timeslots": generate_timeslots(5),
        "continuity_relationships": generate_continuity_relationships(patients_remote, doctors_remote),
        "distance_matrix": generate_distance_matrix(patients_remote, doctors_remote)
    }
    
    return scenarios


if __name__ == "__main__":
    # Generate main dataset
    print("=" * 60)
    print("SYNTHETIC DATA GENERATOR FOR REHAB OPTIMIZATION")
    print("=" * 60)
    
    dataset = generate_complete_dataset(
        n_patients=20,
        n_doctors=6,
        n_days=5
    )
    
    save_dataset(dataset, "synthetic_data_main.json")
    
    # Generate test scenarios
    print("\n" + "=" * 60)
    print("GENERATING TEST SCENARIOS")
    print("=" * 60)
    
    scenarios = generate_test_scenarios()
    
    for scenario_name, scenario_data in scenarios.items():
        filename = f"synthetic_data_{scenario_name}.json"
        save_dataset(scenario_data, filename)
    
    # Print sample data
    print("\n" + "=" * 60)
    print("SAMPLE DATA PREVIEW")
    print("=" * 60)
    
    print("\n📋 Sample Patient:")
    print(json.dumps(dataset["patients"][0], indent=2))
    
    print("\n👨‍⚕️ Sample Doctor:")
    print(json.dumps(dataset["doctors"][0], indent=2))
    
    print("\n🕐 Sample Timeslot:")
    print(json.dumps(dataset["timeslots"][0], indent=2))
    
    print("\n🔗 Sample Continuity Relationship:")
    sample_patient_id = list(dataset["continuity_relationships"].keys())[0]
    print(f"{sample_patient_id}: {dataset['continuity_relationships'][sample_patient_id]}")
    
    print("\n📏 Sample Distance:")
    sample_patient_id = list(dataset["distance_matrix"].keys())[0]
    sample_doctor_id = list(dataset["distance_matrix"][sample_patient_id].keys())[0]
    print(f"{sample_patient_id} to {sample_doctor_id}: {dataset['distance_matrix'][sample_patient_id][sample_doctor_id]} km")
    
    print("\n" + "=" * 60)
    print("✅ ALL FILES GENERATED SUCCESSFULLY")
    print("=" * 60)
    print("\nGenerated files:")
    print("  - synthetic_data_main.json")
    print("  - synthetic_data_high_demand.json")
    print("  - synthetic_data_all_critical.json")
    print("  - synthetic_data_limited_availability.json")
    print("  - synthetic_data_remote_patients.json")
