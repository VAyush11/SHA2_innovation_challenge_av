"""
Data Adapter for Optimization System
Converts synthetic JSON data into the format expected by optim.py
"""

import json
from typing import Dict, List, Any, Tuple


def load_synthetic_data(filename: str = "synthetic_data_main.json") -> Dict[str, Any]:
    """Load synthetic data from JSON file"""
    with open(filename, 'r') as f:
        return json.load(f)


def convert_to_optim_format(synthetic_data: Dict[str, Any]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Convert synthetic data to the format expected by optim.py
    
    Parameters:
    - synthetic_data: Raw synthetic data dictionary
    
    Returns:
    - Tuple of (patients_list, doctors_list, timeslots_list) in optim.py format
    """
    
    # Extract raw data
    raw_patients = synthetic_data["patients"]
    raw_doctors = synthetic_data["doctors"]
    raw_timeslots = synthetic_data["timeslots"]
    continuity = synthetic_data["continuity_relationships"]
    distances = synthetic_data["distance_matrix"]
    
    # Convert patients
    patients = []
    for p in raw_patients:
        # Build availability dictionary: {(day, time): True/False}
        availability = {}
        for slot in raw_timeslots:
            day = slot["day"]
            time = slot["time"]
            is_available = (day in p["available_days"]) and (time in p["available_times"])
            availability[(day, time)] = is_available
        
        # Build time preferences: {(day, time): preference_score}
        time_prefs = {}
        for slot in raw_timeslots:
            day = slot["day"]
            time = slot["time"]
            if time in p["preferred_times"]:
                time_prefs[(day, time)] = 1.0  # Strong preference
            elif (day in p["available_days"]) and (time in p["available_times"]):
                time_prefs[(day, time)] = 0.5  # Neutral
            else:
                time_prefs[(day, time)] = 0.0  # Not available
        
        # Get continuity doctors for this patient
        continuity_doctors = continuity.get(p["patient_id"], [])
        
        patient = {
            "patient_id": p["patient_id"],
            "name": p["name"],
            "score": p["score"],
            "urgency": p["urgency"],
            "specialty_needed": p["specialty_needed"],
            "location": p["location"],
            "max_distance": p["max_distance_km"],
            "availability": availability,
            "time_preferences": time_prefs,
            "continuity_doctors": continuity_doctors
        }
        patients.append(patient)
    
    # Convert doctors
    doctors = []
    for d in raw_doctors:
        # Build availability dictionary
        availability = {}
        for slot in raw_timeslots:
            day = slot["day"]
            time = slot["time"]
            is_available = (day in d["available_days"]) and (time in d["available_times"])
            availability[(day, time)] = is_available
        
        doctor = {
            "doctor_id": d["doctor_id"],
            "name": d["name"],
            "specialties": d["specialties"],
            "clinic_name": d["clinic_name"],
            "location": d["clinic_location"],
            "availability": availability
        }
        doctors.append(doctor)
    
    # Convert timeslots (simple mapping)
    timeslots = []
    for t in raw_timeslots:
        timeslot = {
            "timeslot_id": t["timeslot_id"],
            "day": t["day"],
            "time": t["time"],
            "date": t["date"],
            "datetime": t["datetime"]
        }
        timeslots.append(timeslot)
    
    # Add distance information to patients (for quick lookup)
    for patient in patients:
        patient["distances"] = {}
        patient_id = patient["patient_id"]
        for doctor in doctors:
            doctor_id = doctor["doctor_id"]
            patient["distances"][doctor_id] = distances[patient_id][doctor_id]
    
    return patients, doctors, timeslots


def format_for_api(patients: List[Dict], doctors: List[Dict], timeslots: List[Dict]) -> Dict[str, Any]:
    """
    Format converted data for Flask API endpoints
    
    Parameters:
    - patients, doctors, timeslots: Output from convert_to_optim_format()
    
    Returns:
    - Dictionary ready for POST to /api/optimize or /api/optimize/all
    """
    return {
        "patients": patients,
        "doctors": doctors,
        "timeslots": timeslots
    }


def print_data_summary(patients: List[Dict], doctors: List[Dict], timeslots: List[Dict]):
    """Print summary statistics of the converted data"""
    print("\n" + "=" * 60)
    print("DATA SUMMARY")
    print("=" * 60)
    
    # Patient statistics
    critical = sum(1 for p in patients if p["urgency"] == "High")
    concerning = sum(1 for p in patients if p["urgency"] == "Medium")
    normal = sum(1 for p in patients if p["urgency"] == "Low")
    
    avg_score = sum(p["score"] for p in patients) / len(patients)
    
    print(f"\n📋 Patients: {len(patients)}")
    print(f"   - Critical (urgency=High): {critical}")
    print(f"   - Concerning (urgency=Medium): {concerning}")
    print(f"   - Normal (urgency=Low): {normal}")
    print(f"   - Average rehab score: {avg_score:.2f}")
    
    # Specialty distribution
    specialty_needs = {}
    for p in patients:
        spec = p["specialty_needed"]
        specialty_needs[spec] = specialty_needs.get(spec, 0) + 1
    
    print(f"\n   Specialty needs:")
    for spec, count in specialty_needs.items():
        print(f"     - {spec}: {count}")
    
    # Doctor statistics
    print(f"\n👨‍⚕️ Doctors: {len(doctors)}")
    
    specialty_supply = {}
    for d in doctors:
        for spec in d["specialties"]:
            specialty_supply[spec] = specialty_supply.get(spec, 0) + 1
    
    print(f"   Specialty coverage:")
    for spec, count in specialty_supply.items():
        print(f"     - {spec}: {count} doctors")
    
    # Availability statistics
    total_patient_slots = sum(sum(1 for avail in p["availability"].values() if avail) for p in patients)
    avg_patient_avail = total_patient_slots / len(patients)
    
    total_doctor_slots = sum(sum(1 for avail in d["availability"].values() if avail) for d in doctors)
    avg_doctor_avail = total_doctor_slots / len(doctors)
    
    print(f"\n🕐 Timeslots: {len(timeslots)}")
    print(f"   - Average patient availability: {avg_patient_avail:.1f} slots")
    print(f"   - Average doctor availability: {avg_doctor_avail:.1f} slots")
    print(f"   - Total capacity: {total_doctor_slots} appointments")
    
    # Continuity statistics
    patients_with_continuity = sum(1 for p in patients if len(p["continuity_doctors"]) > 0)
    total_continuity_relationships = sum(len(p["continuity_doctors"]) for p in patients)
    
    print(f"\n🔗 Continuity of Care:")
    print(f"   - Patients with history: {patients_with_continuity}")
    print(f"   - Total relationships: {total_continuity_relationships}")
    
    # Distance statistics
    all_distances = []
    for p in patients:
        all_distances.extend(p["distances"].values())
    
    avg_distance = sum(all_distances) / len(all_distances)
    min_distance = min(all_distances)
    max_distance = max(all_distances)
    
    print(f"\n📏 Distance Statistics:")
    print(f"   - Average distance: {avg_distance:.1f} km")
    print(f"   - Min distance: {min_distance:.1f} km")
    print(f"   - Max distance: {max_distance:.1f} km")
    
    # Supply-demand analysis
    print(f"\n⚖️ Supply-Demand Analysis:")
    for spec in specialty_needs.keys():
        demand = specialty_needs[spec]
        supply = specialty_supply.get(spec, 0)
        ratio = supply / demand if demand > 0 else 0
        print(f"   - {spec}: {supply} doctors / {demand} patients (ratio: {ratio:.2f})")


def print_sample_patient(patient: Dict):
    """Print detailed view of a sample patient"""
    print("\n" + "=" * 60)
    print(f"SAMPLE PATIENT: {patient['name']} ({patient['patient_id']})")
    print("=" * 60)
    
    print(f"\n📊 Clinical Info:")
    print(f"   - Rehab score: {patient['score']}")
    print(f"   - Urgency: {patient['urgency']}")
    print(f"   - Specialty needed: {patient['specialty_needed']}")
    
    print(f"\n📍 Location:")
    print(f"   - Coordinates: ({patient['location']['lat']:.4f}, {patient['location']['long']:.4f})")
    print(f"   - Max travel distance: {patient['max_distance']} km")
    
    print(f"\n🕐 Availability:")
    available_slots = [k for k, v in patient['availability'].items() if v]
    print(f"   - Available timeslots: {len(available_slots)} out of {len(patient['availability'])}")
    print(f"   - Sample slots: {available_slots[:5]}")
    
    preferred_slots = [(k, v) for k, v in patient['time_preferences'].items() if v == 1.0]
    print(f"   - Preferred times: {len(preferred_slots)}")
    
    print(f"\n🔗 Continuity:")
    print(f"   - Previously seen doctors: {patient['continuity_doctors']}")
    
    print(f"\n📏 Distances to clinics:")
    sorted_distances = sorted(patient['distances'].items(), key=lambda x: x[1])
    for doctor_id, dist in sorted_distances[:5]:
        print(f"   - {doctor_id}: {dist:.1f} km")


def save_converted_data(patients: List[Dict], doctors: List[Dict], timeslots: List[Dict], 
                       filename: str = "converted_data.json"):
    """Save converted data to JSON file"""
    
    # Convert tuple keys to strings for JSON serialization
    patients_serializable = []
    for p in patients:
        p_copy = p.copy()
        # Convert availability dict with tuple keys to string keys
        p_copy["availability"] = {f"{k[0]}_{k[1]}": v for k, v in p["availability"].items()}
        p_copy["time_preferences"] = {f"{k[0]}_{k[1]}": v for k, v in p["time_preferences"].items()}
        patients_serializable.append(p_copy)
    
    doctors_serializable = []
    for d in doctors:
        d_copy = d.copy()
        d_copy["availability"] = {f"{k[0]}_{k[1]}": v for k, v in d["availability"].items()}
        doctors_serializable.append(d_copy)
    
    data = {
        "patients": patients_serializable,
        "doctors": doctors_serializable,
        "timeslots": timeslots
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n💾 Converted data saved to {filename}")


if __name__ == "__main__":
    print("=" * 60)
    print("SYNTHETIC DATA ADAPTER")
    print("=" * 60)
    
    # Load and convert main dataset
    print("\nLoading synthetic_data_main.json...")
    raw_data = load_synthetic_data("synthetic_data_main.json")
    
    print("Converting to optimization format...")
    patients, doctors, timeslots = convert_to_optim_format(raw_data)
    
    # Print summary
    print_data_summary(patients, doctors, timeslots)
    
    # Print sample patient
    if patients:
        # Find a critical patient for the sample
        critical_patients = [p for p in patients if p["urgency"] == "High"]
        sample_patient = critical_patients[0] if critical_patients else patients[0]
        print_sample_patient(sample_patient)
    
    # Save converted data
    save_converted_data(patients, doctors, timeslots, "converted_data_main.json")
    
    # Convert all test scenarios
    print("\n" + "=" * 60)
    print("CONVERTING TEST SCENARIOS")
    print("=" * 60)
    
    scenarios = [
        "high_demand",
        "all_critical",
        "limited_availability",
        "remote_patients"
    ]
    
    for scenario in scenarios:
        input_file = f"synthetic_data_{scenario}.json"
        output_file = f"converted_data_{scenario}.json"
        
        print(f"\nConverting {input_file}...")
        raw_data = load_synthetic_data(input_file)
        patients, doctors, timeslots = convert_to_optim_format(raw_data)
        save_converted_data(patients, doctors, timeslots, output_file)
        print(f"   ✅ {len(patients)} patients, {len(doctors)} doctors, {len(timeslots)} timeslots")
    
    print("\n" + "=" * 60)
    print("✅ ALL CONVERSIONS COMPLETE")
    print("=" * 60)
    print("\nGenerated files:")
    print("  - converted_data_main.json")
    print("  - converted_data_high_demand.json")
    print("  - converted_data_all_critical.json")
    print("  - converted_data_limited_availability.json")
    print("  - converted_data_remote_patients.json")
