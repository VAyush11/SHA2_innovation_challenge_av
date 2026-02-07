"""
Demo Script: Using Synthetic Data with Optimization System

This script demonstrates how to:
1. Load synthetic data
2. Run optimization for different scenarios
3. Analyze and visualize results
"""

import json
from typing import Dict, List, Any
from data_adapter import load_synthetic_data, convert_to_optim_format


def load_converted_data(filename: str = "converted_data_main.json") -> Dict[str, Any]:
    """Load converted data that's ready for optimization"""
    with open(filename, 'r') as f:
        return json.load(f)


def restore_tuple_keys(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Restore tuple keys from string format for use with optim.py
    Converts "Monday_9:00 AM" back to ("Monday", "9:00 AM")
    """
    
    # Restore patients
    for patient in data["patients"]:
        # Restore availability dict
        availability = {}
        for key_str, value in patient["availability"].items():
            day, time = key_str.split("_", 1)
            availability[(day, time)] = value
        patient["availability"] = availability
        
        # Restore time_preferences dict
        time_prefs = {}
        for key_str, value in patient["time_preferences"].items():
            day, time = key_str.split("_", 1)
            time_prefs[(day, time)] = value
        patient["time_preferences"] = time_prefs
    
    # Restore doctors
    for doctor in data["doctors"]:
        availability = {}
        for key_str, value in doctor["availability"].items():
            day, time = key_str.split("_", 1)
            availability[(day, time)] = value
        doctor["availability"] = availability
    
    return data


def print_optimization_input_summary(patients: List[Dict], doctors: List[Dict], timeslots: List[Dict]):
    """Print summary of data being fed to optimizer"""
    print("\n" + "="*60)
    print("OPTIMIZATION INPUT SUMMARY")
    print("="*60)
    
    print(f"\n📊 Problem Size:")
    print(f"   - Patients to assign: {len(patients)}")
    print(f"   - Doctors available: {len(doctors)}")
    print(f"   - Timeslots to choose from: {len(timeslots)}")
    print(f"   - Decision variables: {len(patients) * len(doctors) * len(timeslots)}")
    
    # Urgency distribution
    urgent_patients = [p for p in patients if p["urgency"] == "High"]
    print(f"\n🚨 Urgent Patients: {len(urgent_patients)}")
    for p in urgent_patients:
        print(f"   - {p['name']}: score={p['score']}, needs {p['specialty_needed']}")
    
    # Specialty mismatch analysis
    print(f"\n⚖️ Specialty Supply-Demand:")
    specialty_demand = {}
    for p in patients:
        spec = p["specialty_needed"]
        specialty_demand[spec] = specialty_demand.get(spec, 0) + 1
    
    specialty_supply = {}
    for d in doctors:
        for spec in d["specialties"]:
            specialty_supply[spec] = specialty_supply.get(spec, 0) + 1
    
    all_specs = set(specialty_demand.keys()) | set(specialty_supply.keys())
    for spec in sorted(all_specs):
        demand = specialty_demand.get(spec, 0)
        supply = specialty_supply.get(spec, 0)
        status = "✅" if supply >= demand else "⚠️"
        print(f"   {status} {spec}: {supply} doctors for {demand} patients")


def print_optimization_results(results: Dict[str, Any]):
    """Print formatted optimization results"""
    print("\n" + "="*60)
    print("OPTIMIZATION RESULTS")
    print("="*60)
    
    for patient_id, recommendations in results.items():
        patient_data = recommendations["patient"]
        
        status_emoji = "🚨" if patient_data["urgency"] == "High" else "⚠️" if patient_data["urgency"] == "Medium" else "✅"
        
        print(f"\n{status_emoji} {patient_data['name']} (score: {patient_data['score']}, {patient_data['urgency']} urgency)")
        
        if recommendations["recommendations"]:
            for i, rec in enumerate(recommendations["recommendations"], 1):
                score_bar = "█" * int(rec["score"] * 10)
                print(f"   {i}. {rec['doctor']} @ {rec['day']} {rec['time']}")
                print(f"      Distance: {rec['distance']:.1f}km | Score: {score_bar} {rec['score']:.2f}")
        else:
            print(f"   ❌ No suitable appointments found")


def analyze_solution_quality(results: Dict[str, Any]):
    """Analyze quality metrics of the optimization solution"""
    print("\n" + "="*60)
    print("SOLUTION QUALITY METRICS")
    print("="*60)
    
    total_patients = len(results)
    assigned_patients = sum(1 for r in results.values() if r["recommendations"])
    
    print(f"\n📈 Assignment Rate: {assigned_patients}/{total_patients} ({assigned_patients/total_patients*100:.1f}%)")
    
    # Urgent patient assignment
    urgent_results = {k: v for k, v in results.items() if v["patient"]["urgency"] == "High"}
    urgent_assigned = sum(1 for r in urgent_results.values() if r["recommendations"])
    
    print(f"🚨 Urgent Assignment Rate: {urgent_assigned}/{len(urgent_results)} ({urgent_assigned/len(urgent_results)*100:.1f}%)")
    
    # Average scores
    all_scores = []
    for r in results.values():
        if r["recommendations"]:
            all_scores.append(r["recommendations"][0]["score"])  # Top recommendation score
    
    if all_scores:
        avg_score = sum(all_scores) / len(all_scores)
        min_score = min(all_scores)
        max_score = max(all_scores)
        
        print(f"\n⭐ Recommendation Quality:")
        print(f"   - Average score: {avg_score:.3f}")
        print(f"   - Min score: {min_score:.3f}")
        print(f"   - Max score: {max_score:.3f}")
    
    # Average distance
    all_distances = []
    for r in results.values():
        if r["recommendations"]:
            all_distances.append(r["recommendations"][0]["distance"])
    
    if all_distances:
        avg_dist = sum(all_distances) / len(all_distances)
        print(f"\n📏 Average Travel Distance: {avg_dist:.1f} km")
    
    # Continuity preservation
    continuity_preserved = 0
    continuity_possible = 0
    for r in results.values():
        if r["patient"]["continuity_doctors"]:
            continuity_possible += 1
            if r["recommendations"]:
                top_rec_doctor = r["recommendations"][0]["doctor_id"]
                if top_rec_doctor in r["patient"]["continuity_doctors"]:
                    continuity_preserved += 1
    
    if continuity_possible > 0:
        print(f"\n🔗 Continuity Preservation: {continuity_preserved}/{continuity_possible} ({continuity_preserved/continuity_possible*100:.1f}%)")


def demo_scenario_comparison():
    """Compare different scenarios side-by-side"""
    print("\n" + "="*60)
    print("SCENARIO COMPARISON")
    print("="*60)
    
    scenarios = {
        "Main (Balanced)": "converted_data_main.json",
        "High Demand": "converted_data_high_demand.json",
        "All Critical": "converted_data_all_critical.json",
        "Limited Availability": "converted_data_limited_availability.json",
        "Remote Patients": "converted_data_remote_patients.json"
    }
    
    print(f"\n{'Scenario':<25} {'Patients':<10} {'Doctors':<10} {'Slots':<10} {'P/D Ratio':<12}")
    print("-" * 75)
    
    for name, filename in scenarios.items():
        data = load_converted_data(filename)
        n_patients = len(data["patients"])
        n_doctors = len(data["doctors"])
        n_slots = len(data["timeslots"])
        ratio = n_patients / n_doctors
        
        print(f"{name:<25} {n_patients:<10} {n_doctors:<10} {n_slots:<10} {ratio:<12.2f}")


if __name__ == "__main__":
    print("="*60)
    print("SYNTHETIC DATA DEMO")
    print("="*60)
    
    # Load main dataset
    print("\n📂 Loading converted_data_main.json...")
    raw_data = load_converted_data("converted_data_main.json")
    
    # Restore tuple keys for use with optim.py
    data = restore_tuple_keys(raw_data)
    
    patients = data["patients"]
    doctors = data["doctors"]
    timeslots = data["timeslots"]
    
    # Print input summary
    print_optimization_input_summary(patients, doctors, timeslots)
    
    # Show scenario comparison
    demo_scenario_comparison()
    
    print("\n" + "="*60)
    print("READY TO OPTIMIZE")
    print("="*60)
    
    print("\n📝 To use this data with your optimization system:")
    print("\n   Option 1: Direct Python import")
    print("   ```python")
    print("   from demo_usage import load_converted_data, restore_tuple_keys")
    print("   ")
    print("   raw_data = load_converted_data('converted_data_main.json')")
    print("   data = restore_tuple_keys(raw_data)")
    print("   ")
    print("   # Now use with optim.py")
    print("   from optim import optimize_all_patients")
    print("   results = optimize_all_patients(data['patients'], data['doctors'], data['timeslots'])")
    print("   ```")
    
    print("\n   Option 2: Flask API")
    print("   ```bash")
    print("   # Start your Flask server")
    print("   python main.py")
    print("   ")
    print("   # POST to /api/optimize/all")
    print("   curl -X POST http://localhost:5000/api/optimize/all \\")
    print("        -H 'Content-Type: application/json' \\")
    print("        -d @converted_data_main.json")
    print("   ```")
    
    print("\n   Test Scenarios:")
    print("   - Main dataset (balanced): 20 patients, mixed urgency")
    print("   - High demand: 30 patients, 4 doctors (tests capacity constraints)")
    print("   - All critical: 10 urgent patients (tests priority handling)")
    print("   - Limited availability: Scheduling conflicts (tests constraint satisfaction)")
    print("   - Remote patients: Long distances (tests proximity weighting)")
    
    print("\n" + "="*60)
