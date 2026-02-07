# 📊 Synthetic Data Package for Rehab Appointment Optimization

## Overview

This package provides **realistic synthetic data** for testing and demonstrating your rehab appointment optimization system. It includes multiple test scenarios covering various edge cases and real-world situations.

---

## 📁 Package Contents

### 🔧 Generator Scripts

| File | Purpose |
|------|---------|
| `synthetic_data_generator.py` | Core data generator - creates patients, doctors, timeslots |
| `data_adapter.py` | Converts raw synthetic data to optim.py format |
| `demo_usage.py` | Demo script showing how to use the data |

### 📊 Generated Data Files

#### Raw Synthetic Data (JSON)
- `synthetic_data_main.json` - Main balanced dataset (20 patients, 6 doctors, 5 days)
- `synthetic_data_high_demand.json` - High patient-to-doctor ratio (30:4)
- `synthetic_data_all_critical.json` - All patients have critical scores
- `synthetic_data_limited_availability.json` - Patients with scheduling conflicts
- `synthetic_data_remote_patients.json` - Geographically dispersed patients

#### Converted Data (Ready for optim.py)
- `converted_data_main.json`
- `converted_data_high_demand.json`
- `converted_data_all_critical.json`
- `converted_data_limited_availability.json`
- `converted_data_remote_patients.json`

---

## 🚀 Quick Start

### Option 1: Use Pre-Generated Data

```python
from demo_usage import load_converted_data, restore_tuple_keys

# Load converted data
raw_data = load_converted_data('converted_data_main.json')
data = restore_tuple_keys(raw_data)

# Extract components
patients = data['patients']
doctors = data['doctors']
timeslots = data['timeslots']

# Now use with your optimization system
from optim import optimize_all_patients
results = optimize_all_patients(patients, doctors, timeslots)
```

### Option 2: Generate Fresh Data

```python
from synthetic_data_generator import generate_complete_dataset
from data_adapter import convert_to_optim_format

# Generate new dataset
raw_data = generate_complete_dataset(
    n_patients=25,
    n_doctors=5,
    n_days=7
)

# Convert to optim format
patients, doctors, timeslots = convert_to_optim_format(raw_data)
```

### Option 3: Use with Flask API

```bash
# Start your Flask server
python main.py

# POST data to API endpoint
curl -X POST http://localhost:5000/api/optimize/all \
     -H 'Content-Type: application/json' \
     -d @converted_data_main.json
```

---

## 📊 Dataset Specifications

### Main Dataset Statistics

```
📋 Patients: 20
   - Critical (urgency=High): 5 patients (25%)
   - Concerning (urgency=Medium): 6 patients (30%)
   - Normal (urgency=Low): 9 patients (45%)
   - Average rehab score: 4.88

👨‍⚕️ Doctors: 6
   - Specialties: MSK, Post-op, Neuro, Sports
   - Average availability: 14.7 timeslots each

🕐 Timeslots: 40
   - 5 days × 8 time slots per day
   - Coverage: 9:00 AM - 5:00 PM
   - Total capacity: 88 potential appointments

📏 Distance Statistics:
   - Average patient-to-clinic: 8.8 km
   - Range: 0.0 - 19.7 km

🔗 Continuity of Care:
   - 11 patients with prior doctor relationships
   - 13 total continuity relationships
```

### Supply-Demand Analysis

| Specialty | Doctors | Patients | Ratio |
|-----------|---------|----------|-------|
| Post-op   | 1       | 7        | 0.14 ⚠️ |
| MSK       | 1       | 4        | 0.25 ⚠️ |
| Neuro     | 3       | 5        | 0.60 ✅ |
| Sports    | 3       | 4        | 0.75 ✅ |

---

## 🎯 Test Scenarios

### 1. Main Dataset (Balanced)
**File:** `converted_data_main.json`

- **Use case:** General testing, demo purposes
- **Characteristics:** Realistic mix of urgencies, balanced supply-demand
- **Best for:** Showcasing normal operation

### 2. High Demand
**File:** `converted_data_high_demand.json`

- **Patients:** 30 | **Doctors:** 4 | **Ratio:** 7.5:1
- **Use case:** Testing capacity constraints
- **Challenges:** Not all patients can be assigned, priority matters
- **Best for:** Testing waitlist logic, triage decisions

### 3. All Critical
**File:** `converted_data_all_critical.json`

- **Patients:** 10 (all with score < 3.0)
- **Use case:** Testing urgency-first optimization
- **Challenges:** All patients need immediate care
- **Best for:** Validating auto-notification triggers, emergency scheduling

### 4. Limited Availability
**File:** `converted_data_limited_availability.json`

- **Patients:** 15 (each available only 2 days, 2 time slots)
- **Use case:** Testing constraint satisfaction
- **Challenges:** Heavy scheduling conflicts
- **Best for:** Validating availability matching logic

### 5. Remote Patients
**File:** `converted_data_remote_patients.json`

- **Patients:** 12 (spread across 20-35 km range)
- **Use case:** Testing distance weighting
- **Challenges:** Long travel distances
- **Best for:** Validating proximity scoring, telehealth alternatives

---

## 📐 Data Schema

### Patient Object

```python
{
  "patient_id": "patient_1",
  "name": "Linda Miller",
  "score": 5.1,                    # Rehab quality score (0-10)
  "urgency": "Low",                # High/Medium/Low
  "specialty_needed": "Post-op",   # MSK/Post-op/Neuro/Sports
  "location": {
    "lat": 40.7614,
    "long": -73.9776
  },
  "max_distance": 6,               # Max km willing to travel
  "availability": {
    ("Monday", "9:00 AM"): True,   # Dict of (day, time): available
    ...
  },
  "time_preferences": {
    ("Monday", "9:00 AM"): 1.0,    # 1.0 = preferred, 0.5 = neutral, 0.0 = unavailable
    ...
  },
  "continuity_doctors": ["doctor_4"], # Previously seen doctors
  "distances": {
    "doctor_1": 13.3,              # Distance to each doctor's clinic
    ...
  }
}
```

### Doctor Object

```python
{
  "doctor_id": "doctor_1",
  "name": "Dr. Sarah Chen",
  "specialties": ["Neuro", "Sports"],
  "clinic_name": "Queens Physical Therapy",
  "location": {
    "lat": 40.8448,
    "long": -73.8648
  },
  "availability": {
    ("Thursday", "11:00 AM"): True,
    ...
  }
}
```

### Timeslot Object

```python
{
  "timeslot_id": "slot_1",
  "day": "Monday",
  "time": "9:00 AM",
  "date": "2026-02-08",
  "datetime": "2026-02-08 9:00 AM"
}
```

---

## 🔄 Regenerating Data

### Generate New Main Dataset

```python
python synthetic_data_generator.py
```

This creates:
- `synthetic_data_main.json`
- All 4 test scenario files
- Sample data previews

### Customize Generation

```python
from synthetic_data_generator import generate_complete_dataset, save_dataset

# Custom parameters
dataset = generate_complete_dataset(
    n_patients=50,      # More patients
    n_doctors=10,       # More doctors
    n_days=10          # Two weeks of slots
)

save_dataset(dataset, "my_custom_data.json")
```

### Convert Custom Data

```python
from data_adapter import convert_to_optim_format, save_converted_data

raw_data = load_synthetic_data("my_custom_data.json")
patients, doctors, timeslots = convert_to_optim_format(raw_data)
save_converted_data(patients, doctors, timeslots, "my_custom_converted.json")
```

---

## 🧪 Testing Checklist

Use these scenarios to validate your system:

- [ ] **Basic assignment** - Main dataset, verify all patients get recommendations
- [ ] **Critical handling** - All Critical dataset, verify urgency prioritization
- [ ] **Specialty matching** - Verify patients only get doctors with right specialty
- [ ] **Availability constraints** - Limited Availability dataset, no double-booking
- [ ] **Distance filtering** - Remote Patients, respect max_distance limits
- [ ] **Continuity bonus** - Verify patients matched to their previous doctors when possible
- [ ] **Capacity limits** - High Demand dataset, handle unassigned patients gracefully
- [ ] **Auto-notification** - Critical patients (score < 3.0) trigger alerts
- [ ] **Top-3 quality** - All 3 recommendations should be reasonable alternatives

---

## 📈 Expected Optimization Results

### Main Dataset (20 patients)

**Expected outcomes:**
- Assignment rate: 85-95%
- Critical assignment rate: 100% (all 5 urgent patients)
- Average recommendation score: 0.70-0.85
- Average travel distance: 6-10 km
- Continuity preservation: 40-60%

**Unassigned patients:** 1-3 (likely due to specialty mismatch or location)

### High Demand (30 patients, 4 doctors)

**Expected outcomes:**
- Assignment rate: 60-75% (capacity limited)
- Critical patients prioritized first
- Some normal-urgency patients may not get slots
- Higher average distances (patients forced to travel farther)

---

## 🛠️ Customization Guide

### Adjust Patient Distribution

```python
# In synthetic_data_generator.py, modify line ~70

# More critical patients (40% instead of 20%)
if rand < 0.40:  # Changed from 0.20
    score = round(random.uniform(1.0, 2.9), 1)
    urgency = "High"
```

### Add New Specialties

```python
# In synthetic_data_generator.py, line ~12

SPECIALTIES = ["MSK", "Post-op", "Neuro", "Sports", "Pediatric", "Geriatric"]
```

### Change Geographic Area

```python
# In synthetic_data_generator.py, line ~17

# Example: Los Angeles coordinates
LA_LOCATIONS = [
    (34.0522, -118.2437),  # Downtown LA
    (34.0689, -118.4452),  # Santa Monica
    # ... add more
]
```

---

## 🐛 Troubleshooting

### Issue: JSON serialization error with tuple keys

**Solution:** Use `restore_tuple_keys()` after loading JSON:

```python
from demo_usage import restore_tuple_keys

raw_data = load_converted_data("converted_data_main.json")
data = restore_tuple_keys(raw_data)  # Converts string keys back to tuples
```

### Issue: All patients unassigned

**Check:**
1. Doctor specialties match patient needs
2. Availability overlap exists
3. Distance constraints aren't too restrictive

### Issue: Poor optimization scores

**Likely causes:**
- Supply-demand imbalance (generate more doctors)
- Geographic mismatch (expand search radius)
- Availability conflicts (generate more timeslots)

---

## 📊 Data Quality Metrics

The generator ensures:

✅ **Realism:** Based on NYC geography, realistic distances  
✅ **Variety:** Mixed urgencies, specialties, availability patterns  
✅ **Edge cases:** Includes difficult-to-schedule patients  
✅ **Consistency:** All relationships (distances, continuity) are valid  
✅ **Reproducibility:** Fixed random seed (42) for consistent output  

---

## 🔮 Future Enhancements

Potential additions for production:

1. **Historical data:** Add appointment history, no-show rates
2. **Insurance:** Add insurance compatibility constraints
3. **Multi-clinic doctors:** Doctors working at multiple locations
4. **Time-of-day preferences:** More granular than just "preferred times"
5. **Language matching:** Patient-doctor language requirements
6. **Telehealth:** Virtual appointment options
7. **Equipment needs:** Special equipment availability (e.g., gait analysis)

---

## 📞 Contact & Support

For questions about the synthetic data:
- Review `demo_usage.py` for usage examples
- Check `data_adapter.py` for format specifications
- Regenerate with `synthetic_data_generator.py` for fresh data

---

## 📄 License

This synthetic data is generated for testing purposes only. All names and locations are randomly generated and not associated with real individuals or clinics.

---

**Generated:** February 2026  
**Version:** 1.0  
**Compatible with:** optim.py v1.0, Flask API v1.0
