# 📊 Synthetic Data Summary & Examples

## Quick Stats

### 📦 Package Contents

**Total Files Generated:** 18 files

**Scripts:**
- `synthetic_data_generator.py` - Data generator (18 KB)
- `data_adapter.py` - Format converter (13 KB)  
- `demo_usage.py` - Demo/testing script (9.5 KB)
- `README.md` - Complete documentation (12 KB)

**Data Files:**

| Scenario | Raw JSON | Converted JSON | Patients | Doctors | Timeslots |
|----------|----------|----------------|----------|---------|-----------|
| Main (Balanced) | 25 KB | 79 KB | 20 | 6 | 40 |
| High Demand | 28 KB | 70 KB | 30 | 4 | 24 |
| All Critical | 18 KB | 48 KB | 10 | 6 | 40 |
| Limited Availability | 19 KB | 62 KB | 15 | 5 | 40 |
| Remote Patients | 19 KB | 53 KB | 12 | 5 | 40 |

---

## 🎯 Sample Data Examples

### Example 1: Critical Patient

```json
{
  "patient_id": "patient_3",
  "name": "Matthew Davis",
  "score": 2.6,
  "urgency": "High",
  "specialty_needed": "MSK",
  "location": {
    "lat": 40.7580,
    "long": -73.9855
  },
  "max_distance_km": 23,
  "available_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
  "available_times": ["9:00 AM", "10:00 AM", "11:00 AM", "1:00 PM", ...],
  "preferred_times": ["9:00 AM", "10:00 AM"],
  "continuity_doctors": [],
  "distances": {
    "doctor_1": 13.3,
    "doctor_2": 0.1,  # ← Very close!
    "doctor_3": 5.3,
    "doctor_4": 1.8,
    "doctor_5": 9.5,
    "doctor_6": 9.5
  }
}
```

**Analysis:**
- ✅ Score of 2.6 → Auto-notification triggered
- ✅ High urgency → Will be prioritized in optimization
- ✅ Very flexible availability (35/40 slots)
- ✅ Closest clinic only 0.1 km away
- ⚠️ Needs MSK specialist (limited supply: only 1 doctor)

---

### Example 2: Normal Patient with Continuity

```json
{
  "patient_id": "patient_1",
  "name": "Linda Miller",
  "score": 5.1,
  "urgency": "Low",
  "specialty_needed": "Post-op",
  "location": {
    "lat": 40.7614,
    "long": -73.9776
  },
  "max_distance_km": 6,
  "available_days": ["Monday", "Wednesday", "Thursday", "Friday"],
  "available_times": ["9:00 AM", "10:00 AM", "1:00 PM", "2:00 PM", "3:00 PM"],
  "preferred_times": ["9:00 AM", "10:00 AM"],
  "continuity_doctors": ["doctor_4"],  # ← Has seen Dr. James Williams before
  "distances": {
    "doctor_1": 13.3,
    "doctor_2": 4.1,
    "doctor_3": 9.9,
    "doctor_4": 0.5,  # ← Her previous doctor is very close!
    "doctor_5": 14.2,
    "doctor_6": 14.3
  }
}
```

**Analysis:**
- ✅ Good rehab score (5.1) → Low urgency
- ✅ Continuity with doctor_4 (Dr. James Williams)
- ✅ Doctor_4 is only 0.5 km away
- ⚠️ Limited availability (only 4 days, 5 time slots)
- ⚠️ Small max distance (6 km) limits options

**Expected Optimization:**
- System should strongly prefer doctor_4 (continuity + proximity)
- If doctor_4 unavailable, may struggle due to 6km limit

---

### Example 3: Doctor with Multiple Specialties

```json
{
  "doctor_id": "doctor_1",
  "name": "Dr. Sarah Chen",
  "specialties": ["Neuro", "Sports"],
  "clinic_name": "Queens Physical Therapy",
  "clinic_location": {
    "lat": 40.8448,
    "long": -73.8648
  },
  "available_days": ["Tuesday", "Thursday"],
  "available_times": ["11:00 AM", "1:00 PM", "2:00 PM", "3:00 PM"]
}
```

**Analysis:**
- ✅ Covers 2 specialties (can serve Neuro + Sports patients)
- ⚠️ Part-time schedule (only 2 days/week)
- ⚠️ Limited availability (8 slots per week)
- 📍 Located in Queens (may be far for Manhattan patients)

---

## 📊 Dataset Statistics

### Main Dataset Deep Dive

#### Patient Score Distribution

```
Score Range    | Count | Percentage | Urgency
---------------|-------|------------|--------
0.0 - 2.9      |   5   |    25%     | High (Critical)
3.0 - 4.9      |   6   |    30%     | Medium (Concerning)
5.0 - 10.0     |   9   |    45%     | Low (Normal)
```

**Score Details:**
- Lowest: 1.4 (2 patients)
- Highest: 9.5
- Median: 4.8
- Mean: 4.88

#### Specialty Distribution

**Patient Needs:**
```
Post-op:  ███████ 7 patients (35%)
Neuro:    █████ 5 patients (25%)
Sports:   ████ 4 patients (20%)
MSK:      ████ 4 patients (20%)
```

**Doctor Supply:**
```
Neuro:    ███ 3 doctors (50%)
Sports:   ███ 3 doctors (50%)
Post-op:  █ 1 doctor (16.7%)
MSK:      █ 1 doctor (16.7%)
```

**Supply-Demand Gaps:**
- ⚠️ **Post-op:** 7 patients, 1 doctor (ratio 0.14) ← Bottleneck!
- ⚠️ **MSK:** 4 patients, 1 doctor (ratio 0.25) ← Bottleneck!
- ✅ **Neuro:** 5 patients, 3 doctors (ratio 0.60) ← Adequate
- ✅ **Sports:** 4 patients, 3 doctors (ratio 0.75) ← Good

#### Geographic Distribution

**Patient Locations:**
```
Manhattan/Central:  10 patients (50%)
Brooklyn/Queens:     6 patients (30%)
Bronx/Outer:        4 patients (20%)
```

**Doctor Locations:**
```
Manhattan:  3 doctors
Brooklyn:   1 doctor
Queens:     1 doctor
Bronx:      1 doctor
```

**Distance Matrix Summary:**
```
Percentile | Distance
-----------|----------
Min        | 0.0 km (perfect match)
25th       | 3.2 km
50th       | 7.8 km
75th       | 13.1 km
Max        | 19.7 km
```

#### Availability Patterns

**Patient Availability:**
```
High (30+ slots):    10 patients (50%) - Very flexible
Medium (15-29 slots): 7 patients (35%) - Moderately flexible
Low (<15 slots):      3 patients (15%) - Constrained
```

**Doctor Availability:**
```
Full-time (30+ slots):  4 doctors (67%)
Part-time (<30 slots):  2 doctors (33%)
```

**Time Preference Patterns:**
```
Morning preference (9-11 AM):     45% of patients
Afternoon preference (1-3 PM):    30% of patients
Late afternoon (4-5 PM):          15% of patients
No strong preference:             10% of patients
```

---

## 🎯 Optimization Challenge Analysis

### Expected Bottlenecks

1. **Post-op Specialty** (7 patients, 1 doctor)
   - Only Dr. Mark Johnson has Post-op specialty
   - He has 40 available slots
   - 7 patients need Post-op care
   - **Expected:** Some patients may need to wait for later slots

2. **MSK Specialty** (4 patients, 1 doctor)
   - Only Dr. Michael Brown has MSK specialty
   - 4 patients need MSK care
   - **Expected:** All should get assigned if availability aligns

3. **Critical Patients** (5 total)
   - Matthew Davis (2.6, MSK)
   - David Miller (2.4, Post-op)
   - John Moore (1.4, MSK)
   - Linda Brown (1.4, Neuro)
   - Jennifer Martinez (1.5, Post-op)
   - **Expected:** All should be prioritized for earliest available slots

### Optimization Targets

**For Main Dataset, you should achieve:**
- ✅ Assignment rate: 85-95% (17-19 out of 20 patients)
- ✅ Critical assignment: 100% (all 5 urgent patients)
- ✅ Average recommendation score: 0.70-0.85
- ✅ Average distance: 6-10 km
- ✅ Continuity preservation: 40-60% (4-7 out of 11 possible)

**Patients likely to be unassigned:**
- Those requiring Post-op with inflexible schedules
- Those requiring MSK with very limited availability
- Those with max_distance < 5km in outer boroughs

---

## 🔬 Test Scenario Characteristics

### Scenario 1: High Demand
```
Patients: 30
Doctors:   4
Ratio:    7.5:1

Expected Behavior:
- Only ~60-75% of patients will get slots
- Critical patients should be prioritized
- Normal urgency patients may be waitlisted
- Average recommendation scores will be lower (0.50-0.65)
- Patients forced to accept longer distances
```

### Scenario 2: All Critical
```
Patients: 10 (all score < 3.0, High urgency)
Doctors:   6
Ratio:    1.67:1

Expected Behavior:
- All patients should get assigned (sufficient capacity)
- Competition for earliest time slots
- Urgency tie-breaking by score (lowest scores first)
- Auto-notifications triggered for all patients
- System stress-tests priority handling
```

### Scenario 3: Limited Availability
```
Patients: 15 (each only 2 days × 2 times = 4 slots available)
Doctors:   5
Ratio:    3:1

Expected Behavior:
- Constraint satisfaction problem
- Many scheduling conflicts
- Assignment rate: 70-85% (some unavoidable conflicts)
- Tests availability matching logic thoroughly
```

### Scenario 4: Remote Patients
```
Patients: 12 (distances 20-35 km)
Doctors:   5
Ratio:    2.4:1

Expected Behavior:
- High average distances (15-25 km)
- Tests distance weighting in objective function
- Patients willing to travel far (max_distance is high)
- Good for testing edge of proximity constraints
```

---

## 📈 Validation Checklist

Use this to verify your optimization results:

### ✅ Constraint Satisfaction
- [ ] No patient assigned to unavailable timeslot
- [ ] No patient assigned to unavailable doctor
- [ ] No doctor double-booked (two patients same slot)
- [ ] All distances respect max_distance limits
- [ ] All specialty matches are correct

### ✅ Priority Handling
- [ ] Critical patients (score < 3.0) get earliest available slots
- [ ] Critical patients have higher average scores than normal patients
- [ ] Medium urgency ranks between High and Low

### ✅ Scoring Logic
- [ ] Continuity bonus applied (higher score for previous doctors)
- [ ] Proximity bonus applied (closer clinics score higher)
- [ ] Time preference bonus applied (preferred times score higher)
- [ ] Combined score is reasonable (0.0 - 1.0 range)

### ✅ Top-3 Quality
- [ ] Recommendation #1 > Recommendation #2 > Recommendation #3
- [ ] All three recommendations are feasible
- [ ] All three respect patient constraints
- [ ] Scores decrease gradually (not cliff drop)

---

## 💡 Usage Tips

### For Testing
```python
# Quick validation test
from demo_usage import load_converted_data, restore_tuple_keys
data = restore_tuple_keys(load_converted_data('converted_data_main.json'))

from optim import optimize_all_patients
results = optimize_all_patients(data['patients'], data['doctors'], data['timeslots'])

# Check critical patient results
for patient_id, result in results.items():
    if result['patient']['urgency'] == 'High':
        print(f"{result['patient']['name']}: {len(result['recommendations'])} recommendations")
        if result['recommendations']:
            top = result['recommendations'][0]
            print(f"  → {top['doctor']} @ {top['day']} {top['time']} (score: {top['score']:.3f})")
```

### For Demos
```python
# Load the most visually interesting scenario
data = restore_tuple_keys(load_converted_data('converted_data_all_critical.json'))

# All patients are critical → shows urgency handling well
# Good for presentations
```

### For Stress Testing
```python
# Test capacity limits
data = restore_tuple_keys(load_converted_data('converted_data_high_demand.json'))

# 30 patients, 4 doctors → not everyone will get assigned
# Tests how system handles scarcity
```

---

## 🎓 Learning Exercises

Try these experiments with the data:

1. **Weight Tuning:** Modify weights in optim.py, see how results change
   - Try w_urgency = 0.8 (heavy urgency focus)
   - Try w_dist = 0.8 (heavy proximity focus)
   - Try w_cont = 0.8 (heavy continuity focus)

2. **Threshold Testing:** Change critical threshold from 3.0 to 4.0
   - More patients will be flagged as critical
   - Test notification logic scales properly

3. **Capacity Analysis:** Remove 2 doctors from main dataset
   - Recalculate supply-demand ratios
   - See which patients can't be assigned

4. **Geographic Clustering:** Group patients by location
   - Analyze if nearby patients compete for same doctor
   - Test if distance scoring works as expected

---

Generated: February 7, 2026
Dataset Version: 1.0
Compatible with: optim.py v1.0
