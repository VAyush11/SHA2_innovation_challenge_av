import json
import sys

import gurobipy as gp
from gurobipy import GRB


# ========================= SCORE THRESHOLD CONSTANTS =========================

THRESHOLD_CRITICAL = 3.0    # Score below which auto-notification triggers
THRESHOLD_CONCERNING = 5.0  # Score for warning notification
MAX_DIST_EXPANSION = 1.5    # Multiply max distance by this for critical patients

# Default objective weights: proximity, urgency, continuity, time_preference
DEFAULT_WEIGHTS = {
    "w_dist": 0.20,
    "w_urgency": 0.40,
    "w_cont": 0.20,
    "w_time": 0.20,
}

URGENCY_MAP = {"Low": 1, "Medium": 2, "High": 3}


# ========================= DATASET LOADER ====================================

def load_dataset(filepath):
    """
    Load a JSON dataset file and convert it to the optimizer's internal format.

    The dataset schema uses:
      - patient_id, doctor_id, timeslot_id as ID fields
      - "Monday_9:00 AM" style keys for availability (true/false booleans)
      - urgency as string ("Low"/"Medium"/"High")
      - distances as a per-doctor dict {doctor_id: km}
      - continuity_doctors as a list of doctor_ids

    Returns (patients, doctors, timeslots) in the optimizer's format.
    """
    with open(filepath, "r") as f:
        raw = json.load(f)

    raw_timeslots = raw["timeslots"]
    raw_doctors = raw["doctors"]
    raw_patients = raw["patients"]

    # -- Build timeslot key mapping: "Monday_9:00 AM" -> timeslot_id --
    # Also assign time_index by the ordering in the file (chronological)
    slot_key_to_id = {}
    timeslots = []
    for idx, ts in enumerate(raw_timeslots):
        tid = ts["timeslot_id"]
        key = f"{ts['day']}_{ts['time']}"
        slot_key_to_id[key] = tid
        timeslots.append({
            "id": tid,
            "label": f"{ts['day'][:3]} {ts['time']}",
            "time_index": idx,
        })

    # -- Convert doctors --
    doctors = []
    for d in raw_doctors:
        avail = {}
        for key, val in d["availability"].items():
            tid = slot_key_to_id.get(key)
            if tid is not None:
                avail[tid] = 1 if val else 0
        doctors.append({
            "id": d["doctor_id"],
            "label": d["name"],
            "specialties": d["specialties"],
            "clinic_name": d.get("clinic_name", ""),
            "availability": avail,
        })

    # -- Convert patients --
    patients = []
    for p in raw_patients:
        # Availability: "Monday_9:00 AM" bool -> timeslot_id int
        avail = {}
        for key, val in p["availability"].items():
            tid = slot_key_to_id.get(key)
            if tid is not None:
                avail[tid] = 1 if val else 0

        # Time preferences: same key mapping
        time_pref = {}
        for key, val in p.get("time_preferences", {}).items():
            tid = slot_key_to_id.get(key)
            if tid is not None:
                time_pref[tid] = val

        # Urgency: string -> int
        urg_str = p.get("urgency", "Low")
        urgency = URGENCY_MAP.get(urg_str, 1)

        # Continuity: list -> dict
        cont_list = p.get("continuity_doctors", [])
        continuity = {doc_id: 1 for doc_id in cont_list}

        # Distances: per-doctor dict {doctor_id: km}
        distances = p.get("distances", {})

        patients.append({
            "id": p["patient_id"],
            "label": p.get("name", p["patient_id"]),
            "score": p["score"],
            "urgency": urgency,
            "max_dist": p.get("max_distance", 50.0),
            "distances": distances,  # per-doctor distances
            "specialty_need": p.get("specialty_needed", ""),
            "availability": avail,
            "continuity": continuity,
            "time_preference": time_pref,
        })

    return patients, doctors, timeslots


# ========================= SCORE-TRIGGERED ADJUSTMENT ========================

def adjust_for_score(patient, weights=None):
    """
    Check patient rehab score and adjust urgency / search radius / weights
    if the score is critical or concerning.

    Modifies the patient dict in-place and returns a notification dict.

    Parameters
    ----------
    patient : dict
        Must contain keys: "score" (float 0-10), "urgency" (1-3),
        "max_dist" (km).
    weights : dict or None
        Current objective weights. Modified in-place for critical patients.

    Returns
    -------
    notification : dict or None
        {"level": "critical"|"concerning", "message": str} or None if normal.
    """
    score = patient["score"]
    notification = None

    if score < THRESHOLD_CRITICAL:
        patient["urgency"] = 3  # High
        patient["max_dist"] = patient["max_dist"] * MAX_DIST_EXPANSION
        if weights is not None:
            weights["w_urgency"] = 0.60
            weights["w_dist"] = 0.15
            weights["w_cont"] = 0.15
            weights["w_time"] = 0.10
        notification = {
            "level": "critical",
            "message": (
                "Your recent exercise quality needs attention. "
                "We strongly recommend scheduling a follow-up ASAP."
            ),
        }
    elif score < THRESHOLD_CONCERNING:
        patient["urgency"] = 2  # Medium
        notification = {
            "level": "concerning",
            "message": "Consider scheduling a check-in with your therapist.",
        }

    return notification


# ========================= CORE OPTIMIZER ====================================

def optimize_single(patients, doctors, timeslots, weights=None, blocked=None):
    """
    Solve the appointment assignment LP for a single clinic (MVP).

    Supports per-doctor distances (distances dict on each patient) as well
    as the legacy single dist_to_clinic field.

    Parameters
    ----------
    patients : list[dict]
        Each dict has keys:
            id (str), score (float 0-10), urgency (int 1-3),
            max_dist (float km),
            distances (dict[str, float] doctor_id -> km)  OR
            dist_to_clinic (float km) for legacy/demo data,
            availability (dict[str, int]  timeslot_id -> 0/1),
            specialty_need (str),
            continuity (dict[str, int] doctor_id -> 0/1),
            time_preference (dict[str, float] timeslot_id -> 0.0-1.0)
    doctors : list[dict]
        Each dict has keys:
            id (str), label (str), specialties (list[str]),
            availability (dict[str, int]  timeslot_id -> 0/1)
    timeslots : list[dict]
        Each dict has keys:
            id (str), label (str e.g. "Mon 9:00 AM"),
            time_index (int, 0 = earliest)
    weights : dict or None
        Keys: w_dist, w_urgency, w_cont, w_time. Defaults to DEFAULT_WEIGHTS.
    blocked : list[tuple] or None
        List of (patient_id, doctor_id, timeslot_id) tuples to block
        (used for sequential top-3 generation).

    Returns
    -------
    result : dict or None
        {
          "assignments": {patient_id: {"doctor_id": ..., "doctor_label": ...,
                                        "timeslot_id": ..., "timeslot_label": ...,
                                        "score": float, "dist_km": float}},
          "objective": float,
          "status": str
        }
        None if infeasible.
    """
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)
    if blocked is None:
        blocked = []

    w_dist = weights["w_dist"]
    w_urg = weights["w_urgency"]
    w_cont = weights["w_cont"]
    w_time = weights["w_time"]

    total_slots = max(ts["time_index"] for ts in timeslots) + 1

    # Build index lookups
    p_ids = [p["id"] for p in patients]
    d_ids = [d["id"] for d in doctors]
    t_ids = [ts["id"] for ts in timeslots]

    p_map = {p["id"]: p for p in patients}
    d_map = {d["id"]: d for d in doctors}
    t_map = {ts["id"]: ts for ts in timeslots}

    blocked_set = set((b[0], b[1], b[2]) for b in blocked)

    # Helper: get distance from patient i to doctor j
    def get_dist(p, doc_id):
        if "distances" in p and p["distances"]:
            return p["distances"].get(doc_id, p.get("dist_to_clinic", 999.0))
        return p.get("dist_to_clinic", 0.0)

    # ---- Create model ----
    model = gp.Model("rehab_appointment")
    model.setParam("OutputFlag", 0)  # suppress solver output

    # ---- Decision variables: X[i, j, t] binary ----
    X = {}
    for i in p_ids:
        for j in d_ids:
            for t in t_ids:
                X[i, j, t] = model.addVar(
                    vtype=GRB.BINARY, name=f"X_{i}_{j}_{t}"
                )

    model.update()

    # ---- Objective function ----
    obj = gp.LinExpr()

    for i in p_ids:
        p = p_map[i]
        max_d = p["max_dist"]
        urgency_val = p["urgency"]  # 1, 2, or 3

        for j in d_ids:
            dist = get_dist(p, j)
            proximity_score = max(0.0, 1.0 - dist / max_d) if max_d > 0 else 0.0
            cont = p["continuity"].get(j, 0)

            for t in t_ids:
                ts = t_map[t]
                time_idx = ts["time_index"]
                urgency_bonus = urgency_val * (1.0 - time_idx / total_slots)
                time_pref = p["time_preference"].get(t, 0.5)

                coeff = (
                    w_dist * proximity_score
                    + w_urg * urgency_bonus
                    + w_cont * cont
                    + w_time * time_pref
                )
                obj += coeff * X[i, j, t]

    model.setObjective(obj, GRB.MAXIMIZE)

    # ---- Constraints ----

    # C1: Each patient assigned to at most one slot
    for i in p_ids:
        model.addConstr(
            gp.quicksum(X[i, j, t] for j in d_ids for t in t_ids) <= 1,
            name=f"one_assignment_{i}",
        )

    # C2: Each doctor sees at most one patient per timeslot
    for j in d_ids:
        for t in t_ids:
            model.addConstr(
                gp.quicksum(X[i, j, t] for i in p_ids) <= 1,
                name=f"doctor_capacity_{j}_{t}",
            )

    # C3: Patient availability
    for i in p_ids:
        p = p_map[i]
        for j in d_ids:
            for t in t_ids:
                if p["availability"].get(t, 0) == 0:
                    model.addConstr(X[i, j, t] == 0,
                                    name=f"pat_avail_{i}_{j}_{t}")

    # C4: Doctor availability
    for j in d_ids:
        d = d_map[j]
        for i in p_ids:
            for t in t_ids:
                if d["availability"].get(t, 0) == 0:
                    model.addConstr(X[i, j, t] == 0,
                                    name=f"doc_avail_{i}_{j}_{t}")

    # C5: Distance constraint - per-doctor distance check
    for i in p_ids:
        p = p_map[i]
        for j in d_ids:
            dist = get_dist(p, j)
            if dist > p["max_dist"]:
                for t in t_ids:
                    model.addConstr(X[i, j, t] == 0,
                                    name=f"dist_{i}_{j}_{t}")

    # C6: Specialty matching
    for i in p_ids:
        p = p_map[i]
        need = p["specialty_need"]
        for j in d_ids:
            d = d_map[j]
            if need and need not in d["specialties"]:
                for t in t_ids:
                    model.addConstr(X[i, j, t] == 0,
                                    name=f"spec_{i}_{j}_{t}")

    # C7: Blocked assignments (for sequential top-3)
    for (bi, bj, bt) in blocked_set:
        if (bi, bj, bt) in X:
            model.addConstr(X[bi, bj, bt] == 0,
                            name=f"blocked_{bi}_{bj}_{bt}")

    # ---- Solve ----
    model.optimize()

    if model.Status == GRB.OPTIMAL:
        assignments = {}
        for i in p_ids:
            for j in d_ids:
                for t in t_ids:
                    if X[i, j, t].X > 0.5:
                        p = p_map[i]
                        dist = get_dist(p, j)
                        max_d = p["max_dist"]
                        prox = max(0.0, 1.0 - dist / max_d) if max_d > 0 else 0.0
                        cont = p["continuity"].get(j, 0)
                        ts = t_map[t]
                        urg_bonus = p["urgency"] * (1.0 - ts["time_index"] / total_slots)
                        t_pref = p["time_preference"].get(t, 0.5)

                        score = (
                            w_dist * prox
                            + w_urg * urg_bonus
                            + w_cont * cont
                            + w_time * t_pref
                        )

                        assignments[i] = {
                            "doctor_id": j,
                            "doctor_label": d_map[j].get("label", j),
                            "timeslot_id": t,
                            "timeslot_label": t_map[t]["label"],
                            "score": round(score, 4),
                            "dist_km": dist,
                        }
        return {
            "assignments": assignments,
            "objective": model.ObjVal,
            "status": "optimal",
        }
    else:
        return None


# ========================= TOP-3 SEQUENTIAL OPTIMIZER ========================

def get_top3_recommendations(patient_id, patients, doctors, timeslots,
                             weights=None):
    """
    Generate top 3 appointment recommendations for a single patient
    using sequential optimization (solve 3 times, blocking previous best).

    Parameters
    ----------
    patient_id : str
        The patient to generate recommendations for.
    patients : list[dict]
        Full patient list (only the target patient is optimized, but others
        are included for constraint completeness).
    doctors : list[dict]
    timeslots : list[dict]
    weights : dict or None

    Returns
    -------
    recommendations : list[dict]
        Up to 3 dicts, each with keys: rank, doctor_id, doctor_label,
        timeslot_id, timeslot_label, score, dist_km.
    notification : dict or None
        Auto-notification if score triggers threshold.
    """
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)

    # Find the target patient and apply score-based adjustments
    target = None
    for p in patients:
        if p["id"] == patient_id:
            target = p
            break

    if target is None:
        return [], None

    # Apply score threshold adjustments
    patient_weights = dict(weights)
    notification = adjust_for_score(target, patient_weights)

    # Filter to only the target patient for single-patient optimization
    single_patient = [target]

    recommendations = []
    blocked = []

    for rank in range(1, 4):
        result = optimize_single(
            patients=single_patient,
            doctors=doctors,
            timeslots=timeslots,
            weights=patient_weights,
            blocked=blocked,
        )

        if result is None or patient_id not in result["assignments"]:
            break

        assignment = result["assignments"][patient_id]
        recommendations.append({
            "rank": rank,
            "doctor_id": assignment["doctor_id"],
            "doctor_label": assignment["doctor_label"],
            "timeslot_id": assignment["timeslot_id"],
            "timeslot_label": assignment["timeslot_label"],
            "score": assignment["score"],
            "dist_km": assignment["dist_km"],
        })

        # Block this assignment for next iteration
        blocked.append((
            patient_id,
            assignment["doctor_id"],
            assignment["timeslot_id"],
        ))

    return recommendations, notification


# ========================= BATCH OPTIMIZER ===================================

def optimize_all_patients(patients, doctors, timeslots, weights=None):
    """
    Run top-3 recommendations for every patient. Returns a dict keyed by
    patient_id, each containing recommendations list and notification.
    """
    results = {}
    for p in patients:
        recs, notif = get_top3_recommendations(
            patient_id=p["id"],
            patients=patients,
            doctors=doctors,
            timeslots=timeslots,
            weights=weights,
        )
        results[p["id"]] = {
            "recommendations": recs,
            "notification": notif,
        }
    return results


# ========================= DEMO DATA & STANDALONE RUNNER =====================

def build_demo_data():
    """Build sample data matching the Phase 1 MVP spec."""

    timeslots = [
        {"id": "mon_9am",  "label": "Mon 9:00 AM",  "time_index": 0},
        {"id": "mon_10am", "label": "Mon 10:00 AM", "time_index": 1},
        {"id": "mon_1pm",  "label": "Mon 1:00 PM",  "time_index": 2},
        {"id": "mon_2pm",  "label": "Mon 2:00 PM",  "time_index": 3},
        {"id": "tue_9am",  "label": "Tue 9:00 AM",  "time_index": 4},
        {"id": "tue_10am", "label": "Tue 10:00 AM", "time_index": 5},
        {"id": "wed_9am",  "label": "Wed 9:00 AM",  "time_index": 6},
        {"id": "wed_2pm",  "label": "Wed 2:00 PM",  "time_index": 7},
        {"id": "thu_9am",  "label": "Thu 9:00 AM",  "time_index": 8},
        {"id": "thu_1pm",  "label": "Thu 1:00 PM",  "time_index": 9},
        {"id": "fri_9am",  "label": "Fri 9:00 AM",  "time_index": 10},
        {"id": "fri_2pm",  "label": "Fri 2:00 PM",  "time_index": 11},
        {"id": "fri_4pm",  "label": "Fri 4:00 PM",  "time_index": 12},
    ]
    ts_ids = [ts["id"] for ts in timeslots]

    doctors = [
        {
            "id": "dr_smith",
            "label": "Dr. Smith",
            "specialties": ["MSK", "Post-op"],
            "availability": {t: 1 for t in ts_ids},
        },
        {
            "id": "dr_jones",
            "label": "Dr. Jones",
            "specialties": ["Post-op", "Neuro"],
            "availability": {
                "mon_1pm": 1, "mon_2pm": 1,
                "tue_9am": 0, "tue_10am": 0,
                "wed_2pm": 1,
                "thu_1pm": 1,
                "fri_2pm": 1, "fri_4pm": 1,
                "mon_9am": 0, "mon_10am": 0,
                "wed_9am": 0, "thu_9am": 0, "fri_9am": 0,
            },
        },
        {
            "id": "dr_chen",
            "label": "Dr. Chen",
            "specialties": ["Post-op", "MSK"],
            "availability": {
                "mon_9am": 1, "mon_10am": 1,
                "tue_9am": 1, "tue_10am": 1,
                "wed_9am": 1,
                "thu_9am": 1, "thu_1pm": 1,
                "fri_9am": 1,
                "mon_1pm": 0, "mon_2pm": 0,
                "wed_2pm": 0, "fri_2pm": 0, "fri_4pm": 0,
            },
        },
    ]

    patients = [
        {
            "id": "patient_1",
            "label": "Jane Doe",
            "score": 2.5,
            "urgency": 1,
            "max_dist": 15.0,
            "distances": {"dr_smith": 8.0, "dr_jones": 10.0, "dr_chen": 5.0},
            "specialty_need": "Post-op",
            "availability": {t: 1 for t in ts_ids},
            "continuity": {"dr_chen": 1},
            "time_preference": {
                "mon_9am": 1.0, "tue_9am": 1.0, "wed_9am": 1.0,
                "thu_9am": 1.0, "fri_9am": 1.0,
                "mon_10am": 0.8, "tue_10am": 0.8,
                "mon_1pm": 0.3, "mon_2pm": 0.3,
                "wed_2pm": 0.3, "thu_1pm": 0.3,
                "fri_2pm": 0.3, "fri_4pm": 0.2,
            },
        },
        {
            "id": "patient_2",
            "label": "John Smith",
            "score": 7.0,
            "urgency": 1,
            "max_dist": 10.0,
            "distances": {"dr_smith": 3.0, "dr_jones": 7.0, "dr_chen": 4.0},
            "specialty_need": "MSK",
            "availability": {
                "mon_9am": 1, "mon_10am": 1, "mon_1pm": 1, "mon_2pm": 1,
                "wed_9am": 1, "wed_2pm": 1,
                "fri_9am": 1, "fri_2pm": 1, "fri_4pm": 1,
                "tue_9am": 0, "tue_10am": 0,
                "thu_9am": 0, "thu_1pm": 0,
            },
            "continuity": {"dr_smith": 1},
            "time_preference": {
                "mon_1pm": 1.0, "mon_2pm": 1.0, "wed_2pm": 1.0,
                "fri_2pm": 1.0, "fri_4pm": 0.9,
                "mon_9am": 0.4, "mon_10am": 0.4,
                "wed_9am": 0.4, "fri_9am": 0.4,
            },
        },
        {
            "id": "patient_3",
            "label": "Maria Garcia",
            "score": 4.5,
            "urgency": 1,
            "max_dist": 20.0,
            "distances": {"dr_smith": 12.0, "dr_jones": 15.0, "dr_chen": 18.0},
            "specialty_need": "Neuro",
            "availability": {t: 1 for t in ts_ids},
            "continuity": {},
            "time_preference": {t: 0.5 for t in ts_ids},
        },
    ]

    return patients, doctors, timeslots


def print_results(all_results):
    """Pretty-print optimization results."""
    print("=" * 65)
    print("  REHAB APPOINTMENT OPTIMIZATION RESULTS")
    print("=" * 65)

    for pid, data in all_results.items():
        notif = data["notification"]
        recs = data["recommendations"]

        print(f"\n  Patient: {pid}")
        if notif:
            level = notif["level"].upper()
            print(f"  [{level}] {notif['message']}")
        print(f"  Recommendations:")

        if not recs:
            print("    No feasible appointments found.")
        else:
            for r in recs:
                print(
                    f"    #{r['rank']}: {r['doctor_label']}, "
                    f"{r['timeslot_label']}, "
                    f"{r['dist_km']} km away "
                    f"(Score: {r['score']:.2f})"
                )

        print("-" * 65)


if __name__ == "__main__":
    # If a dataset filepath is passed as argument, use it; otherwise demo data
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        print(f"Loading dataset: {filepath}")
        patients, doctors, timeslots = load_dataset(filepath)
        print(f"  {len(patients)} patients, {len(doctors)} doctors, "
              f"{len(timeslots)} timeslots")
    else:
        print("Using built-in demo data (pass a JSON file path to use a dataset)")
        patients, doctors, timeslots = build_demo_data()

    results = optimize_all_patients(patients, doctors, timeslots)
    print_results(results)
