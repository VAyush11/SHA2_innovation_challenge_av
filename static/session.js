<script>
const VIDEO = document.querySelector("video"); // your webcam video element
const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d");

async function startSession() {
  await fetch("/api/session/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ threshold: 30.0 })
  });
}

function grabFrameDataURL() {
  const w = VIDEO.videoWidth, h = VIDEO.videoHeight;
  canvas.width = w; canvas.height = h;
  ctx.drawImage(VIDEO, 0, 0, w, h);
  return canvas.toDataURL("image/jpeg", 0.85);
}

function renderStatus(score, status) {
  document.getElementById("frameScoreText").textContent = score.toFixed(2);

  const badge = document.getElementById("formStatusBadge");
  if (status === "CORRECT") {
    badge.textContent = "✓ CORRECT FORM";
    badge.classList.remove("wrong");
    badge.classList.add("correct");
  } else {
    badge.textContent = "✗ WRONG FORM";
    badge.classList.remove("correct");
    badge.classList.add("wrong");
  }
}

function renderFeedback(items) {
  const box = document.getElementById("feedbackList");
  box.innerHTML = "";

  (items || []).slice(0, 4).forEach(txt => {
    const div = document.createElement("div");
    div.className = "feedback-item";
    div.textContent = txt;
    box.appendChild(div);
  });
}

async function pollFeedback() {
  if (!VIDEO.videoWidth) return; // camera not ready

  const frame_b64 = grabFrameDataURL();
  const r = await fetch("/api/live_feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ frame_b64 })
  });
  const out = await r.json();

  renderStatus(out.frame_score, out.form_status);
  renderFeedback(out.llm_feedback);
}

(async function init() {
  await startSession();
  setInterval(pollFeedback, 2000);
})();
</script>