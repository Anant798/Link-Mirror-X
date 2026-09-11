"""
linkmirror_engine.py

This is your original LinkMirror X visual-comparison logic
(analyze_url_heuristic, ORB/ResNet fusion scoring, decide_trust),
pulled out of linkmirror_5_0.py and stripped of all Streamlit
dependencies so it can be:

  1. Called directly by linkmirror_5_0.py (the original app UI)
  2. Called automatically by the new email forensic pipeline whenever
     it finds a suspicious URL inside an email

Nothing about the actual detection logic has changed — same ORB +
ResNet50 fusion (0.4/0.6 weighting), same URL heuristic checks, same
decision rules. Two things WERE fixed:

  - The hardcoded `C:\\tmp` path (crashed on non-Windows) now uses the
    system's actual temp directory.
  - `st.cache_resource` (Streamlit-only) replaced with a plain
    module-level cache so this works outside Streamlit too.
"""

from __future__ import annotations
import os
import tempfile
import datetime
from typing import List, Tuple, Optional
from dataclasses import dataclass

import numpy as np
import cv2
from PIL import Image
from sklearn.metrics.pairwise import cosine_similarity

# ---------------------------
# Safe, cross-platform temp dir (fixes the Windows-only C:\tmp bug)
# ---------------------------
tempfile.tempdir = tempfile.gettempdir()

# ---------------------------
# Optional torch / ResNet50
# ---------------------------
try:
    import torch
    from torchvision import models, transforms
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

_resnet_model = None
_resnet_transform = None


def _load_resnet_torch():
    """Loads ResNet50 once and caches it at module level (works with or
    without Streamlit, unlike the original @st.cache_resource version)."""
    global _resnet_model, _resnet_transform
    if _resnet_model is not None:
        return _resnet_model, _resnet_transform
    if not TORCH_AVAILABLE:
        return None, None
    try:
        model = models.resnet50(pretrained=True)
        model.eval()
        model = torch.nn.Sequential(*(list(model.children())[:-1]))
        transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                  std=[0.229, 0.224, 0.225])
        ])
        _resnet_model, _resnet_transform = model, transform
    except Exception:
        _resnet_model, _resnet_transform = None, None
    return _resnet_model, _resnet_transform


# ---------------------------
# Visual comparators (unchanged logic from linkmirror_5_0.py)
# ---------------------------
def compute_orb_similarity_cv(img_cv_q, img_cv_ref, nfeatures=800) -> float:
    orb = cv2.ORB_create(nfeatures)
    kp1, des1 = orb.detectAndCompute(img_cv_q, None)
    kp2, des2 = orb.detectAndCompute(img_cv_ref, None)
    if des1 is None or des2 is None or len(kp1) == 0 or len(kp2) == 0:
        return 0.0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    n_matches = len(matches)
    denom = min(len(kp1), len(kp2))
    if denom == 0:
        return 0.0
    return n_matches / denom


def compute_resnet_similarity_pil(pil_q, pil_ref) -> float:
    model, transform = _load_resnet_torch()
    if model is None:
        return 0.0
    try:
        tq = transform(pil_q).unsqueeze(0)
        tr = transform(pil_ref).unsqueeze(0)
        with torch.no_grad():
            f_q = model(tq).cpu().numpy().reshape(1, -1)
            f_r = model(tr).cpu().numpy().reshape(1, -1)
        return float(cosine_similarity(f_q, f_r)[0][0])
    except Exception:
        return 0.0


@dataclass
class ScreenshotMatch:
    reference_name: str
    score_pct: float
    orb_similarity: float
    resnet_similarity: float


def analyze_screenshot_against_refs(
    pil_query: Image.Image, ref_dir: str = "reference_images"
) -> Tuple[Optional[str], float, List[ScreenshotMatch]]:
    """
    Compares a query screenshot against every image in ref_dir.
    Returns (best_match_name, best_score_pct, all_results).
    Identical logic to the original app — same 0.4 ORB / 0.6 ResNet fusion.
    """
    if not os.path.isdir(ref_dir):
        raise FileNotFoundError(f"Reference directory not found: {ref_dir}")

    query_cv = np.array(pil_query.convert("RGB"))[:, :, ::-1]
    best_name = None
    best_score = -1.0
    results: List[ScreenshotMatch] = []

    for fname in os.listdir(ref_dir):
        if not fname.lower().endswith((".png", ".jpg", ".jpeg")):
            continue
        path = os.path.join(ref_dir, fname)
        try:
            ref_pil = Image.open(path).convert("RGB")
        except Exception:
            continue
        ref_cv = np.array(ref_pil)[:, :, ::-1]

        try:
            orb_sim = compute_orb_similarity_cv(query_cv, ref_cv)
        except Exception:
            orb_sim = 0.0
        try:
            resnet_sim = compute_resnet_similarity_pil(pil_query, ref_pil)
        except Exception:
            resnet_sim = 0.0

        combined = 0.4 * orb_sim + 0.6 * resnet_sim
        score_pct = combined * 100
        results.append(ScreenshotMatch(fname, round(score_pct, 2), orb_sim, resnet_sim))

        if score_pct > best_score:
            best_score = score_pct
            best_name = fname

    results.sort(key=lambda r: r.score_pct, reverse=True)
    return best_name, round(best_score, 2), results


# ---------------------------
# URL heuristic analyzer (unchanged logic)
# ---------------------------
def analyze_url_heuristic(url: str) -> Tuple[int, List[str]]:
    reasons = []
    s = 100
    if not url:
        return 50, ["No URL provided."]
    u = url.strip().lower()
    if not u.startswith("http"):
        u = "http://" + u
    if u.startswith("https://"):
        reasons.append("HTTPS present")
    else:
        reasons.append("No HTTPS")
        s -= 15

    tokens = ['login', 'verify', 'secure', 'update', 'account', 'bank',
              'signin', 'paypal', 'free', 'bonus']
    count = sum(1 for t in tokens if t in u)
    if count > 0:
        reasons.append(f"Suspicious token(s) found: {count}")
        s -= min(20, 5 * count)

    if len(u) > 60:
        reasons.append("URL unusually long")
        s -= 5
    else:
        reasons.append("URL length ok")

    try:
        import tldextract
        ext = tldextract.extract(u)
        if ext.suffix in ("xyz", "top", "club", "click", "work", "party", "zip"):
            reasons.append(f"Suspicious TLD: .{ext.suffix}")
            s -= 10
        else:
            reasons.append(f"TLD: .{ext.suffix}")
    except Exception:
        reasons.append("TLD check unavailable")

    try:
        import whois
        domain = u.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd:
            age_days = (datetime.datetime.now() - cd).days
            if age_days < 180:
                reasons.append("Domain very new (<6 months)")
                s -= 10
            else:
                reasons.append("Domain age OK")
        else:
            reasons.append("WHOIS: no creation date")
            s -= 5
    except Exception:
        reasons.append("WHOIS check failed or not available")

    s = max(0, min(100, s))
    return s, reasons


def fused_score(url_score: float, img_score: float) -> float:
    if img_score is None or img_score < 0:
        w_img = 0.05
    else:
        if img_score >= 85:
            w_img = 0.6
        elif img_score >= 60:
            w_img = 0.35
        else:
            w_img = 0.1
    w_url = 1.0 - w_img
    final = round(w_url * url_score + w_img * max(img_score, 0), 2)
    return final


def decide_trust(url_score, img_score, best_ref_name=None, v_high=85, v_mid=60):
    reasons = []
    if url_score is None:
        url_score = 50
        reasons.append("URL score missing — treated as neutral.")
    if img_score is None:
        img_score = -1

    if img_score >= v_high:
        reasons.append(f"Strong visual match to reference: {best_ref_name} ({img_score:.1f}%)")
    elif img_score >= v_mid:
        reasons.append(f"Weak visual similarity to references ({img_score:.1f}%)")
    elif img_score >= 0:
        reasons.append("No significant visual match to references.")
    else:
        reasons.append("No screenshot available for visual comparison.")

    if url_score >= 80:
        reasons.append("URL heuristics indicate low risk.")
    elif url_score >= 60:
        reasons.append("URL heuristics indicate moderate risk.")
    else:
        reasons.append("URL heuristics indicate high risk.")

    if img_score >= v_high and url_score >= 60:
        verdict = "Likely genuine (visual clone of known reference; URL not strongly suspicious)"
        color = "green"
    elif img_score >= v_high and url_score < 60:
        verdict = "High risk — visual clone + suspicious URL (likely phishing)"
        color = "red"
    elif v_mid <= img_score < v_high and url_score < 60:
        verdict = "Suspicious — partial visual match + risky URL"
        color = "orange"
    elif img_score < v_mid and url_score >= 80:
        verdict = "Unknown site but URL looks safe — manual check recommended"
        color = "blue"
    elif img_score < v_mid and url_score < 80:
        verdict = "Unknown site & URL heuristics suspicious — treat as risky"
        color = "red"
    else:
        verdict = "Mixed signals — manual review recommended"
        color = "orange"

    return verdict, color, reasons


# ---------------------------
# High-level convenience function for the forensic pipeline:
# given a URL and a screenshot (real or demo-mode), run the full
# analysis and return one clean result object.
# ---------------------------
@dataclass
class EngineResult:
    url: str
    url_score: int
    url_reasons: List[str]
    screenshot_best_match: Optional[str]
    screenshot_score: float
    verdict: str
    verdict_color: str
    verdict_reasons: List[str]
    fused: float


def analyze_url_and_screenshot(
    url: str,
    screenshot: Optional[Image.Image],
    ref_dir: str = "reference_images",
) -> EngineResult:
    url_score, url_reasons = analyze_url_heuristic(url)

    img_score = -1.0
    best_name = None
    if screenshot is not None:
        try:
            best_name, img_score, _ = analyze_screenshot_against_refs(screenshot, ref_dir)
        except FileNotFoundError:
            img_score = -1.0

    verdict, color, verdict_reasons = decide_trust(url_score, img_score, best_ref_name=best_name)
    fused = fused_score(url_score, img_score)

    return EngineResult(
        url=url,
        url_score=url_score,
        url_reasons=url_reasons,
        screenshot_best_match=best_name,
        screenshot_score=img_score,
        verdict=verdict,
        verdict_color=color,
        verdict_reasons=verdict_reasons,
        fused=fused,
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python linkmirror_engine.py <url> [screenshot_path]")
        sys.exit(1)

    url = sys.argv[1]
    screenshot = None
    if len(sys.argv) > 2:
        screenshot = Image.open(sys.argv[2]).convert("RGB")

    result = analyze_url_and_screenshot(url, screenshot)
    print(f"URL score: {result.url_score}")
    for r in result.url_reasons:
        print(f"  - {r}")
    print(f"Screenshot best match: {result.screenshot_best_match} ({result.screenshot_score:.2f}%)")
    print(f"Verdict: {result.verdict}")
    for r in result.verdict_reasons:
        print(f"  - {r}")
    print(f"Fused score: {result.fused}")
