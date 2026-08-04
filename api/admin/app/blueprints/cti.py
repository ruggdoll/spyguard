#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, request
from app.decorators import require_header_token
from app import db
from app.db.models import CTIQuarantine

import time

cti_bp = Blueprint("cti", __name__)


@cti_bp.route("/quarantine", methods=["GET"])
@require_header_token
def get_quarantine():
    """Return all quarantine events (active and expired)."""
    now = int(time.time())
    rows = db.session.query(CTIQuarantine).all()
    results = []
    for r in rows:
        expires_at = int(r.started_at) + int(r.duration_days) * 86400
        results.append({
            "id": r.id,
            "name": r.name,
            "reason": r.reason,
            "started_at": int(r.started_at),
            "duration_days": int(r.duration_days),
            "expires_at": expires_at,
            "active": expires_at > now,
        })
    return jsonify({"status": True, "results": results})


@cti_bp.route("/quarantine/add", methods=["POST"])
@require_header_token
def add_quarantine():
    """Add a post-exposure quarantine event.

    Body (JSON):
        name         – short label, e.g. "Pegasus cluster 2024-07"
        reason       – free-text reason / source report
        duration_days – optional, defaults to 42 (6 weeks)
    """
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"status": False, "message": "name is required"})
    reason = (data.get("reason") or "").strip()
    try:
        duration_days = int(data.get("duration_days") or 42)
        if duration_days < 1:
            duration_days = 42
    except (TypeError, ValueError):
        duration_days = 42

    db.session.add(CTIQuarantine(name, reason, int(time.time()), duration_days))
    db.session.commit()
    return jsonify({
        "status": True,
        "message": "Quarantine event created",
        "duration_days": duration_days,
    })


@cti_bp.route("/quarantine/delete/<int:event_id>", methods=["DELETE"])
@require_header_token
def delete_quarantine(event_id):
    """Delete a quarantine event by id."""
    row = db.session.query(CTIQuarantine).filter_by(id=event_id).first()
    if row is None:
        return jsonify({"status": False, "message": "Event not found"})
    db.session.delete(row)
    db.session.commit()
    return jsonify({"status": True, "message": "Quarantine event deleted"})
