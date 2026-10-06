"""Accurate payload exposure check."""

import json
from sqlmodel import Session, create_engine, select
from backend.models import Attack

def check_exposure_accurate():
    engine = create_engine("sqlite:///runs/gauntlet.db")
    with Session(engine) as session:
        attacks = session.exec(select(Attack)).all()

    channel_stats = {
        "email": {"total": 0, "exposed": 0},
        "web_page": {"total": 0, "exposed": 0},
        "document": {"total": 0, "exposed": 0},
    }

    unexposed = []

    for i, a in enumerate(attacks):
        trace = json.loads(a.trace_json)
        payload = a.payload.strip()
        ch = a.channel
        channel_stats[ch]["total"] += 1

        exposed = False
        for call in trace:
            res = call.get("result", {})
            if isinstance(res, dict):
                # check common result text fields
                email_obj = res.get("email")
                if isinstance(email_obj, dict):
                    content = email_obj.get("body", "")
                else:
                    content = res.get("content", "")
                if not content:
                    content = str(res)
            else:
                content = str(res)

            if payload in content:
                exposed = True
                break

        if exposed:
            channel_stats[ch]["exposed"] += 1
        else:
            unexposed.append((i, ch, a.category, [c.get("tool") for c in trace]))

    print("=" * 60)
    print("ACCURATE PAYLOAD EXPOSURE BY CHANNEL:")
    print("=" * 60)
    tot_exp = sum(s["exposed"] for s in channel_stats.values())
    tot_att = sum(s["total"] for s in channel_stats.values())
    for ch, s in channel_stats.items():
        pct = (s["exposed"] / s["total"] * 100.0) if s["total"] > 0 else 0.0
        print(f"  {ch:<10}: {s['exposed']}/{s['total']} ({pct:.1f}%)")
    print(f"  OVERALL   : {tot_exp}/{tot_att} ({tot_exp/tot_att*100:.1f}%)")

    if unexposed:
        print(f"\nUnexposed attacks count: {len(unexposed)}")
        for idx, ch, cat, tools in unexposed[:10]:
            print(f"  Attack {idx} [{ch}/{cat}]: tools={tools}")

    engine.dispose()

if __name__ == "__main__":
    check_exposure_accurate()
