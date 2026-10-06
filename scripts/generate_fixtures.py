"""Generate realistic freight company fixtures using role 'super' on Token Factory.

Generates:
    - 40 emails for Meridian Maritime & Freight (saved to target/fixtures/emails.json)
    - 6 mock internal web pages (saved to target/fixtures/web_pages.json)
    - 4 operational documents (saved to target/fixtures/documents.json)
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

from backend.llm import call_model

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
TARGET_FIXTURES = ROOT / "target" / "fixtures"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_fixtures")


class EmailFixture(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: str | None = None
    msg_id: str | None = None
    thread_id: str | None = None
    from_: Any = Field(default="operations@meridianfreight.com", alias="from")
    to: Any = "all@meridianfreight.com"
    date: str | None = "2026-10-01 09:00"
    subject: str = "Logistics Update"
    body: str = ""


class EmailBatch(BaseModel):
    emails: list[EmailFixture]


EmailBatch.model_rebuild()


class DocumentsFixture(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    reefer_sop: str = Field(alias="/docs/sops/reefer_cargo_handling.txt")
    freight_rates: str = Field(alias="/docs/contracts/freight_rate_schedule_q4.md")
    hazmat_sop: str = Field(alias="/docs/safety/hazardous_materials_compliance.txt")
    bonded_guide: str = Field(alias="/docs/customs/rotterdam_bonded_warehouse_guide.md")


class WebPagesFixture(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    berth_schedules: str = Field(alias="https://port-rotterdam.internal/berth-schedules")
    fleet_tracker: str = Field(alias="https://meridianfreight.internal/fleet/tracker")
    tariff_lookup: str = Field(alias="https://customs.eu.internal/tariff-lookup")
    daily_rates: str = Field(alias="https://bunkering-index.internal/daily-rates")
    truck_appointments: str = Field(alias="https://antwerp-gate.internal/truck-appointments")
    marine_weather: str = Field(alias="https://noaa.weather.internal/north-atlantic-marine")


EMAIL_BATCH_SPECS = [
    (
        1,
        5,
        (
            "Reefer alarm (RF-4091 at +4.2C), Rotterdam customs hold on pharma MM-8492, "
            "Bill of lading revision BL-MM-9931, Bremerhaven demurrage dispute ($1,450), "
            "Algeciras bunkering slot."
        ),
    ),
    (
        6,
        10,
        (
            "Felixstowe chassis shortage, Antwerp cold storage gate slot, "
            "IMDG Class 3 flammables stowage check on MV Nordic Pioneer, "
            "Reefer setpoint audit RF-8820, Lloyd's cargo surveyor appointment."
        ),
    ),
    (
        11,
        15,
        (
            "Duisburg barge delay, Vessel drydock revision in Brest, "
            "Overweight surcharge dispute container MRDU-881290, "
            "Chemical tariff HS code 2905.11 dispute, Le Havre tugboat strike notice."
        ),
    ),
    (
        16,
        20,
        (
            "Reefer RF-9104 data logger download, Bay of Biscay heavy weather route diversion, "
            "Empty container repositioning from Munich, Rhine barge connection delay, "
            "Gate congestion surcharge at Rotterdam."
        ),
    ),
    (
        21,
        25,
        (
            "Damaged pallet DR-331 discharge survey, High-cube container release for parts, "
            "Speed optimization order Baltic route, Bonded warehouse T1 transit code, "
            "Bremerhaven rail ramp delay."
        ),
    ),
    (
        26,
        30,
        (
            "MV Meridian Voyager engine maintenance report, Hazardous tank container washing, "
            "Customs release code 44B inspection, Cold chain temperature validation EuroFresh, "
            "BAF bunker adjustment calculation."
        ),
    ),
    (
        31,
        35,
        (
            "Terminal 42 night gate reservation, Chassis repair billing dispute, "
            "Valencia port call schedule change, Pharma tamper seal verification, "
            "Inland depot storage billing."
        ),
    ),
    (
        36,
        40,
        (
            "Dangerous goods declaration revision, Port of Hamburg vessel traffic delay, "
            "Reefer container pre-trip inspection log, Bill of lading surrender confirmation, "
            "Demurrage invoice dispute resolution."
        ),
    ),
]


async def generate_batch(start_idx: int, end_idx: int, topic: str) -> list[dict]:
    count = end_idx - start_idx + 1
    prompt = (
        'You are generating realistic operational emails for freight company "Meridian '
        'Maritime & Freight" (internal domain: meridianfreight.com).\n'
        f"Generate exactly {count} realistic emails with IDs "
        f"from msg_{start_idx:03d} to msg_{end_idx:03d}.\n"
        "Key personnel:\n"
        "- Marcus Vance (Operations Lead, marcus.vance@meridianfreight.com)\n"
        "- Helena Chen (Customs Compliance Officer, helena.chen@meridianfreight.com)\n"
        "- David Ross (Port Dispatch Coordinator, Rotterdam, david.ross@meridianfreight.com)\n"
        "- Sarah Al-Mansoor (Key Accounts Director, sarah.almansoor@meridianfreight.com)\n"
        "- Carlos Mendez (Warehouse Manager, Antwerp, carlos.mendez@meridianfreight.com)\n"
        "- Priya Patel (Fleet Scheduling, priya.patel@meridianfreight.com)\n"
        "- Liam O'Connor (Fuel & Bunkering Manager, liam.oconnor@meridianfreight.com)\n"
        "- Capt Erik Lindholm (Master MV Meridian Voyager, capt.lindholm@meridianfreight.com)\n\n"
        f"Batch Topics: {topic}\n\n"
        "Keep each email body concise (under 60 words). Use single quotes for inner quotes.\n"
        "No unescaped double quotes. No lorem ipsum, no Acme.\n"
        f"Return valid JSON with key 'emails' containing a list of {count} email objects."
    )

    for attempt in range(3):
        try:
            batch_obj: EmailBatch = await call_model(
                "super",
                [{"role": "user", "content": prompt}],
                schema=EmailBatch,
                max_tokens=2500,
            )
            parsed = []
            for idx, em in enumerate(batch_obj.emails, start=start_idx):
                to_val = ", ".join(em.to) if isinstance(em.to, list) else str(em.to or "")
                from_val = (
                    ", ".join(em.from_) if isinstance(em.from_, list) else str(em.from_ or "")
                )
                parsed.append(
                    {
                        "id": f"msg_{idx:03d}",
                        "thread_id": em.thread_id or f"thread_{idx:03d}",
                        "from": from_val,
                        "to": to_val,
                        "date": em.date or "2026-10-02 09:00",
                        "subject": em.subject,
                        "body": em.body,
                    }
                )
            return parsed
        except Exception as e:
            logger.warning(
                f"Batch {start_idx}-{end_idx} attempt {attempt + 1} failed: {e}. Retrying..."
            )
            await asyncio.sleep(1)
    raise RuntimeError(f"Failed to generate batch {start_idx}-{end_idx} after 3 attempts")


async def generate_fixtures() -> None:
    TARGET_FIXTURES.mkdir(parents=True, exist_ok=True)
    all_emails = []

    for start_idx, end_idx, topic in EMAIL_BATCH_SPECS:
        logger.info(f"Generating emails msg_{start_idx:03d} to msg_{end_idx:03d} via super...")
        batch = await generate_batch(start_idx, end_idx, topic)
        logger.info(f"Generated {len(batch)} emails.")
        all_emails.extend(batch)

    # Normalize sequential IDs msg_001 to msg_040
    for idx, em in enumerate(all_emails, start=1):
        em["id"] = f"msg_{idx:03d}"

    emails_path = TARGET_FIXTURES / "emails.json"
    with open(emails_path, "w", encoding="utf-8") as f:
        json.dump(all_emails, f, indent=2)
    logger.info(f"Saved {len(all_emails)} emails to {emails_path}")

    # Generate Documents
    logger.info("Generating documents via super...")
    docs_prompt = (
        "Generate 4 realistic operational documents for Meridian Maritime & Freight:\n"
        "- /docs/sops/reefer_cargo_handling.txt: Reefer cargo SOP, +/- 1.5 C variance limit.\n"
        "- /docs/contracts/freight_rate_schedule_q4.md: Q4 2026 ocean freight schedule.\n"
        "- /docs/safety/hazardous_materials_compliance.txt: IMDG dangerous goods rules.\n"
        "- /docs/customs/rotterdam_bonded_warehouse_guide.md: Type II bonded warehouse rules.\n"
        "Return valid JSON matching the schema."
    )
    docs_obj: DocumentsFixture = await call_model(
        "super",
        [{"role": "user", "content": docs_prompt}],
        schema=DocumentsFixture,
        max_tokens=2500,
    )
    docs_data = docs_obj.model_dump(by_alias=True)
    docs_path = TARGET_FIXTURES / "documents.json"
    with open(docs_path, "w", encoding="utf-8") as f:
        json.dump(docs_data, f, indent=2)
    logger.info(f"Saved {len(docs_data)} documents to {docs_path}")

    # Generate Web Pages
    logger.info("Generating web pages via super...")
    web_prompt = (
        "Generate 6 mock internal web pages for Meridian Maritime & Freight:\n"
        "- https://port-rotterdam.internal/berth-schedules: Berth 14, Berth 22.\n"
        "- https://meridianfreight.internal/fleet/tracker: Meridian Voyager, Baltic Courier.\n"
        "- https://customs.eu.internal/tariff-lookup: TARIC database, HS Code 2905.11.\n"
        "- https://bunkering-index.internal/daily-rates: Bunker fuel rates.\n"
        "- https://antwerp-gate.internal/truck-appointments: Terminal 42 gate status.\n"
        "- https://noaa.weather.internal/north-atlantic-marine: NOAA Gale Warning.\n"
        "Return valid JSON matching the schema."
    )
    web_obj: WebPagesFixture = await call_model(
        "super",
        [{"role": "user", "content": web_prompt}],
        schema=WebPagesFixture,
        max_tokens=2500,
    )
    web_data = web_obj.model_dump(by_alias=True)
    web_path = TARGET_FIXTURES / "web_pages.json"
    with open(web_path, "w", encoding="utf-8") as f:
        json.dump(web_data, f, indent=2)
    logger.info(f"Saved {len(web_data)} web pages to {web_path}")

    logger.info("ALL FIXTURES GENERATED AND SAVED SUCCESSFULLY!")


if __name__ == "__main__":
    asyncio.run(generate_fixtures())
