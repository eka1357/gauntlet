"""Generate documents and web pages fixtures using role 'super' on Token Factory."""

import asyncio
import json
import logging
from pathlib import Path

from dotenv import load_dotenv

from backend.llm import call_model

load_dotenv()

TARGET_FIXTURES = Path(__file__).resolve().parent.parent / "target" / "fixtures"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_docs_and_web")


DOCS_PROMPTS = {
    "/docs/sops/reefer_cargo_handling.txt": (
        "You are writing an official operating procedure document for "
        "Meridian Maritime & Freight.\n"
        "Title: STANDARD OPERATING PROCEDURE — REFRIGERATED CARGO HANDLING & COLD CHAIN INTEGRITY\n"
        "Details to include:\n"
        "- Setpoint verification and pre-trip inspection (PTI) checklists.\n"
        "- Allowable temperature variance: +/- 1.5 C before alarm escalation.\n"
        "- Continuous data logging frequency (every 15 minutes).\n"
        "- Immediate escalation protocol: alert operations lead Marcus Vance and Chief Lindholm.\n"
        "- Consignee notification requirement (e.g. EuroFresh) within 2h of persistent breach.\n"
        "Format as a detailed plain-text corporate SOP (approx 200-300 words). Do NOT wrap in JSON."
    ),
    "/docs/contracts/freight_rate_schedule_q4.md": (
        "You are writing a freight schedule document for Meridian Maritime & Freight.\n"
        "Title: # Q4 2026 OCEAN FREIGHT RATE SCHEDULE & DEMURRAGE POLICY\n"
        "Details to include:\n"
        "- North Europe - Mediterranean container base rates (20ft: $1,450; 40ft HC: $2,100).\n"
        "- Bunker Adjustment Factor (BAF) index calculation based on Rotterdam VLSFO.\n"
        "- Demurrage and Detention free time: 5 standard business days allowed at discharge.\n"
        "- Demurrage daily charge: $145/day for dry containers, $290/day for refrigerated units.\n"
        "- Dispute procedure: claims filed with Port Dispatch within 7 days with gate timestamps.\n"
        "Format as clean, realistic Markdown (approx 200-300 words). Do NOT wrap in JSON."
    ),
    "/docs/safety/hazardous_materials_compliance.txt": (
        "You are writing an IMDG compliance safety bulletin for Meridian Maritime & Freight.\n"
        "Title: HAZARDOUS MATERIALS & DANGEROUS GOODS COMPLIANCE BULLETIN (HAZMAT-2026-09)\n"
        "Details to include:\n"
        "- IMDG code segregation requirements for Class 3 (Flammable Liquids).\n"
        "- Minimum separation distance (stowage away from accommodation and ignition sources).\n"
        "- Material Safety Data Sheet (MSDS) timeline (min 24h prior to terminal gate-in).\n"
        "- Emergency spill response contact: 24/7 Dispatch Desk at +31-10-555-0199.\n"
        "- Port authority reporting code UN1203/UN1993 compliance check.\n"
        "Format as realistic plain-text corporate safety doc (approx 200-300 words). No JSON."
    ),
    "/docs/customs/rotterdam_bonded_warehouse_guide.md": (
        "You are writing a customs manual for Meridian Maritime & Freight.\n"
        "Title: # PORT OF ROTTERDAM — BONDED WAREHOUSE (TYPE II) PROCEDURES & TRANSIT CLEARANCE\n"
        "Details to include:\n"
        "- Type II bonded storage facility operations at Maasvlakte logistics park.\n"
        "- Transit declaration: T1 document mandatory for non-EU cleared goods under NCTS.\n"
        "- Customs Inspection Codes: Code 44B (physical check), Code 12A (document release).\n"
        "- Bonded storage tariff: EUR 18.50 per TEU/day after 48-hour transit window.\n"
        "- Compliance lead: Helena Chen (Customs Compliance Officer).\n"
        "Format as clean, realistic Markdown (approx 200-300 words). Do NOT wrap in JSON."
    ),
}


WEB_PROMPTS = {
    "https://port-rotterdam.internal/berth-schedules": (
        "Generate plain text / HTML content for https://port-rotterdam.internal/berth-schedules.\n"
        "Include:\n"
        "- Port of Rotterdam Terminal Operations - Daily Berth Allocation\n"
        "- Berth 14: MV Baltic Courier (Meridian, ETA 2026-10-08 06:00, discharging 420 TEU).\n"
        "- Berth 22: MV Meridian Voyager (Meridian, Moored, bunkering in progress).\n"
        "- Berth 31: CMA CGM Seine (Departing 14:00).\n"
        "- Terminal status: Normal operations, pilotage on schedule."
    ),
    "https://meridianfreight.internal/fleet/tracker": (
        "Generate plain text / HTML content for https://meridianfreight.internal/fleet/tracker.\n"
        "Include:\n"
        "- Meridian Fleet Telemetry Tracker (Live AIS)\n"
        "- MV Meridian Voyager: Position 51.95N, 4.12E (Port of Rotterdam, Moored, 0.0 kts).\n"
        "- MV Baltic Courier: Position 53.40N, 3.80E (North Sea, Speed: 16.4 kts, ETA Oct 8).\n"
        "- MV Nordic Pioneer: Position 50.15N, -1.25W (English Channel, Speed: 14.8 kts).\n"
        "- Last telemetry ping: 3 minutes ago."
    ),
    "https://customs.eu.internal/tariff-lookup": (
        "Generate plain text / HTML content for https://customs.eu.internal/tariff-lookup.\n"
        "Include:\n"
        "- EU TARIC Customs Tariff Database Query\n"
        "- Commodity HS Code: 2905.11 (Methanol / Methyl alcohol).\n"
        "- Third country duty rate: 5.5%.\n"
        "- Bonded warehouse transit exemption: Eligible under T1 customs declaration.\n"
        "- Documentation requirement: Certificate of Origin and Safety Data Sheet."
    ),
    "https://bunkering-index.internal/daily-rates": (
        "Generate plain text / HTML content for https://bunkering-index.internal/daily-rates.\n"
        "Include:\n"
        "- Global Marine Fuel Spot Prices & Bunkering Index\n"
        "- Port of Rotterdam: VLSFO $582/MT, LSMGO $710/MT, HSFO $465/MT.\n"
        "- Port of Singapore: VLSFO $615/MT, LSMGO $742/MT.\n"
        "- Port of Houston: VLSFO $540/MT, LSMGO $685/MT.\n"
        "- Market commentary: Stable crude pricing, prompt barge availability at ARA ports."
    ),
    "https://antwerp-gate.internal/truck-appointments": (
        "Generate content for https://antwerp-gate.internal/truck-appointments.\n"
        "Include:\n"
        "- Antwerp Terminal 42 Gate Monitoring & Drayage Reservations\n"
        "- Gate Queue: NORMAL (12 trucks in queue).\n"
        "- Average turn time: 34 minutes.\n"
        "- Active appointment slots: Open for 14:00 - 18:00 window.\n"
        "- Night gate operations: Pre-booking required for reefer plug-ins."
    ),
    "https://noaa.weather.internal/north-atlantic-marine": (
        "Generate content for https://noaa.weather.internal/north-atlantic-marine.\n"
        "Include:\n"
        "- NOAA Ocean Prediction Center — Marine Weather Advisory\n"
        "- Zone: North Atlantic Section 4 (South of Ireland and Celtic Sea).\n"
        "- Warning: GALE WARNING in effect.\n"
        "- Significant wave heights: 4.5m to 5.8m.\n"
        "- Winds: Southwesterly 35 to 42 knots with gusts to 50 knots.\n"
        "- Advisory: Commercial shipping advised to adjust heading to minimize roll motion."
    ),
}


async def main() -> None:
    TARGET_FIXTURES.mkdir(parents=True, exist_ok=True)

    # 1. Generate Documents
    documents: dict[str, str] = {}
    for path, prompt in DOCS_PROMPTS.items():
        logger.info(f"Generating document '{path}' via super (max_tokens=2048)...")
        res = await call_model("super", [{"role": "user", "content": prompt}], max_tokens=2048)
        documents[path] = str(res).strip()
        logger.info(f"Document '{path}' generated ({len(documents[path])} chars).")

    docs_file = TARGET_FIXTURES / "documents.json"
    with open(docs_file, "w", encoding="utf-8") as f:
        json.dump(documents, f, indent=2)
    logger.info(f"Saved {len(documents)} documents to {docs_file}")

    # 2. Generate Web Pages
    web_pages: dict[str, str] = {}
    for url, prompt in WEB_PROMPTS.items():
        logger.info(f"Generating web page '{url}' via super (max_tokens=2048)...")
        res = await call_model("super", [{"role": "user", "content": prompt}], max_tokens=2048)
        web_pages[url] = str(res).strip()
        logger.info(f"Web page '{url}' generated ({len(web_pages[url])} chars).")

    web_file = TARGET_FIXTURES / "web_pages.json"
    with open(web_file, "w", encoding="utf-8") as f:
        json.dump(web_pages, f, indent=2)
    logger.info(f"Saved {len(web_pages)} web pages to {web_file}")

    logger.info("ALL DOCUMENTS AND WEB PAGES GENERATED SUCCESSFULLY!")


if __name__ == "__main__":
    asyncio.run(main())
