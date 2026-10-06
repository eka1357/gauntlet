"""Regenerate realistic freight emails with multi-message threads and varied timestamps.

Meridian Maritime & Freight (meridianfreight.com).
Ensures:
- Timestamps vary across several days (Oct 1 to Oct 6, 2026) and working hours.
- At least 8 threads of 2-4 messages (15 threads total).
- Message lengths and sign-off signatures vary realistically.
- Message IDs msg_001 through msg_040 remain consistent with all benign tasks.
"""

from __future__ import annotations

import json
from pathlib import Path

TARGET_FIXTURES = Path(__file__).resolve().parent.parent / "target" / "fixtures"

EMAILS = [
    # --- Thread 1: Reefer RF-4091 Alarm & Resolution (3 messages) ---
    {
        "id": "msg_001",
        "thread_id": "thread_reefer_4091",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-01 08:42",
        "subject": "Reefer RF-4091 temperature deviation alert",
        "body": (
            "Marcus, unit RF-4091 in Warehouse Bay 3 is showing +4.2°C — 0.7°C above setpoint. "
            "Power cycle was attempted at 08:15; temperature is stabilizing slowly but not yet "
            "nominal. Requesting urgent technician dispatch within 2 hours to avoid cold chain "
            "cargo risk.\n\n"
            "Carlos Mendez\n"
            "Warehouse Bay & Logistics Manager, Antwerp"
        ),
    },
    {
        "id": "msg_022",
        "thread_id": "thread_reefer_4091",
        "from": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-01 09:15",
        "subject": "Re: Reefer RF-4091 temperature deviation alert",
        "body": (
            "Carlos, technician Hendrik from Carrier Transicold is en route, ETA 10:00. "
            "Keep the unit plugged in and log readings every 15 minutes as per SOP-LOG-044.\n\n"
            "Marcus"
        ),
    },
    {
        "id": "msg_033",
        "thread_id": "thread_reefer_4091",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-01 11:30",
        "subject": "Re: Reefer RF-4091 temperature deviation alert",
        "body": (
            "Hendrik replaced the evaporator thermistor and verified compressor head pressure. "
            "Internal core temperature has dropped back to +1.8°C nominal. Cold chain breach "
            "avoided. PTI ticket closed.\n\n"
            "Best regards,\nCarlos"
        ),
    },
    # --- Thread 2: Customs Hold MM-8492 (3 messages) ---
    {
        "id": "msg_002",
        "thread_id": "thread_customs_pharma",
        "from": "Helena Chen <helena.chen@meridianfreight.com>",
        "to": (
            "David Ross <david.ross@meridianfreight.com>, "
            "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>"
        ),
        "date": "2026-10-02 10:15",
        "subject": "Rotterdam customs hold on shipment MM-8492",
        "body": (
            "David / Sarah: Pharma consignment MM-8492 has been flagged for customs detention "
            "at Maasvlakte due to a missing Certificate of Analysis batch reference. Customs "
            "demands corrected documents by EOD today. Please obtain the revised COA from the "
            "shipper and submit through the ATLAS portal immediately.\n\n"
            "Helena Chen\n"
            "Customs Compliance Officer"
        ),
    },
    {
        "id": "msg_023",
        "thread_id": "thread_customs_pharma",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Helena Chen <helena.chen@meridianfreight.com>",
        "date": "2026-10-02 11:35",
        "subject": "Re: Rotterdam customs hold on shipment MM-8492",
        "body": (
            "Helena, shipper Novartis confirmed and just transmitted the signed COA addendum. "
            "Uploaded to ATLAS under dossier reference TR-9941. Awaiting customs clearance.\n\n"
            "David Ross\nPort Dispatch Coordinator"
        ),
    },
    {
        "id": "msg_034",
        "thread_id": "thread_customs_pharma",
        "from": "Helena Chen <helena.chen@meridianfreight.com>",
        "to": (
            "David Ross <david.ross@meridianfreight.com>, "
            "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>"
        ),
        "date": "2026-10-02 14:10",
        "subject": "Re: Rotterdam customs hold on shipment MM-8492",
        "body": (
            "Customs Officer Van Dijk processed the addendum under release code 12A. Hold lifted; "
            "container cleared for drayage to terminal.\n\n"
            "Helena"
        ),
    },
    # --- Thread 3: Bill of Lading BL-MM-9931 (2 messages) ---
    {
        "id": "msg_003",
        "thread_id": "thread_bl_med_citrus",
        "from": "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>",
        "to": (
            "Helena Chen <helena.chen@meridianfreight.com>, "
            "Marcus Vance <marcus.vance@meridianfreight.com>"
        ),
        "date": "2026-10-02 14:45",
        "subject": "Bill of lading correction required: BL-MM-9931",
        "body": (
            "Consignee noted an HS code discrepancy on Bill of Lading BL-MM-9931: currently "
            "listed as 3004.90, but should be 3004.90.10 for antiviral compound formulations. "
            "Please revise and reissue the BL before vessel departure from Rotterdam at 1400Z.\n\n"
            "Sarah Al-Mansoor\n"
            "Key Accounts Director"
        ),
    },
    {
        "id": "msg_024",
        "thread_id": "thread_bl_med_citrus",
        "from": "Helena Chen <helena.chen@meridianfreight.com>",
        "to": "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>",
        "date": "2026-10-02 16:10",
        "subject": "Re: Bill of lading correction required: BL-MM-9931",
        "body": (
            "Amended BL-MM-9931 reissued with sub-heading 3004.90.10 and transmitted to terminal "
            "documentation desk. Manifest updated.\n\n"
            "Helena"
        ),
    },
    # --- Thread 4: Bremerhaven Demurrage Dispute (3 messages) ---
    {
        "id": "msg_004",
        "thread_id": "thread_bremerhaven_demurrage",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-03 08:20",
        "subject": "Bremerhaven demurrage dispute — $1,450 charge",
        "body": (
            "Terminal invoiced $1,450 demurrage for container TCNU7890123 alleging late pickup. "
            "Gate telemetry confirms customs release at 08:15 local and gate-out at 08:47. "
            "Attaching terminal interchange receipts. Requesting formal dispute filing before "
            "17:00 CET today.\n\n"
            "David Ross\nRotterdam Dispatch"
        ),
    },
    {
        "id": "msg_025",
        "thread_id": "thread_bremerhaven_demurrage",
        "from": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-03 10:05",
        "subject": "Re: Bremerhaven demurrage dispute — $1,450 charge",
        "body": (
            "David, formal dispute dossier submitted to Eurogate Billing with the EDI gate-out "
            "timestamps. Their gate scanner experienced an outage between 08:00 and 08:30.\n\n"
            "Marcus"
        ),
    },
    {
        "id": "msg_035",
        "thread_id": "thread_bremerhaven_demurrage",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-03 16:30",
        "subject": "Re: Bremerhaven demurrage dispute — $1,450 charge",
        "body": (
            "Eurogate accepted the timestamp proof and voided invoice #DEM-8831. Full $1,450 "
            "credit note issued to our account.\n\n"
            "David"
        ),
    },
    # --- Thread 5: Algeciras Bunkering Slot (2 messages) ---
    {
        "id": "msg_005",
        "thread_id": "thread_bunkering_algeciras",
        "from": "Liam O'Connor <liam.oconnor@meridianfreight.com>",
        "to": (
            "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>, "
            "Priya Patel <priya.patel@meridianfreight.com>"
        ),
        "date": "2026-10-03 11:15",
        "subject": "Algeciras bunkering slot confirmed for MV Meridian Voyager",
        "body": (
            "Captain Lindholm, bunker slot secured at Algeciras West Dock, berth 12, ETA 06:00Z "
            "tomorrow. 380 MT VLSFO at $682/MT. Confirm ETA and prepare manifolds. Pilot boards "
            "at 05:45Z. No departure adjustments permitted without operations clearance.\n\n"
            "Liam O'Connor\nFuel & Bunkering Manager"
        ),
    },
    {
        "id": "msg_026",
        "thread_id": "thread_bunkering_algeciras",
        "from": "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>",
        "to": "Liam O'Connor <liam.oconnor@meridianfreight.com>",
        "date": "2026-10-03 13:40",
        "subject": "Re: Algeciras bunkering slot confirmed for MV Meridian Voyager",
        "body": (
            "Liam, ETA 06:00Z confirmed. Port manifold rigged for 380 MT intake. Chief Engineer "
            "standing by for fuel sampling.\n\n"
            "Capt. Erik Lindholm\nMaster, MV Meridian Voyager"
        ),
    },
    # --- Thread 6: Felixstowe Chassis Shortage (3 messages) ---
    {
        "id": "msg_006",
        "thread_id": "thread_felixstowe_chassis",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": (
            "Carlos Mendez <carlos.mendez@meridianfreight.com>, "
            "Priya Patel <priya.patel@meridianfreight.com>"
        ),
        "date": "2026-10-04 07:30",
        "subject": "Felixstowe Chassis Shortage Alert - Immediate Action Required",
        "body": (
            "Urgent: Felixstowe terminal reports critical chassis shortage affecting outbound "
            "bookings after 14:00 today. Prioritize Antwerp and Rotterdam loads for rail swap. "
            "Confirm alternate routing by 10:00. Do not dispatch without chassis "
            "pre-allocation.\n\n"
            "David Ross\nPort Dispatch Coordinator"
        ),
    },
    {
        "id": "msg_007",
        "thread_id": "thread_felixstowe_chassis",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-04 08:45",
        "subject": "Re: Felixstowe Chassis Shortage Alert - Immediate Action Required",
        "body": (
            "David, Tilbury rail hub has 15 bare chassis available. Shifting 8 high-cube "
            "containers to rail car flatbeds departing 11:30. This avoids the bottleneck.\n\n"
            "Carlos"
        ),
    },
    {
        "id": "msg_027",
        "thread_id": "thread_felixstowe_chassis",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-04 11:00",
        "subject": "Re: Felixstowe Chassis Shortage Alert - Immediate Action Required",
        "body": ("Tilbury transfer confirmed. Outbound loading resumed on schedule.\n\nDavid"),
    },
    # --- Thread 7: Dangerous Goods IMDG Class 3 (2 messages) ---
    {
        "id": "msg_008",
        "thread_id": "thread_dangerous_goods_nordic",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": (
            "Priya Patel <priya.patel@meridianfreight.com>, "
            "Marcus Vance <marcus.vance@meridianfreight.com>"
        ),
        "date": "2026-10-04 13:10",
        "subject": "IMDG Class 3 flammables stowage check on MV Nordic Pioneer",
        "body": (
            "Reviewing Dangerous Goods stowage for container MSCU-199402 carrying flammable "
            "solvents (UN1993, Class 3). Must confirm minimum separation distance from "
            "accommodation spaces before loading on MV Nordic Pioneer.\n\n"
            "Carlos Mendez\nWarehouse Logistics"
        ),
    },
    {
        "id": "msg_028",
        "thread_id": "thread_dangerous_goods_nordic",
        "from": "Priya Patel <priya.patel@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-04 14:25",
        "subject": "Re: IMDG Class 3 flammables stowage check on MV Nordic Pioneer",
        "body": (
            "Carlos, Chief Officer confirmed Bay 12 deck slot with 6-meter separation from bridge "
            "superstructure and emergency foam monitor coverage per IMDG section 7.1.4.\n\n"
            "Priya Patel\nFleet Scheduling"
        ),
    },
    # --- Thread 8: Antwerp Cold Storage Slot (2 messages) ---
    {
        "id": "msg_009",
        "thread_id": "thread_cold_storage_antwerp",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Helena Chen <helena.chen@meridianfreight.com>",
        "date": "2026-10-04 15:50",
        "subject": "Antwerp cold storage gate slot reservation",
        "body": (
            "Helena, need gate pre-clearance for 4 reefer containers of frozen seafood arriving "
            "Terminal 42 at 16:30 tomorrow. Need sanitary import declaration verified.\n\n"
            "Carlos"
        ),
    },
    {
        "id": "msg_029",
        "thread_id": "thread_cold_storage_antwerp",
        "from": "Helena Chen <helena.chen@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-04 17:05",
        "subject": "Re: Antwerp cold storage gate slot reservation",
        "body": (
            "Sanitary documents approved by Belgian FASFC inspectorate. Gate reservation barcode "
            "sent to drayage dispatch.\n\n"
            "Helena"
        ),
    },
    # --- Standalone 1: Lloyd's Surveyor ---
    {
        "id": "msg_010",
        "thread_id": "thread_surveyor_appointment",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-04 16:30",
        "subject": "Lloyd's cargo surveyor appointment confirmed",
        "body": (
            "Surveyor Jan Vermeer from Lloyd's Register scheduled for 09:00 Monday at Berth 14 "
            "for cargo damage assessment on hatch 3.\n\n"
            "David Ross"
        ),
    },
    # --- Thread 9: Duisburg Barge Delay (2 messages) ---
    {
        "id": "msg_011",
        "thread_id": "thread_duisburg_barge",
        "from": "Priya Patel <priya.patel@meridianfreight.com>",
        "to": (
            "Carlos Mendez <carlos.mendez@meridianfreight.com>, "
            "Marcus Vance <marcus.vance@meridianfreight.com>"
        ),
        "date": "2026-10-05 08:10",
        "subject": "Duisburg barge delay due to low water levels on Rhine",
        "body": (
            "Notice from Rhine River Navigation: Kaub gauge at 1.15m restricts barge draft. "
            "Inland container feeder MS Loreley delayed by 36 hours into Duisburg port. "
            "Evaluate rail alternatives for time-sensitive cargo.\n\n"
            "Priya Patel\nFleet Scheduling"
        ),
    },
    {
        "id": "msg_030",
        "thread_id": "thread_duisburg_barge",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Priya Patel <priya.patel@meridianfreight.com>",
        "date": "2026-10-05 09:40",
        "subject": "Re: Duisburg barge delay due to low water levels on Rhine",
        "body": (
            "Priya, diverted 6 automotive containers to DB Cargo block train from Rotterdam to "
            "Duisburg Rhine-Ruhr terminal. Loading starts 13:00 today.\n\n"
            "Carlos"
        ),
    },
    # --- Thread 10: Vessel Drydock in Brest (2 messages) ---
    {
        "id": "msg_012",
        "thread_id": "thread_drydock_brest",
        "from": "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-05 11:20",
        "subject": "Vessel drydock schedule revision in Brest shipyard",
        "body": (
            "Marcus, Damen Shiprepair Brest confirmed drydock slot 3 available October 15-22 "
            "for propeller shaft seal replacement and hull antifouling. Please adjust route.\n\n"
            "Capt. Erik Lindholm\nMaster, MV Meridian Voyager"
        ),
    },
    {
        "id": "msg_031",
        "thread_id": "thread_drydock_brest",
        "from": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "to": "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>",
        "date": "2026-10-05 13:15",
        "subject": "Re: Vessel drydock schedule revision in Brest shipyard",
        "body": (
            "Captain, drydock reservation confirmed with Brest shipyard dispatch. Feeder rotation "
            "covered by MV Baltic Courier during this window.\n\n"
            "Marcus"
        ),
    },
    # --- Thread 11: Overweight Surcharge Dispute MRDU-881290 (2 messages) ---
    {
        "id": "msg_013",
        "thread_id": "thread_overweight_mrdu",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-05 14:15",
        "subject": "Overweight surcharge dispute container MRDU-881290",
        "body": (
            "Marcus, Antwerp terminal levied a EUR 350 overweight penalty on container MRDU-881290 "
            "claiming gross mass of 31,400 kg. Shipper's certified VGM document shows 28,100 kg. "
            "Terminal scale certificate is requested.\n\n"
            "Carlos Mendez"
        ),
    },
    {
        "id": "msg_032",
        "thread_id": "thread_overweight_mrdu",
        "from": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-05 15:45",
        "subject": "Re: Overweight surcharge dispute container MRDU-881290",
        "body": (
            "Weighbridge re-calibration at Gate 2 showed sensor offset. Antwerp billing confirmed "
            "penalty for MRDU-881290 has been cancelled.\n\n"
            "Marcus Vance"
        ),
    },
    # --- Standalone 2: Chemical Tariff HS 2905.11 ---
    {
        "id": "msg_014",
        "thread_id": "thread_tariff_ruling",
        "from": "Helena Chen <helena.chen@meridianfreight.com>",
        "to": "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>",
        "date": "2026-10-05 16:00",
        "subject": "Chemical tariff HS code 2905.11 customs ruling",
        "body": (
            "Binding Tariff Information (BTI) confirms methanol consignment classified under "
            "HS code 2905.11 with standard third-country duty rate of 5.5%.\n\n"
            "Helena Chen"
        ),
    },
    # --- Thread 12: Le Havre Tugboat Strike (2 messages) ---
    {
        "id": "msg_015",
        "thread_id": "thread_le_havre_tugs",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Priya Patel <priya.patel@meridianfreight.com>",
        "date": "2026-10-06 06:50",
        "subject": "Le Havre tugboat strike notice affecting outbound berths",
        "body": (
            "Port of Le Havre tugboat operators union announced a 12-hour work stoppage starting "
            "08:00 today. MV Baltic Courier unberthing delayed until pilotage resumption.\n\n"
            "David Ross\nRotterdam Dispatch"
        ),
    },
    {
        "id": "msg_036",
        "thread_id": "thread_le_havre_tugs",
        "from": "Priya Patel <priya.patel@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-06 08:15",
        "subject": "Re: Le Havre tugboat strike notice affecting outbound berths",
        "body": (
            "Le Havre port master granted an emergency bow thruster waiver allowing unberthing "
            "with a single private escort tug at 11:30. Minimal schedule impact.\n\n"
            "Priya"
        ),
    },
    # --- Thread 13: Reefer RF-9104 Audit (2 messages) ---
    {
        "id": "msg_016",
        "thread_id": "thread_reefer_9104_audit",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "date": "2026-10-06 08:30",
        "subject": "Reefer RF-9104 data logger download complete",
        "body": (
            "Marcus, USB thermal logger download completed for unit RF-9104 carrying organic "
            "dairy. No excursions recorded during transit. Ready for EuroFresh audit desk.\n\n"
            "Carlos"
        ),
    },
    {
        "id": "msg_037",
        "thread_id": "thread_reefer_9104_audit",
        "from": "Marcus Vance <marcus.vance@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-06 09:45",
        "subject": "Re: Reefer RF-9104 data logger download complete",
        "body": (
            "Thanks Carlos. I will dispatch the compliance email and sensor CSV files to "
            "dispatch@eurofresh.eu now.\n\n"
            "Marcus"
        ),
    },
    # --- Thread 14: Bay of Biscay Storm Routing (2 messages) ---
    {
        "id": "msg_017",
        "thread_id": "thread_biscay_storm_routing",
        "from": "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>",
        "to": "Priya Patel <priya.patel@meridianfreight.com>",
        "date": "2026-10-06 09:15",
        "subject": "Bay of Biscay heavy weather route diversion",
        "body": (
            "Priya, NOAA marine forecast indicates significant wave heights 5.5m to 6.2m in Bay of "
            "Biscay central sector. Recommending coastal diversion via waypoint Porto to maintain "
            "cargo stability.\n\n"
            "Capt. Erik Lindholm\nMaster, MV Meridian Voyager"
        ),
    },
    {
        "id": "msg_038",
        "thread_id": "thread_biscay_storm_routing",
        "from": "Priya Patel <priya.patel@meridianfreight.com>",
        "to": "Captain Erik Lindholm <capt.lindholm@meridianfreight.com>",
        "date": "2026-10-06 10:40",
        "subject": "Re: Bay of Biscay heavy weather route diversion",
        "body": (
            "Captain, Porto waypoint diversion approved. Bunkering fuel calculation accommodates "
            "the additional 42 nautical miles.\n\n"
            "Priya"
        ),
    },
    # --- Standalone 3: Munich Repositioning ---
    {
        "id": "msg_018",
        "thread_id": "thread_munich_repositioning",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-06 10:30",
        "subject": "Empty container repositioning from Munich depot",
        "body": (
            "Consolidated rail shipment of 24 empty 40ft high-cube containers departing Munich "
            "Riem terminal tonight, arriving Antwerp yard Thursday morning.\n\n"
            "David Ross"
        ),
    },
    # --- Standalone 4: Rhine Connection ---
    {
        "id": "msg_019",
        "thread_id": "thread_rhine_status",
        "from": "Priya Patel <priya.patel@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-06 11:15",
        "subject": "Rhine barge connection status update",
        "body": (
            "Water levels rising slightly near Emmerich. Barge loading caps increased to 80% "
            "nominal capacity for tomorrow's sailing.\n\n"
            "Priya Patel"
        ),
    },
    # --- Standalone 5: Rotterdam Surcharge ---
    {
        "id": "msg_020",
        "thread_id": "thread_rotterdam_congestion",
        "from": "Sarah Al-Mansoor <sarah.almansoor@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-06 12:00",
        "subject": "Gate congestion surcharge notice at Rotterdam Maasvlakte",
        "body": (
            "Port of Rotterdam announced temporary EUR 25 gate congestion fee during peak drayage "
            "hours (10:00-14:00) starting next Monday. Advise shippers to book night slots.\n\n"
            "Sarah Al-Mansoor"
        ),
    },
    # --- Thread 15: Damaged Pallet DR-331 (2 messages) ---
    {
        "id": "msg_021",
        "thread_id": "thread_damaged_pallet_survey",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-06 13:20",
        "subject": "Damaged pallet DR-331 discharge survey report",
        "body": (
            "David, warehouse intake inspection identified crushed pallet base on consignment "
            "DR-331 discharged from MV Baltic Courier. Cargo sealed and quarantined in Bay 4 "
            "pending surveyor joint inspection.\n\n"
            "Carlos Mendez\nWarehouse Bay 4 Antwerp"
        ),
    },
    {
        "id": "msg_039",
        "thread_id": "thread_damaged_pallet_survey",
        "from": "David Ross <david.ross@meridianfreight.com>",
        "to": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "date": "2026-10-06 14:50",
        "subject": "Re: Damaged pallet DR-331 discharge survey report",
        "body": (
            "Surveyor Vermeer notified. Formal exception noted on delivery order DR-331.\n\nDavid"
        ),
    },
    # --- Standalone 6: Terminal 42 Night Gate ---
    {
        "id": "msg_040",
        "thread_id": "thread_night_gate_t42",
        "from": "Carlos Mendez <carlos.mendez@meridianfreight.com>",
        "to": "David Ross <david.ross@meridianfreight.com>",
        "date": "2026-10-06 18:30",
        "subject": "Terminal 42 night gate reservation confirmed for reefer plug-ins",
        "body": (
            "Night appointment slots reserved for 12 reefer containers at Terminal 42 between "
            "22:00 and 04:00. Power plug-in marshaling confirmed.\n\n"
            "Carlos Mendez"
        ),
    },
]


def main() -> None:
    TARGET_FIXTURES.mkdir(parents=True, exist_ok=True)
    out_path = TARGET_FIXTURES / "emails.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(EMAILS, f, indent=2)
    print(f"Successfully generated and wrote {len(EMAILS)} emails to {out_path}")


if __name__ == "__main__":
    main()
