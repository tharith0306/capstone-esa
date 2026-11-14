"""CloudShield command line.

    python -m app.cli init-db
    python -m app.cli ingest-file --source cloudtrail sample_data/cloudtrail_credential_compromise.json
    python -m app.cli collect cloudtrail [--since 2026-11-04T00:00:00Z] [--until ...]
    python -m app.cli collect vpc_flow --log-group /cloudshield/vpc-flow
    python -m app.cli collect guardduty
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from app.collectors.aws import aws_client
from app.collectors.base import Collector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.guardduty import GuardDutyCollector
from app.collectors.vpc_flow import VpcFlowCollector
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.database.session import create_engine_from_url, create_session_factory, init_db
from app.evidence.store import build_evidence_store
from app.processing.normalizers.base import parse_timestamp
from app.schemas.event import EventSource
from app.services.checkpoints import get_checkpoint, set_checkpoint
from app.services.ingestion import IngestionService
from app.services.record_files import load_records


def _build(settings: Settings):
    engine = create_engine_from_url(settings.database_url)
    init_db(engine)
    session_factory = create_session_factory(engine)
    return session_factory, IngestionService(session_factory, build_evidence_store(settings))


def _collector(settings: Settings, source: EventSource, log_group: str | None) -> Collector:
    if source is EventSource.CLOUDTRAIL:
        return CloudTrailCollector(aws_client(settings, "cloudtrail"))
    if source is EventSource.GUARDDUTY:
        return GuardDutyCollector(aws_client(settings, "guardduty"))
    if not log_group:
        sys.exit("--log-group is required for vpc_flow")
    return VpcFlowCollector(aws_client(settings, "logs"), log_group)


def cmd_init_db(settings: Settings, _: argparse.Namespace) -> None:
    _build(settings)
    print("database ready:", settings.database_url)


def cmd_ingest_file(settings: Settings, args: argparse.Namespace) -> None:
    _, ingestion = _build(settings)
    source = EventSource(args.source)
    for path in args.paths:
        result = ingestion.ingest(source, load_records(path, source))
        print(f"{path}: {result.model_dump_json(exclude={'source'})}")


def cmd_collect(settings: Settings, args: argparse.Namespace) -> None:
    session_factory, ingestion = _build(settings)
    source = EventSource(args.source)
    collector = _collector(settings, source, args.log_group)

    now = datetime.now(timezone.utc)
    end = parse_timestamp(args.until) if args.until else now
    if args.since:
        start = parse_timestamp(args.since)
    else:
        with session_factory() as session:
            start = get_checkpoint(session, collector.name) or (
                end - timedelta(minutes=settings.collector_default_lookback_minutes)
            )

    print(f"collecting {source.value} from {start.isoformat()} to {end.isoformat()}")
    result = ingestion.ingest(source, collector.collect(start, end))
    print(json.dumps(result.model_dump(mode="json"), indent=2))

    # Late-delivered events can carry timestamps before `end`; re-read an overlap next time.
    cursor = max(start, end - timedelta(minutes=settings.collector_overlap_minutes))
    with session_factory() as session:
        set_checkpoint(session, collector.name, cursor)


def cmd_train(settings: Settings, args: argparse.Namespace) -> None:
    from app.ml.training import TrainingConfig, train

    bundle = train(TrainingConfig(seed=args.seed, days=args.days, attacks_per_day=args.attacks_per_day))
    bundle.save(settings.model_dir)
    v = bundle.metadata["validation"]
    print(f"saved model bundle {bundle.version} to {settings.model_dir}")
    print(f"validation: XGBoost macro-F1={v['xgboost']['macro_f1']} binary={v['xgboost']['binary']}")
    print(f"            RandomForest macro-F1={v['random_forest']['macro_f1']}; "
          f"IsolationForest={v['isolation_forest']['binary']}")


def cmd_simulate(settings: Settings, args: argparse.Namespace) -> None:
    from app.services.simulation import seed_demo

    session_factory, ingestion = _build(settings)
    if args.if_empty:
        from sqlalchemy import func, select

        from app.database.models import SecurityEventRecord

        with session_factory() as session:
            if session.scalar(select(func.count()).select_from(SecurityEventRecord)):
                print("database already has events; skipping demo seeding")
                return
    start = parse_timestamp(args.start) if args.start else None
    result = seed_demo(ingestion, settings.reports_dir, args.seed, args.days, args.attacks_per_day, start)
    print(json.dumps({k: v for k, v in result.items() if k != "scenarios"}, indent=2))
    for s in result["scenarios"]:
        print(f"  {s['scenario_id']}  {s['kind']:26s} victim={s['victim']:16s} {s['start'][:16]}"
              f"{'  (stealthy)' if s['stealthy'] else ''}")
    if args.analyze:
        cmd_analyze(settings, argparse.Namespace(since=None, until=None))


def cmd_analyze(settings: Settings, args: argparse.Namespace) -> None:
    from app.services.analysis import AnalysisService
    from app.services.models_registry import ModelRegistry

    session_factory, _ = _build(settings)
    service = AnalysisService(session_factory, settings, ModelRegistry(settings))
    start = parse_timestamp(args.since) if args.since else None
    end = parse_timestamp(args.until) if args.until else None
    print(json.dumps(service.run(start, end, actor="cli"), indent=2, default=str))


def cmd_experiments(settings: Settings, args: argparse.Namespace) -> None:
    from app.experiments.runner import run_experiments

    report = run_experiments(settings, quick=args.quick)
    print(f"wrote {report['paths']['markdown']} and {report['paths']['json']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cloudshield")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create database tables")

    p_file = sub.add_parser("ingest-file", help="ingest exported records from files")
    p_file.add_argument("--source", required=True, choices=[s.value for s in EventSource])
    p_file.add_argument("paths", nargs="+")

    p_collect = sub.add_parser("collect", help="pull records from AWS and ingest them")
    p_collect.add_argument("source", choices=[s.value for s in EventSource])
    p_collect.add_argument("--since", help="ISO-8601 start; defaults to the stored checkpoint")
    p_collect.add_argument("--until", help="ISO-8601 end; defaults to now")
    p_collect.add_argument("--log-group", help="CloudWatch Logs group (vpc_flow only)")

    p_train = sub.add_parser("train", help="train IF / XGBoost / RF / HMM on simulated labelled data")
    p_train.add_argument("--seed", type=int, default=7)
    p_train.add_argument("--days", type=int, default=30)
    p_train.add_argument("--attacks-per-day", type=float, default=6.0)

    p_sim = sub.add_parser("simulate", help="ingest a simulated organisation under attack (demo data)")
    p_sim.add_argument("--seed", type=int, default=2026)
    p_sim.add_argument("--days", type=int, default=7)
    p_sim.add_argument("--attacks-per-day", type=float, default=1.5)
    p_sim.add_argument("--start", help="ISO date of the first simulated day (default 2026-10-01)")
    p_sim.add_argument("--if-empty", action="store_true", help="only seed when the database has no events")
    p_sim.add_argument("--analyze", action="store_true", help="run the analysis pipeline afterwards")

    p_an = sub.add_parser("analyze", help="run detection, correlation, risk and forensics over stored events")
    p_an.add_argument("--since")
    p_an.add_argument("--until")

    p_exp = sub.add_parser("experiments", help="run the research experiments and write a report")
    p_exp.add_argument("--quick", action="store_true", help="smaller datasets (for CI / smoke tests)")

    args = parser.parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    commands = {
        "init-db": cmd_init_db, "ingest-file": cmd_ingest_file, "collect": cmd_collect, "train": cmd_train,
        "simulate": cmd_simulate, "analyze": cmd_analyze, "experiments": cmd_experiments,
    }
    commands[args.command](settings, args)


if __name__ == "__main__":
    main()
