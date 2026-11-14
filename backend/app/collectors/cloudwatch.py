"""EC2 CPU utilisation from CloudWatch (GetMetricData), one datapoint per instance per period."""

from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource

_MAX_QUERIES = 500


class CloudWatchMetricsCollector(Collector):
    name = "cloudwatch_cpu"
    source = EventSource.CLOUDWATCH

    def __init__(self, cloudwatch: Any, ec2: Any, period_seconds: int = 600):
        self.cloudwatch = cloudwatch
        self.ec2 = ec2
        self.period = period_seconds

    def _instances(self) -> list[dict]:
        out = []
        for page in self.ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    out.append({"id": inst["InstanceId"], "ip": inst.get("PrivateIpAddress"),
                                "account": reservation.get("OwnerId")})
        return out

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        instances = self._instances()
        region = self.cloudwatch.meta.region_name
        for i in range(0, len(instances), _MAX_QUERIES):
            batch = instances[i:i + _MAX_QUERIES]
            queries = [{
                "Id": f"q{j}",
                "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization",
                                          "Dimensions": [{"Name": "InstanceId", "Value": inst["id"]}]},
                               "Period": self.period, "Stat": "Average"},
            } for j, inst in enumerate(batch)]
            paginator = self.cloudwatch.get_paginator("get_metric_data")
            for page in paginator.paginate(MetricDataQueries=queries, StartTime=start, EndTime=end):
                for result in page.get("MetricDataResults", []):
                    inst = batch[int(result["Id"][1:])]
                    for ts, value in zip(result.get("Timestamps", []), result.get("Values", [])):
                        yield {"instance_id": inst["id"], "metric": "CPUUtilization", "value": value,
                               "unit": "Percent", "timestamp": ts.isoformat(), "region": region,
                               "account_id": inst["account"], "private_ip": inst["ip"]}
