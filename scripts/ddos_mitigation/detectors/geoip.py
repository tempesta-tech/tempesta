import os
import time
from dataclasses import dataclass, field
from decimal import Decimal

from geoip2.database import City, Reader

from utils.access_log import ClickhouseAccessLog
from config import AppConfig
from utils.datatypes import User
from detectors.base import BaseDetector
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class GeoIPDetector(BaseDetector):
    # clickhouse access log client
    clickhouse_client: ClickhouseAccessLog

    # loaded application config
    app_config: AppConfig

    # path to geoip database (maxmind)
    path_to_db: str

    # path to file with allowed cities list
    path_to_allowed_cities_list: str

    # maxmind geoip database reader
    client: Reader = None

    # loaded list of cities
    loaded_cities: set[str] = field(default_factory=set)

    @staticmethod
    def name() -> str:
        return "geoip"

    def find_city(self, ip: str) -> City:
        """
        Find the city by IP and return it.

        :param ip: client IP
        :return: city details
        """
        return self.client.city(ip)

    async def prepare(self):
        if not os.path.exists(self.path_to_allowed_cities_list):
            raise FileNotFoundError(
                f"List of allowed cities does not exist: "
                f"{self.path_to_allowed_cities_list}"
            )

        with open(self.path_to_allowed_cities_list, "r") as f:
            for line in f.readlines():
                self.loaded_cities.add(line.strip())

        if not os.path.exists(self.path_to_db):
            raise FileNotFoundError(f"GeoIP database was not found: {self.path_to_db}")

        self.client = Reader(self.path_to_db)

    async def find_users(self, current_time: int = None) -> list[User]:
        _current_time = current_time or int(time.time())
        response = await self.clickhouse_client.get_aggregated_clients_for_period(
            start_at=_current_time,
            period_in_seconds=self.app_config.detector_geoip_period_seconds,
            legal_response_statuses=self.app_config.response_statuses_white_list,
        )
        users_by_cities: dict[str, list[User]] = {}
        total_users = Decimal(0)
        total_requests = 0

        for item in response.result_rows:
            total_users += 1
            total_requests += item[4]

            user = User(
                ja5t=hex(item[0])[2:],
                ja5h=hex(item[1])[2:],
                ipv4=[item[2]],
                value=None,
                type=None,
            )
            city = self.find_city(str(user.ipv4[0]))

            if city.city.name not in users_by_cities:
                users_by_cities[city.city.name] = []

            users_by_cities[city.city.name].append(user)

        total_rps = total_requests / self.app_config.detector_geoip_period_seconds
        logger.debug(f"GeoIP detector fetched {total_users} users. RPS: {total_rps}")

        if total_rps < self.app_config.detector_geoip_min_rps:
            logger.debug(
                f"Skipped. RPS to low: {total_rps} < {self.app_config.detector_geoip_min_rps}"
            )
            return []

        result_users = []
        cities = set()

        for name, users in users_by_cities.items():
            if name in self.loaded_cities:
                logger.debug(f"GeoIP skipped user from allowed city {name}")
                continue

            cities.add(name)
            percent = len(users) * Decimal(100) / total_users

            if percent > self.app_config.detector_geoip_percent_threshold:
                result_users.extend(users)

        logger.debug(f"GeoIP found {len(result_users)} risky users in cities {cities}")
        return result_users
