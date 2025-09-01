import os
import time
from dataclasses import dataclass, field
from decimal import Decimal

from geoip2.database import City, Reader

from config import AppConfig
from detectors.base import BaseDetector
from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class CityStats:
    users: list[User] = field(default_factory=list)
    total_requests: Decimal = Decimal(0)


class GeoIPDetector(BaseDetector):
    def __init__(
        self,
        *args,
        path_to_db: str = None,
        path_to_allowed_cities_list: str = None,
        client: Reader = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.path_to_db = path_to_db
        self.path_to_allowed_cities_list = path_to_allowed_cities_list
        self.client = client
        self.loaded_cities = set()

    @staticmethod
    def name() -> str:
        return "geoip"

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

    def find_city(self, ip: str) -> City:
        """
        Find the city by IP and return it.

        :param ip: client IP
        :return: city details
        """
        return self.client.city(ip)

    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        response = await self.db.query(
            f"""
            WITH prepared_users AS (
                SELECT al.*
                FROM {self._access_log.table_name} al
                LEFT ANTI JOIN user_agents ua
                    ON al.user_agent = ua.name
                LEFT ANTI JOIN persistent_users p
                    ON al.address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
            )
            SELECT 
                groupUniqArray(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                address address,
                count(1) value
            FROM prepared_users
            GROUP by address
            """
        )

        return [
            User(
                ja5t=user[0],
                ja5h=user[1],
                ipv4=[user[2]],
                value=user[3],
            )
            for user in response.result_rows
        ]

    def cities_stats(self, users: list[User]) -> dict[str, CityStats]:
        cities = dict()

        for user in users:
            city = self.find_city(str(user.ipv4[0]))

            if city.city.name not in cities:
                cities[city.city.name] = CityStats()

            cities[city.city.name].users.append(user)
            cities[city.city.name].total_requests += user.value

        return cities

    def validate_model(
        self, users_before: list[User], users_after: list[User]
    ) -> list[User]:

        cities_before = self.cities_stats(users_before)
        cities_after = self.cities_stats(users_after)

        blocking_cities = []

        for name, city_after in cities_after.items():
            if name in self.loaded_cities:
                logger.debug(f"GeoIP skipped user from allowed city {name}")
                continue

            city_before = cities_before.get(name)

            if not city_before:
                city_before = CityStats(total_requests=Decimal(1))

            if city_after.total_requests < self.threshold:
                continue

            multiplier = city_after.total_requests / city_before.total_requests

            if multiplier >= self._difference_multiplier:
                blocking_cities.append(name)

        result_users = []

        for city in blocking_cities:
            city_to_block = cities_after.get(city)
            result_users.extend(city_to_block.users)

        logger.debug(
            f"GeoIP found {len(result_users)} risky users in cities {blocking_cities}"
        )
        return result_users

    def get_values_for_threshold(self, users: list[User]) -> list[Decimal]:
        city_stats = self.cities_stats(users)
        return [city.total_requests for city in city_stats.values()]
