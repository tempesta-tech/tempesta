import os
from decimal import Decimal
from ipaddress import IPv4Address

from detectors.geoip import GeoIPDetector
from tests.base import BaseTestCaseWithFilledDB

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestGeoIpDetector(BaseTestCaseWithFilledDB):
    async def create_records(self):
        await self.access_log.conn.query(
            """
            insert into access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751536000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751537000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
            """
        )

    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.geoip_db_path = "/tmp/geoip.db"
        self.allowed_cities = "/tmp/allowed_cities_list.txt"

        with open("tests/GeoLite2-City.mmdb", "rb") as f:
            data = f.read()

        with open(self.geoip_db_path, "wb") as f:
            f.write(data)

        open(self.allowed_cities, "w").close()

        self.detector = GeoIPDetector(
            access_log=self.access_log,
            path_to_db=self.geoip_db_path,
            path_to_allowed_cities_list=self.allowed_cities,
        )

    async def asyncTearDown(self):
        await super().asyncTearDown()

        try:
            os.remove(self.geoip_db_path)
        except:
            pass

        try:
            os.remove(self.allowed_cities)
        except:
            pass

    async def create_additional_logs(self):
        await self.access_log.conn.query(
            """
            insert into access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '179.143.107.11', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '179.143.107.11', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '179.143.107.11', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '179.143.107.11', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '179.143.107.11', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
            """
        )

    async def test_prepare_no_city_list(self):
        os.remove(self.allowed_cities)

        with self.assertRaises(FileNotFoundError) as error:
            await self.detector.prepare()
            assert "List of allowed cities does not exist" in str(error)

    async def test_prepare_no_geodb(self):
        os.remove(self.allowed_cities)

        with self.assertRaises(FileNotFoundError) as error:
            await self.detector.prepare()
            assert "GeoIP database was not found" in str(error)

    async def test_find_low_rps(self):
        await self.detector.prepare()
        before, after = await self.detector.find_users(
            current_time=1751535003, interval=5
        )
        assert len(before) == 0
        assert len(after) == 1

        blocked = self.detector.validate_model(users_before=before, users_after=after)
        assert blocked == []

    async def test_find(self):
        await self.create_additional_logs()
        await self.detector.prepare()

        before, after = await self.detector.find_users(
            current_time=1751535003, interval=5
        )

        assert len(before) == 0
        assert len(after) == 2

        blocked = self.detector.validate_model(users_before=before, users_after=after)

        assert len(blocked) == 1
        assert blocked[0].ipv4[0] == IPv4Address("79.143.107.10")

    async def test_find_allowed_city(self):
        await self.create_additional_logs()

        with open(self.allowed_cities, "w") as f:
            f.write("Podgorica")

        await self.detector.prepare()
        before, after = await self.detector.find_users(
            current_time=1751535003, interval=5
        )

        assert len(before) == 0
        assert len(after) == 2

        blocked = self.detector.validate_model(users_before=before, users_after=after)
        assert blocked == []

    async def test_update_thresholds(self):
        await self.create_additional_logs()
        await self.detector.prepare()

        _, after = await self.detector.find_users(current_time=1751535003, interval=5)
        self.detector.update_threshold(users=after)

        assert self.detector.threshold == Decimal(11.0)
