import os

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
            app_config=self.app_config,
            clickhouse_client=self.access_log,
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

    async def test_prepare_no_city_list(self):
        os.remove(self.allowed_cities)

        with self.assertRaises(FileNotFoundError) as error:
            await self.detector.prepare()
            self.assertIn("List of allowed cities does not exist", str(error))

    async def test_prepare_no_geodb(self):
        os.remove(self.allowed_cities)

        with self.assertRaises(FileNotFoundError) as error:
            await self.detector.prepare()
            self.assertIn("GeoIP database was not found", str(error))

    async def test_find_low_rps(self):
        await self.detector.prepare()
        self.detector.app_config.detector_geoip_period_seconds = 3

        result = await self.detector.find_users(1751535000)
        self.assertEqual(len(result), 0)

    async def test_find(self):
        await self.detector.prepare()
        self.detector.app_config.detector_geoip_period_seconds = 1
        self.detector.app_config.detector_geoip_min_rps = 1

        result = await self.detector.find_users(1751535000)
        self.assertEqual(len(result), 1)

    async def test_find_allowed_city(self):
        with open(self.allowed_cities, "w") as f:
            f.write("Podgorica")

        await self.detector.prepare()
        self.detector.app_config.detector_geoip_period_seconds = 1
        self.detector.app_config.detector_geoip_min_rps = 1

        result = await self.detector.find_users(1751535000)
        self.assertEqual(len(result), 0)
