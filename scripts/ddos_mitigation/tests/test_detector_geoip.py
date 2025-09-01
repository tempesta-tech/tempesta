import os
from decimal import Decimal
from ipaddress import IPv4Address

import pytest

from detectors.geoip import GeoIPDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
async def detector(access_log):
    await access_log.conn.query(
        """
        insert into access_log values 
        (cast('1751535000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
        (cast('1751536000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
        (cast('1751537000' as DateTime64(3, 'UTC')), '79.143.107.10', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
        """
    )

    geoip_db_path = "/tmp/geoip.db"
    allowed_cities = "/tmp/allowed_cities_list.txt"

    with open("tests/GeoLite2-City.mmdb", "rb") as f:
        data = f.read()

    with open(geoip_db_path, "wb") as f:
        f.write(data)

    open(allowed_cities, "w").close()

    _detector = GeoIPDetector(
        access_log=access_log,
        path_to_db=geoip_db_path,
        path_to_allowed_cities_list=allowed_cities,
    )
    yield _detector

    try:
        os.remove(geoip_db_path)
    except:
        ...

    try:
        os.remove(allowed_cities)
    except:
        ...


@pytest.fixture
async def additional_logs(access_log):
    await access_log.conn.query(
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


async def test_prepare_no_city_list(detector: GeoIPDetector):
    os.remove(detector.path_to_allowed_cities_list)

    with pytest.raises(FileNotFoundError) as error:
        await detector.prepare()
        assert "List of allowed cities does not exist" in str(error)


async def test_prepare_no_geodb(detector: GeoIPDetector):
    os.remove(detector.path_to_allowed_cities_list)

    with pytest.raises(FileNotFoundError) as error:
        await detector.prepare()
        assert "GeoIP database was not found" in str(error)


async def test_find_low_rps(detector):
    await detector.prepare()
    before, after = await detector.find_users(current_time=1751535003, interval=5)
    assert len(before) == 0
    assert len(after) == 1

    blocked = detector.validate_model(users_before=before, users_after=after)
    assert blocked == []


async def test_find(detector, additional_logs):
    await detector.prepare()

    before, after = await detector.find_users(current_time=1751535003, interval=5)

    assert len(before) == 0
    assert len(after) == 2

    blocked = detector.validate_model(users_before=before, users_after=after)

    assert len(blocked) == 1
    assert blocked[0].ipv4[0] == IPv4Address("79.143.107.10")


async def test_find_allowed_city(detector, additional_logs):
    with open(detector.path_to_allowed_cities_list, "w") as f:
        f.write("Podgorica")

    await detector.prepare()
    before, after = await detector.find_users(current_time=1751535003, interval=5)

    assert len(before) == 0
    assert len(after) == 2

    blocked = detector.validate_model(users_before=before, users_after=after)
    assert blocked == []


async def test_update_thresholds(detector, additional_logs):
    await detector.prepare()

    _, after = await detector.find_users(current_time=1751535003, interval=5)
    detector.update_threshold(users=after)

    assert detector.threshold == Decimal(11.0)
