import os

import geoip2.database


class GeoClient:
    def __init__(self, path_to_db: str):
        self.path_to_db = path_to_db

        if not os.path.exists(self.path_to_db):
            raise FileNotFoundError

        self.client = geoip2.database.Reader(self.path_to_db)

    def find_city(self, ip: str) -> geoip2.database.City:
        return self.client.city(ip)
