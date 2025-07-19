# DDoS Defender

Block users by JA5T, JA5H, or IP based on Tempesta FW access 
logs stored in the ClickHouse database.

# How to run

### Requirements:
- Python 3.10 <=
- Tempesta FW 0.0.8 <=
- Clickhouse 25.6.0 <=

### Run manually
```bash
python3 -m venv tempesta-ddos-defender
source tempesta-ddos-defender/bin/activate
pip install -r requirements.txt
cp example.env /etc/tempesta-ddos-defender/env
touch /etc/tempesta-ddos-defender/allow_user_agents.txt
python3 app.py --config=/etc/tempesta-ddos-defender/env
```

### Run with Docker
```bash
docker build -t tempesta-ddos-defender .
docker run -d 
  -v /etc/tempesta-ddos-defender:/etc/tempesta-ddos-defender:ro \
  --name tempesta-ddos-defender tempesta-ddos-defender
```

### Run functional tests
```bash
python3 -m unittest discover -s tests
```

### Format project
```bash
black .
isort .
```

# How to block

### Prepare Tempesta FW config
It's useful to define separate directories for different groups of JA5 hashes  
in the Tempesta FW configuration file (/etc/tempesta/tempesta_fw.conf).
```nginx
ja5t {
    !include /etc/tempesta/ja5t/
}
ja5h {
    !include /etc/tempesta/ja5h/
}
```
Then add 2 files
- /etc/tempesta/ja5t/blocked.conf
- /etc/tempesta/ja5h/blocked.conf

These files should be used by default by the Defender 
to add new blocking hashes.
