# DDoS Mitigation Script

## Brief
### How it works
Tempesta provides extended information about user requests. In this case, we're interested in the user's IP address, 
as well as their JA5T and JA5H hashes. These hashes allow us to distinguish users based on similar characteristics, 
such as TLS connection or HTTP request fingerprints.

Additionally, access logs can be stored in ClickHouse, which offers extremely powerful capabilities for analyzing traffic.

The mitigation script connects to the ClickHouse database and, at regular intervals, analyzes user traffic. 
It compares aggregated values (such as the total number of requests, accumulated response time, and total number of
error responses) against predefined thresholds. All of these thresholds can be customized in the application configuration.

To block a user, the mitigation script adds the user's JA5T hash to the Tempesta FW configuration and reloads the server.

### Historical Mode
The Mitigation Script can be configured to start in historical mode.  To enable it, set the following in your 
app configuration:
```.env
training_mode="historical"
```
You can also configure the training_mode_duration_min variable, which defines how far back (in minutes) the script 
should look to analyze user traffic. If the calculated values are too low, the script will prefer 
to use the default thresholds from the configuration.

This mode is especially useful when the actual average system load is unknown, and it's more effective to 
let the Mitigation Script determine reasonable thresholds automatically.

### Real Mode
In cases where historical data is not available, but you still want to automatically set thresholds,
you can start the Mitigation Script with:

```.env
training_mode="real"
```
This mode works similarly to historical, with one key difference:
the script waits for a specified amount of time to collect fresh data, and only then begins analysis.

To train the script using the last 10 minutes of live traffic, you can use:

```.env
training_mode_duration_min=10
```
During this period, the script will gather user activity, calculate average metrics,
apply multipliers (as in historical mode), and set the thresholds accordingly.

### Persistent Users
This feature is available only in `historical` and `real` modes, as it requires existing traffic data for analysis.

The Mitigation Script can identify persistent users — users that generate regular, consistent traffic — and protect them during an attack.
All users except those marked as persistent can potentially be blocked.

By default, this feature is enabled in both `historical` and `real` modes.

To configure persistent user detection, use the following variables:

```.env
persistent_users_max_amount=100
persistent_users_window_offset_min=60
persistent_users_window_duration_min=60
persistent_users_total_requests: Decimal=1
persistent_users_total_time=1
```

A user is marked as persistent if they exceed either of the following thresholds during the specified time window: 

- persistent_users_total_requests: minimum number of requests (RPS)
- persistent_users_total_time: minimum total response time

These thresholds help ensure that only consistently active users are protected from being mistakenly blocked.

### Known UserAgents
Another way to protect trusted users during a DDoS attack is by maintaining a list of known User-Agents.
You can define these in a separate configuration file.

By default, the path to this file is:

```.env
/etc/tempesta-ddos-defender/allow_user_agents.txt

```
An example configuration might look like:

```text
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0
```

Each User-Agent should be on a separate line.

If you want to use a custom location for this file, you can set the following variable in your config:

```.env
allowed_user_agents_file_path=/your/custom/path.txt
```

Requests with matching User-Agents will be ignored by the blocking logic and treated as safe.

### Blocking Methods
The mitigation script supports several methods for blocking users:

| NAME | Description                                |
|-|--------------------------------------------|
| ja5t | Client TLS connection fingerprint          |
| ja5h | Client HTTP fingerprint                    |
| ipset | Block by  ip using ipset + iptables |
| nftables | Block by ip using nftables |

By default, the ja5t blocking method is used. However, multiple methods can be specified, including combinations:

```.env
blocking_type=["ja5t", "ipset"]
```

### Unblocking Users
After a DDoS attack, blocked users can be automatically unblocked.
The default blocking duration is controlled by the blocking_time_min variable (in minutes).

Once the specified time has passed, the Mitigation Script will check blocked users periodically
and remove their blocks if the time limit has been exceeded.

You can configure how often this check is performed using:

```.env
blocking_release_time_min=5
```

This ensures that users are not blocked longer than necessary, while still maintaining protection during an active attack.

## Prepare Tempesta FW
The script requires a specific Tempesta FW configuration.
Let's create two directories inside the Tempesta configuration directory /etc/tempesta/:
ja5t and ja5h.

Inside each directory, create an empty block.conf file.
The final paths should look like this:

```bash
/etc/tempesta/ja5t/block.conf
/etc/tempesta/ja5h/block.conf
```

Next, update your main Tempesta FW configuration file to include the following settings:

```nginx
ja5t {
    !include /etc/tempesta/ja5t
}
ja5h {
    !include /etc/tempesta/ja5h
}
```

Once the configuration is updated, reload Tempesta FW:

```bash
service tempesta --reload
```
This setup allows the Mitigation Script to dynamically update ja5t and ja5h blocking rules.

## Start Mitigation Script

### Run Manually
Manual startup is slightly more complex but doesn't require anything special.
You just need to create a virtual environment, install the requirements, copy the default config, and create an 
empty file for the User-Agent list:

```bash
python3 -m venv tempesta-ddos-defender
source tempesta-ddos-defender/bin/activate
pip install -r requirements.txt
cp example.env /etc/tempesta-ddos-defender/app.env
touch /etc/tempesta-ddos-mitigation/allow_user_agents.txt
python3 app.py 
```

## How to Defend Your App
The mitigation script currently provides basic protection suitable for small to medium-sized applications,
where traffic spikes are not extremely frequent or unpredictable.

### Blog or Online Shop
These types of applications typically don’t have a large number of concurrent users and often operate within a traffic range of 0 to 50 active users.
However, it's important to account for the fact that static files (like CSS, JS, and images) are also requested.
On initial page load, a single user might generate up to 20 or more HTTP requests.

Let's estimate:
- If 10 users are browsing your site concurrently, total requests might reach 200.
- If there are 50 concurrent users, it might go up to 1000 requests.

Requests alone are not the only important metric.

#### Total Accumulated Response Time
Static file requests are usually handled directly by Tempesta FW without reaching the backend.
However, dynamic page generation or API calls (e.g., fetch() requests) hit the backend and consume time.

If your backend is slow and receives 1000 requests, you’ll likely observe a noticeable increase in accumulated response time —
which is a key indicator of server load.

#### Total Errors
A spike in errors (like 5xx responses) is a strong signal of a problem.
If you're seeing dozens of such responses, it likely means something is going wrong and needs attention.

#### Example Mitigation Script Configuration
Based on a typical blog or online shop scenario, the following configuration is a reasonable starting point:

```.env
default_requests_threshold=300
default_time_threshold=40
default_errors_threshold=5
```
These thresholds provide a balance between responsiveness and protection, ensuring that legitimate traffic is allowed
while abnormal spikes can be mitigated early.

### Crypto Exchanger or a Game
Let’s assume you’re running a cryptocurrency exchanger or a small online game.
With good marketing, you’re likely to see consistent user traffic. Depending on the complexity of the application,
there may be dozens of AJAX requests per user — or even persistent WebSocket connections delivering real-time data,
such as coin prices or player actions.

This type of behavior significantly increases the total number of requests, many of which cannot be cached by Tempesta FW,
leading to heavier load on your backend services.

#### Defense Strategy
The mitigation strategy is similar to that of a blog or e-commerce site, but with higher thresholds.

Additionally, for such dynamic applications, it's highly recommended to use training mode with either historical or real value.
In this mode, the Mitigation Script will analyze real user traffic and determine the most suitable threshold values
for filtering potential attacks without affecting normal operation.

To enable real-time training, update your configuration like this:

```.env
training_mode="real"
training_mode_duration_min=30
```

This setup allows the script to observe traffic for 30 minutes, calculate real averages,
and apply scaled thresholds based on live behavior — which is ideal for dynamic, traffic-intensive apps.

### Testing your App
There are many tools available to simulate DDoS attacks on your application.
Some of them — like Apache JMeter — even allow you to write request scenarios and define different RPS (requests per second) loads over time slices.

However, for a more focused and powerful DDoS simulation, we recommend using MHDDoS.
It’s lightweight and easy to set up, making it ideal for local or test environments.

You can install and run Tempesta FW, ClickHouse, and the DDoS Mitigation Script all on a single machine.

To simulate an HTTP server, you can use Python’s built-in web server:

```bash
python3 -m http.server
```

By default, it runs on localhost:8000.

Generate SSL certificates and update your Tempesta FW configuration accordingly
to enable HTTPS support and route traffic through Tempesta for analysis and mitigation.

```nginx
listen 80 proto=http;
listen 433 proto=h2,https;

cache 0;
access_log dmesg mmap logger_config=/etc/tempesta/logger.conf;

tls_certificate /etc/tempesta/cert.crt;
tls_certificate_key /etc/tempesta/cert.key;
tls_match_any_server_name;

frang_limits {
    http_methos get post head options;
}

ja5t {
    !include /etc/tempesta/ja5t
}
ja5h {
    !include /etc/tempesta/ja5h
}

server 127.0.0.1:8000;
```

Update /etc/hosts. Add the following entry to your /etc/hosts file:
```text
127.0.0.1 app.com
```

Now, make a simple HTTPS request to confirm that the server is working correctly:
```bash
curl https://app.com/ -k
```
You should see a directory listing of files.

Let’s simulate a DDoS attack using MHDDoS. We’ll use:

- 10 threads
- 10 RPS per thread
- 60 seconds duration
- An empty proxy list


Run the following command:
```bash
./start.py GET https://app.com/ 1 10 /Users/MHDDoS/files/proxies/file 10 60
```

This will simulate an attack with up to 100 RPS for 60 seconds against https://app.com.

Now, start the Mitigation Script. You should see output similar to the following:
```bash
(tempesta-ddos-venv) root@symtu:/home/tempesta-ddos-defender# python3 app.py 
[2025-07-17 03:53:28,539][root][INFO]: Starting DDoS Defender
[2025-07-17 03:53:28,566][root][INFO]: Training mode set to OFF
[2025-07-17 03:53:28,570][root][INFO]: Found protected user agents. Total user agents: 0
[2025-07-17 03:53:28,570][root][INFO]: Updated live thresholds to: requests=100, time=40, errors=5
[2025-07-17 03:53:28,570][root][INFO]: Preparation is complete. Starting monitoring.
```

Let’s restart MHDDoS and see how the Mitigation Script reacts to the simulated attack:
```bash
[2025-07-17 03:56:30,760][root][WARNING]: Blocked user User(ja5t='66cbe62b13320000', blocked_at=1752717390) by ja5t
```

## Future Cases

### Abnormal Traffic
In large-scale applications, traffic patterns can vary significantly depending on many factors, such as:

- Marketing campaigns
- Time of day
- Holidays
- Black Friday or other sales events
- Political or social events
- Regional incidents or frustration
- And many others

There are plenty of real-world scenarios where traffic might resemble a DDoS attack — but in fact, it’s legitimate.
To avoid blocking real users in such cases, it’s important to make thresholds dynamically adaptive.

Moreover, if traffic surges are predictable (e.g. due to a scheduled event or planned marketing campaign),
it's possible to pre-train or pre-configure the system with expected behavior — reducing the risk of false positives.

In future versions, integrating traffic forecasting or external signal sources could help the 
Mitigation Script make smarter decisions.
