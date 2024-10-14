![GitHub top language](https://img.shields.io/github/languages/top/QueenDekim/NetworkMonitor)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/QueenDekim/NetworkMonitor?label=commits)
![GitHub Repo stars](https://img.shields.io/github/stars/QueenDekim/NetworkMonitor)

# NetworkMonitor(nmap) + RestAPI(flusk)

```shell
git clone https://github.com/QueenDekim/NetworkMonitor.git
cd ./NetworkMonitor
pip install -r requirements.txt
```

Install `mysql` and execute the command from the `base.sql` file in it

Install `nmap`:
 - Windows - [installer (exe)](https://nmap.org/dist/nmap-7.95-setup.exe)
 - Ubuntu - `sudo apt install nmap`

In the `.py` files change the login details in `MySQL`:
```py
conn = mysql.connector.connect(
    host='localhost',
    user='username',
    password='password',
    database='network_monitoring'
)
```

in the `rest_api.py` file we configure `Flusk`, or leave it as is:
```
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5150)
```

first run `network_monitor.py`, then `rest_api.py`

after information about the found devices appears in the `network_monitor.py` console, try making a `GET` request to `<your ip>:<port(default 5150)>/api/scans`

We receive the response in `Json` format:
```
{
    "device_info": "{\"ports\": [{\"name\": \"ftp\", \"port\": 21, \"state\": \"filtered\", \"product\": \"\", \"version\": \"\"}], \"hostname\": \"\"}",
    "id": 1,
    "ip": "192.168.0.1",
    "status": "up",
    "timestamp": "Mon, 14 Oct 2024 09:38:47 GMT"
},
```

|                                                links                                                                         |                                 description                                         |
|:----------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------:|
|[![Static Badge](https://img.shields.io/badge/Discord-from__russia__with__love-purple)](https://about:blank)                  |                                My Discord tag                                       |
|[![Static Badge](https://img.shields.io/badge/Telegram-%40QueenDek1m-blue)](https://t.me/QueenDek1m)                          |                                  My telegram                                        |
