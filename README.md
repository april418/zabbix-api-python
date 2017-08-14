# zabbix-api-python

## Usage

Import your Python code.

```python
from zabbix_api import ZabbixApi

with ZabbixApi('host', 'user', 'pass') as api:
    response = api.call('host.get')

hosts = response['result']
```

Or execute command line.

```sh
$ ./zabbix_api.py host user pass host.get
```

