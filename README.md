# laurel-securityonion
Configuration files to ingest auditd logs processed by Laurel into SecurityOnion

## Install and Configure Laurel
```
git clone https://github.com/threathunters-io/laurel
wget https://github.com/threathunters-io/laurel/releases/download/v0.4.1/laurel-v0.4.1-x86_64-glibc.tar.gz
mv laurel laureldir
tar xzf laurel-v0.4.1-x86_64-glibc.tar.gz laurel
sudo install -m755 laurel /usr/local/sbin/laurel
```
## Create a dedicated user, e.g.:
```
sudo useradd --system --home-dir /var/log/laurel --create-home _laurel
```
## Configure LAUREL: Customize /etc/laurel/config.toml.  Must change read-users and change translate values to "true".  If you do not change the translate values you will ingest hexidecimal representations of some of the values.  
```
sudo mkdir /etc/laurel
sudo cp /home/defender/laureldir/etc/laurel/config.toml /etc/laurel/
sudo nano /etc/laurel/config.toml
```
##
CHANGES TO CONFIG.TOML
```
read-users = [ "defender" ]

[translate]
# arch, syscall, sockaddr structures
universal = true
# UID, GID values
user-db = true

```

## Register LAUREL as an auditd plugin:
```
sudo cp /home/defender/laureldir/etc/audit/plugins.d/laurel.conf /etc/audisp/plugins.d/
```
## Tell auditd(8) to re-evaluate its configuration:
```
sudo pkill -HUP auditd
```
## Restart auditd
```
service auditd restart
```

## View Logs in /var/log/laurel/
```
tail -n1  /var/log/laurel/audit.log | jq .
```
# Install and Configure Filebeat
	
## Download .deb package from Elastic or SecurityOnion GUI
```
sudo dpkg -i filebeat-oss-8.3.3-amd64.deb
```
## Modify filebeat with the following configs
```
sudo nano /etc/filebeat/filebeat.yml
```
CHANGES TO FILEBEAT.YML
```
filebeat.inputs:

  id: laurel

  enabled: true

  paths:
    - /var/log/laurel/audit.log
  # ------------------------------ Logstash Output -------------------------------
output.logstash:
  # The Logstash hosts
    hosts: ["192.168.5.100:5044"]
# ================================= Processors =================================
processors:
   - decode_json_fields:
      fields: ["message"]
      process_array: true
      max_depth: 10
      target: ""
   - add_fields:
      target: observer
      fields:
        name: laurel
```
# Prior to starting Filebeat on the Linux server, run the so-allow command on the MANAGER NODE to allow beats endpoints to connect.

## Start filebeat
```
sudo service filebeat start
```
## Enable filebeat to start at boot
```
sudo systemctl enable filebeat
```
## Check filebeat status
```
sudo service filebeat status
```

## View data in Security Onion SOC Console
```
* AND observer.name: "laurel" 
```
![image](https://user-images.githubusercontent.com/73084279/193065242-0eaa3ad8-37a0-47cf-82d5-13893924af43.png)

# Configure SecurityOnion
Add Elastic pipeline for laurel

```
cp  /opt/so/saltstack/default/salt/elasticsearch/files/ingest/beats.common  /opt/so/saltstack/local/salt/elasticsearch/files/ingest/beats.common
```

Add the laurel pipeline to the top line of beats.common pipeline as shown below

```

   { "pipeline":      { "if": "ctx.agent?.name == 'laurel'",  "name": "laurel" }  },

```
## Normalize data to match other host events
```
vi /opt/so/saltstack/local/salt/elasticsearch/files/ingest/laurel
```
## Add auditbeat parsers as shown below:
```
{
  "description" : "laurel",
  "processors" : [
    { "set":          { "if": "ctx.host?.name != null",   "field": "observer.name", "value": "{{host.name}}", "override": true } },
    { "set":          { "field": "event.module", "value": "laurel", "override": true } },
    { "rename":       { "field": "SYSCALL.SYSCALL", "target_field": "auditd.data.syscall",  "ignore_missing": true  } },
    { "set":          { "if": "ctx.USER_ACCT?.msg != null",   "field": "event.dataset", "value": "user_acct_pam", "override": true } },
    { "set":          { "if": "ctx.auditd?.data?.syscall != null",   "field": "event.dataset", "value": "{{auditd.data.syscall}}", "override": true } },
    { "join":         { "if": "ctx.PROCTITLE?.ARGV != null", "field": "PROCTITLE.ARGV", "separator": ","  } },
    { "gsub":         { "if": "ctx.PROCTITLE?.ARGV != null", "field": "PROCTITLE.ARGV", "pattern": "\\,", "replacement": " "  } },
    { "set":          { "if": "ctx.PROCTITLE?.ARGV != null", "field": "process.command_line",  "value": "{{PROCTITLE.ARGV}}", "override": true } },
    { "join":         { "if": "ctx.EXECVE?.ARGV != null", "field": "EXECVE.ARGV", "separator": ","  } },
    { "gsub":         { "if": "ctx.EXECVE?.ARGV != null", "field": "EXECVE.ARGV", "pattern": "\\,", "replacement": " "  } },
    { "set":          { "if": "ctx.EXECVE?.ARGV != null", "field": "process.command_line",  "value": "{{EXECVE.ARGV}}", "override": true } },
    { "set":          { "if": "ctx.event?.dataset != null && ctx.event.dataset.contains('network')", "field": "event.dataset", "value": "network_connection", "override": true }$
    { "set":          { "if": "ctx.SYSCALL?.success != null && ctx.SYSCALL.success.contains('yes')", "field": "auditd.result", "value": "success", "override": true }  },
    { "rename":       { "field": "SYSCALL.tty", "target_field": "auditd.data.tty",  "ignore_missing": true  } },
    { "rename":       { "field": "PROCTITLE.ARGV || EXECVE.ARGV", "target_field": "process.command_line",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.AUID", "target_field": "auditd.summary.actor.primary",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.ARCH", "target_field": "auditd.data.arch",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.GID", "target_field": "group.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.SGID", "target_field": "set.group.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.EGID", "target_field": "user.effective.group.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.SUID", "target_field": "set.user.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.FSUID", "target_field": "user.filesystem.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.FSGID", "target_field": "user.filesystem.group.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.EUID", "target_field": "user.effective.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.egid", "target_field": "user.effective.group.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.euid", "target_field": "user.effective.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.SUID", "target_field": "user.saved.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.UID", "target_field": "user.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.comm", "target_field": "process.name",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.fsuid", "target_field": "user.filesystem.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.uid", "target_field": "user.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.suid", "target_field": "user.saved.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.sgid", "target_field": "user.saved.group.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.exit", "target_field": "auditd.data.exit",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.gid", "target_field": "user.group.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.fsgid", "target_field": "user.filesystem.group.id",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.exe", "target_field": "process.executable",  "ignore_missing": true  } },
    { "rename":       { "field": "PARENT_INFO.comm", "target_field": "process.parent.command_line",  "ignore_missing": true  } },
    { "rename":       { "field": "PARENT_INFO.exe", "target_field": "process.parent.executable",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.ppid", "target_field": "parent.process.pid",  "ignore_missing": true  } },
    { "rename":       { "field": "SYSCALL.pid", "target_field": "process.pid",  "ignore_missing": true  } },
    { "community_id": {} }
  ]
}

```
## Create SOC Dashboards
```
cp /opt/so/saltstack/default/salt/soc/files/soc/dashboards.queries.json /opt/so/saltstack/local/salt/soc/files/soc/dashboards.queries.json
``` 
```
vi /opt/so/saltstack/local/salt/soc/files/soc/dashboards.queries.json
```
``` 
 { "name": "Laurel", "description": "Laurel logs", "query": "event.module:laurel | groupby event.module event.dataset | groupby -sankey  process.parent.executable process.executable SOCKADDR.SADDR.addr"},
``` 
Restart SOC
```
sudo so-soc-restart
```
![image](https://user-images.githubusercontent.com/73084279/193070418-632a547a-2d76-4546-bad7-b58796da33b6.png)

