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

```
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

## View events in Security Onion

***Events will not contain observer.name****
Must search with host.name until this is resolved.  


