# firmware-upgrader
**Description**
---------------
WebApp - used as a learning example, contains
- Nornir (and Napalm)
- Flask
- Task queueing (redis, rq)


**How to Run It**
=================
on Linux (ubuntu 18)
--------------------
prerequisites:
- install redis server:
```
  sudo apt-get install redis-server
```

go to project directory
```
cd /home/luk/dev/firmware-upgrader
```

activate virtual environment (venv)
```
source venv/bin/activate
```

go to source root
```
cd /home/luk/dev/firmware-upgrader/firmware-upgrader
```

start RQ worker (obsolete)
```
cd /home/luk/dev/firmware-upgrader/firmware-upgrader
rq worker


# (venv) luk@ubuntu:~/dev/firmware-upgrader/firmware-upgrader$ rq worker
# 12:47:26 RQ worker 'rq:worker:ubuntu.15089' started, version 0.12.0
# 12:47:26 *** Listening on default...
# 12:47:26 Cleaning registries for queue: default
```

start netbox
```
cd /home/luk/dev/netbox-docker
docker-compose up -d
```

find out netbox URL
```
echo "http://$(docker-compose port nginx 8080)/"
```

more details about netbox:
https://github.com/ninech/netbox-docker

dockerized version
------------------
make sure that regular redis-server is not running
```
sudo /etc/init.d/redis-server stop
```

initial docker pull
```
docker pull redis
docker images
```

run redis container (and export internal redis default port 6379 to external world)
```
docker run -p 6379:6379 redis
```



**How to Run the Unit Tests**

**Key Dependencies**

**Future Enhancements**
