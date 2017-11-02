# docker-identd
An ident service that identifies the container for a connection

## Problem Statement

You have a Docker environment in your network; you limit outgoing traffic from your servers using a whitelisted proxy configuration (Squid) which can then be used for auditing. You wish to allow some containers access to some sites; perhaps even allow some containers access to any site.
How then, can you grant access based on the container? You need to add an extra level of authentication.
You could set up user-credentials for each container that needs access, but that is an administrative burden, and further a lot of software doesn't work well with a proxy that needs user authentication, which is a support concern.
Or we could use ident lookups to determine the 'user', which can then be used to evaluate ACL conditions. To do that, we would need to set up some specialised 'identd' type service on our docker host(s) that was able to return the container name associated with a given source-dest TCP port pair. This turns out to be entirely feasible, and has the added benefit of adding a level of authentication without the container having to do anything more than just point to the proxy.

## Background: ident service

Let's say you got in your TARDIS and travelled back to the 1980s. You're logged into your multi-user UNIX box and are connecting to.... say an IRC service. The operator of the IRC service has configured things such that when you connect, the IRC service will make another connection back to your IP on port 113 (the 'auth' service), and say the equivalent of 'please tell me the name of the user connecting to me on TCP port X; they are coming from your TCP port Y'. The identd daemon running on your machine would then look up its connection information, see that the connection is owned by user 'crk' and then respond back with that username.
... that's ident in a nutshell. It's a very old service, with issues around trust and privacy, and that doesn't work too well with NAT. But the concept is sound for our purposes:
accept queries just from the proxy service
instead of user, return the name of the container
and do some other hujamaha relating to NAT translation and accounting for proxy server load-balancer architecture.

## (Alternative) Design: run lsof inside each container

Initially, I thought the most obvious solution would be query lsof for the requested port pair, and that would tell me enough to identify the container it was running in. Unfortunately, lsof (and friends) won't show connections inside other containers, as they are in different namespaces (note: not 'network' namespaces, which is a different concept in Linux). You can do it though, you just have to:
get a list of each container's namespace ID (docker inspect --format '{{ .State.Pid }}' on each container)
either run nsenter -t $pid -n lsof ....
This runs the hosts version of lsof, but inside the namespace of the container.
nsenter is package in the util-linux package, so trivially available.
But the container's copy of /etc/passwd will not necessarily be the same, and so you won't be able to resolve all usernames.
or docker exec $container_id lsof ....
This runs lsof from within the container; as such it can resolve user IDs to user-names

### Pros of this approach

You can get richer information (eg. username/ID within the container or command-name), which is useful to log, but perhaps less useful for identd

### Cons of this approach

Not sufficiently light-weight for an ident lookup, which could conceivably happen frequently
In our Docker environment, the container has a different IP (172.x.x.x) compared to what the ident client (Squid proxy server) sees (10.x.x.x), so you need to chase up some connection tracking information.


## Chosen Design: use connection-tracking information to identify container

It turns out that a much simpler approach is to simply consult /proc/net/nf_conntrack to figure out which internal IP (source-ip) is associated with the triple of source-port,dest-port,dest-ip. Thankfully, the port doesn't seem to get translated, just the address, so this seems fairly reliable. This gives us a 172.16/12 address that will belong to one of the Docker containers.
Thus, we then need to formulate a lookup table of container-name and IP address. This table would be cacheable for a least a few seconds (we don't tend to have very short-running containers). Building this lookup table requires the ability to run 'docker ps' and 'docker inspect', so we need to be in the 'docker' group. This lookup table can then be used to quickly determine the container name.

### Pros of this approach

 - Fairly lightweight
 - At least some of it is cacheable
 - Less to do than for nsenter+lsof alternate design

### Cons of this approach

 - /proc/net/nf_conntrack can be fairly large, so not constant-time to query, and lot's of parsing.

## Implementation on Docker host

### Service user

We do need to bind to port 113 (a reserved port), but we don't need to use 'root' user for anything, although we need to be in the 'root' group to access /proc/net/nf_conntract. We also need to be in the 'docker' group so we can query Docker.

    # useradd --system -g docker --comment "Docker Container Ident Service" docker-identd --shell /sbin/nologin --home-dir /

### Systemd Configuration

Systemd does a lot of useful lifting here:

 - Run the program as a service
 - Handle its logs (via journald and syslog)
 - Set user to run as
 - Grant the CAP_NET_BIND_SERVICE capabality to allow it to bind to ports <1024
 - Security hardening
 - /etc/systemd/system/docker-ident.service is as per the following

    [Unit]
    Description=Docker Ident Service
    After=network.target
    Wants=docker.service

    [Service]
    Type=simple
    ExecStart=/usr/local/sbin/docker-identd
    Restart=on-failure
    RestartSec=43s

    User=docker-identd
    # Needed to inspect docker
    Group=docker
    # Needed to read /proc/net/nf_conntrack
    SupplementaryGroups=root

    # Strict would be preferred, but not available in RHEL 7.4
    ProtectSystem=full
    PrivateDevices=true
    PrivateTmp=true
    ReadOnlyDirectories=/

    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    NoNewPrivileges=true

    Nice=12

    StandardOutput=syslog
    StandardError=syslog
    SyslogFacility=daemon
    SyslogIdentifier=docker-identd
    SyslogLevel=info

    [Install]
    WantedBy=multi-user.target

Test unit file with the following command:

    # systemd-analyze verify /etc/systemd/system/docker-ident.service 
    Binding to IPv6 address not available since kernel does not support IPv6.

Plus the usual systemd sort of things like ```systemctl {enable|status|restart|...}``` and ```journalctl -elf -u docker-identd.service```

## docker-identd implementation

This is a bespoke Python program I have written for this purpose
Worth noting that it is sensitive to changes in how the proxy-servers are deployed (addresses).

See the code in this repository

## Squid Configuration

### Logging Configuration

Adjusted the logging configuration in squid.conf to include the username / ident lookups.

I consider it an ugly syntax (I should make something more self-describing, preferably JSON), but the key part is the the ```%ui``` (and ```%un``` I added to the end. This gets you the ident string and the user-name (which could come from one of multiple sources, so I chose to log both).

    logformat custom_v1 [%tl] %>A %{Host}>h "%rm %ru HTTP/%rv" %>Hs %<st "%{Referer}>h" "%{User-Agent}>h" %Ss:%Sh username:%un ident:%ui
    access_log /var/log/squid/access.log custom_v1

There is a matching parser in logstash on my ELK stack; but that is outside the scope of this post.

### ACL Configuration

See the [Squid FAQ on Ident lookups](https://wiki.squid-cache.org/SquidFaq/SquidAcl#Is_there_a_way_to_do_ident_lookups_only_for_a_certain_host_and_compare_the_result_with_a_userlist_in_squid.conf.3F)

Here's an extract from /etc/squid/squid.conf. You can see that there are (historical) entries giving access (needed for only some containers) to all containers. Below that, you can see how I've given access for just one container.

    acl docker_host src 10.x.x.x
    acl docker_dest dstdomain .redhat.com .centos.org .google.com .dockerproject.org .fedoraproject.org .googleapis.com .docker.io pecl.php.net
    http_access allow docker_host docker_dest
    http_access allow docker_host docker_dest CONNECT SSL_ports
    #
    # For access for particular containers, we can constrain accessing using ident lookups.
    # There is a custom ident server running on the docker host that will return the name
    # of the container, as a user (eg. mycontainer) -- only useful if you name the container or course.
    #
    acl docker_host_mycontainer ident mycontainer
    acl docker_host_mycontainer_dstdomains dstdomain api.ipify.org
    http_access allow docker_host docker_host_mycontainer docker_host_mycontainer_dstdomains
    http_access allow docker_host docker_host_mycontainer docker_host_mycontainer_dstdomains CONNECT SSL_ports

## Verification

Here's an example from the mycontainer container for a URL through the proxy; this has been granted access through the proxy for this particular container:

    root@dockerhost:~# docker exec -it mycontainer bash
    [root@mycontainer~]# https_proxy=http://proxy.example.com:3128/ curl https://api.ipify.org/
    192.0.2.123    <--- the answer from the web-service we called out to, in this case our public IP

Here's an example from a different container for the same URL, which is not granted to this container.

    root@dockerhost:~# docker exec -it anothercontainer bash
    [root@api /]# https_proxy=http://proxy.example.com:3128/ curl https://api.ipify.org/
    curl: (56) Received HTTP code 403 from proxy after CONNECT

