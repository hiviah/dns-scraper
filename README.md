# DNS Scraper

This is a simple threaded scanner of various DNS records, mostly targeted at
various DNSSEC stuff.

## Requirements

* python-ldns
* python-unbound (needs patching, see below)
* python-psycopg2
* postgresql-server (highly recommended to run on localhost: no reconnect in DB pool due to transaction use)

## Patching unbound

The patch needed in unbound has SVN revision r2643 which is not yet in current
stable unbound 1.4.16.

1. Download unbound-1.4.16.tar.gz from [unbound.net](http://unbound.net/download.html)
2. Unpack e.g. in ~/tmp: 

    `tar xzf unbound-1.4.16.tar.gz`

3. Still in ~/tmp, do: 

    `patch -p0 < /path/to/dns-scraper/patches/unbound-1.4.16_pythonmodule_packet.patch`

4. configure and build unbound (no need for 'make install'):

    `./configure --disable-gost --with-pthreads --with-pyunbound --with-pythonmodule --with-libevent`  
    `make`

5. copy over the _unbound.so and unbound.py to dns-scraper directory:

    `cp ~/tmp/unbound-1.4.16/.libs/_unbound.so* ~/tmp/unbound-1.4.16/libunbound/python/unbound.py /path/to/dns-scraper`

## Create database and tables, modify config

Create your database (let's name it dns_scraper) using createdb or pgadmin, add
your user, give him privilege to create tables.

Then create tables (in dns-scraper dir):

    psql dns_scraper < sql/001_create_tables.sql

Make sure your user in DB has enough connections allowed - the scanner requires
one DB connection per thread.

Copy dns_scraper.config.sample to dns_scraper.config, set username/pass to DB.

## Running scanner

Create file with trust anchors (same format as ub_ctx.add_ta_file uses), let's
name it "keys". These trust anchors are used when determining DNSSEC validation
state.

Assuming you have your domains in "domains" file (one per line), following
invocation will run the scanner in 10 threads:

    ./dns_scraper.py domains keys 10 dns_scraper.config


