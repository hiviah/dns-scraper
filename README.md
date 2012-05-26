# DNS Scraper

This is a simple threaded scanner of various DNS records, mostly targeted at
various DNSSEC stuff.

## Requirements

* python-ldns (>= 1.6.10, latest ldns preferred)
* python-unbound (>= 1.4.17; or 1.4.16 with patching, see below)
* python-psycopg2 (known to run with 2.0.13)
* postgresql-server (highly recommended to run on localhost: no reconnect in DB pool due to transaction use)

## Patching unbound (not needed for unbound >= 1.4.17)

1. Download unbound-1.4.16.tar.gz from [unbound.net](http://unbound.net/download.html)
2. Unpack e.g. in ~/tmp: 

    `tar xzf unbound-1.4.16.tar.gz`

3. Still in ~/tmp, do: 

    `patch -p0 < /path/to/dns-scraper/patches/unbound-1.4.16_pythonmodule_packet.patch`

4. configure and build unbound (no need for 'make install'):

    `./configure --disable-gost --with-pthreads --with-pyunbound --with-pythonmodule --with-libevent`  
    `make`

5. copy over the \_unbound.so and unbound.py to dns-scraper directory:

    `cp ~/tmp/unbound-1.4.16/.libs/_unbound.so* ~/tmp/unbound-1.4.16/libunbound/python/unbound.py /path/to/dns-scraper`

## Create database and tables, modify config

Create your database (let's name it dns_scraper) using createdb or pgadmin, add
your user, give him privilege to create tables, the user needs to be owner of schemas
you'll be modifying (by default it seems that schema 'public' is owned by postgres).

Then create tables (in dns-scraper dir):

    make tables

Optionally, you can set `DNS_SCRAPER_DB`, `DNS_SCRAPER_SCHEMA`,
`DNS_SCRAPER_USER` variables to customize names of DB, schema and username,
e.g.:

    export DNS_SCRAPER_DB=scraper_db
    export DNS_SCRAPER_SCHEMA=scan_2012_04_18
    make tables

Note: if you get error `ERROR:  language "plpgsql" does not exist`, use `CREATE LANGUAGE plpgsql;` to
load the plpgsql language (needed only once).

Copy `dns_scraper.config.sample` to `dns_scraper.config`, set username/pass to DB.

Make sure your user in DB has enough connections allowed. Usually the single
storage thread in sample config is enough. See note on multiple DB threads in
known bugs.


## Running scanner

Create file with trust anchors (same format as `ub_ctx.add_ta_file` uses), let's
name it "keys". These trust anchors are used when determining DNSSEC validation
state. In the config file, there's `ta_file` option under `dns` section for it.

Assuming you have your domains in "domains" file (one per line), following
invocation will run the scanner:

    ./dns_scraper.py domains dns_scraper.config

After the scan is complete, you may create indices to speed up working/searching 
(envvars like `DNS_SCRAPER_DB` are supported as before):

    make indices

## Known bugs

- sometimes libunbound's resolution can take really long time when encountering
  SERVFAIL (up to 10 minute timeouts were observed for single RR)
- some records may be duplicated in DB if they are present in multiple
  responses (e.g. NSEC RRs)
- note on multiple DB threads: there is a possibility of race condition since
  the `insert_unique_domain` function is not atomic. However, the code accounts
  for this, catches the case and retries the command (just the log will contain
  a debug message about the caught IntegrityError).

