.PHONY: all little_bobby_tables tables

# Default DB name
ifndef DNS_SCRAPER_DB
    DNS_SCRAPER_DB := dns_scraper
endif
ifndef DNS_SCRAPER_SCHEMA
    DNS_SCRAPER_SCHEMA := public
endif

all:
	@echo "Use 'make tables' to create DB tables. Two envvars are supported:"
	@echo "DNS_SCRAPER_SCHEMA - use different schema name than 'public'"
	@echo "DNS_SCRAPER_DB - use different schema name than 'dns_scraper'"

tables: little_bobby_tables

little_bobby_tables:
	sql/makePrefix.sh $(DNS_SCRAPER_SCHEMA) | psql $(DNS_SCRAPER_DB)


