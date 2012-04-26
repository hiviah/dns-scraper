.PHONY: all little_bobby_tables tables indices

PSQL_FLAGS := 

# Default DB name
ifndef DNS_SCRAPER_DB
    DNS_SCRAPER_DB := dns_scraper
endif
ifndef DNS_SCRAPER_SCHEMA
    DNS_SCRAPER_SCHEMA := public
endif
ifdef DNS_SCRAPER_USER
    PSQL_FLAGS += -U $(DNS_SCRAPER_USER) -W
endif


all:
	@echo "Use 'make tables' to create DB tables. Two envvars are supported:"
	@echo "DNS_SCRAPER_SCHEMA - use different schema name than 'public'"
	@echo "DNS_SCRAPER_DB - use different schema name than 'dns_scraper'"
	@echo "Use 'make indices' to create search indices on already created tables"

tables: little_bobby_tables

little_bobby_tables:
	sql/makePrefix.sh $(DNS_SCRAPER_SCHEMA) tables | psql $(PSQL_FLAGS) $(DNS_SCRAPER_DB)

indices:
	sql/makePrefix.sh $(DNS_SCRAPER_SCHEMA) indices | psql $(PSQL_FLAGS) $(DNS_SCRAPER_DB)

