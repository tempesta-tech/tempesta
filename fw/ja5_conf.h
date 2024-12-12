#include "ttls.h"
#include "cfg.h"

typedef struct {
	struct hlist_node	hlist;
	atomic64_t		refcnt;
	/* TODO: make an unified macro for different types of ja5 hashes */
	TlsJa5t			ja5_hash;
	u64			conns_per_sec;
	u64			tls_records_per_sec;
} TlsJa5HashEntry;

TlsJa5HashEntry*
tls_get_ja5_hash_entry(TlsJa5t hash);

void
tls_put_ja5_hash_entry(TlsJa5HashEntry *entry);

u32
tls_get_ja5_max_entries(void);

int
handle_ja5_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce);

int
tls_cfgop_ja5_begin(TfwCfgSpec *cs, TfwCfgEntry *ce);

int
tls_cfgop_ja5_finish(TfwCfgSpec *cs);

void
tls_cfgop_ja5_cleanup(TfwCfgSpec *cs);
