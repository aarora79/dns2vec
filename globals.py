APP_NAME = "dnswrangler"
APP_VER = "1.0.0.0"
DATASET_VER = "1.0.0.0"
RAW_DATA_DIR = "raw_data"
DATA_DIR = "data"
DNS_DATASET_FILE_NAME = "dns_queries.csv" #"dns_queries.csv"
DATASET_SPLIT_SIZE_IN_MB = "100"
WRANGLE_ONLY_DEFAULT = True
ACTION_ANALYZE_ONLY = "analyze-only"
ACTION_WRANGLE_ONLY = "wrangle-only"
ACTION_RUN_ALL = "run-all"
ACTION_DEFAULT = ACTION_ANALYZE_ONLY

# filesplit package needs the size in multiples of 1000 and not 1024
SPLITS_DIR = "splits"
MB = 1000*1000
NUM_WORKER_PROCESSES = 42
MINUTE_AGGREGATION_BOUNDARY = 5
MINUTE_AGGR_INTERVALS = 60/MINUTE_AGGREGATION_BOUNDARY
WRANGLED_DATASET_FILE_NAME = "dnsdata.csv"
QUERY_TYPE_STATS_FILE_NAME = "query_type_stats.csv"
FQDN_STATS_FILE_NAME = "fqdn_stats.csv"
HOURLY_TOTAL_QUERY_COUNT_TIMESERIES_FILE_NAME = "hourly_total_query_count.csv"
HOURLY_PER_QUERY_COUNT_TIMESERIES_FILE_NAME = "hourly_per_query_count.csv"
HOURLY_PER_QUERY_COUNT_LOW_TFIDF_TIMESERIES_FILE_NAME = "hourly_per_query_count_low_tfidf.csv"
HOURLY_DOMAIN_LEN_IN_TOKENS_TIMESERIES_FILE_NAME = "hourly_domain_len_in_tokens.csv"
HOURLY_PER_SINGLE_TOKEN_QUERY_COUNT_TIMESERIES_FILE_NAME = "hourly_per_single_token_domain_count.csv"
FQDN_TFIDF_FILE_NAME = "fqdn_tfidf.csv"
FQDN_TFIDF_SUBSET_FILE_NAME = "fqdn_tfidf_subset.csv"
FIRST_TOKEN_COUNTS_FILE_NAME = "first_token_counts.csv"
SRC_IP_STATS_FILE_NAME = "src_ip_stats.csv"
HOURLY_QUERY_TYPE_STATS_FILE_NAME = "hourly_qtype_stats.csv"
HOURLY_UNIQUE_SRC_IP_COUNT_PER_QUERY = "hourly_unique_src_ip_count_per_query.csv"
HOURLY_UNIQUE_SRC_IP_COUNT_PER_LOW_TFIDF_QUERY = "hourly_unique_src_ip_count_per_query_low_tfidf.csv"
HOURLY_UNIQUE_SRC_IP_COUNT_MOST_FREQ_FQDNS = "hourly_unique_src_ip_count_per_query_most_freq_fqdns.csv"
FINAL_INPUT_TO_W2V_MODEL_FILE_NAME = "final_input_to_w2v_model.csv"
N_FOR_FQDNS_W_LOWEST_TFIDF = 100
CCTLD_FILE_NAME = "ccTLD.csv"
MODEL_FILE_SUFFIX = "_dns_word2vec.model"

# default masks we assume for IPv4 and IPv6
# maybe make these as config params...
IPV4_MASK = "/29"
IPV6_PREFIX_LEN = "/64"
EMPTY_STRING = ""
LOWEST_N_TFIDF_DOMAINS = 10

# word2vec hyper parameters
W2V_EMBEDDING_SIZE = 128
W2V_WINDOW = 7
W2V_MIN_COUNT = 5
W2V_NEGATIVE_SAMPLING = 5
W2V_NS_EXPONENT = -1
W2V_SAMPLE = 0.00001
WV_EPOCHS = 1
WV_SEED = 1603
# constants to optimize execution of word2vec
W2V_WORKERS = 42
W2V_USE_SG = 1
W2V_MAX_VOCAB_SIZE = 40000
W2V_PARAMS_FILE_NAME = "word2vec_params.json"
TOP_N_SIMILAR_WORDS = 10
MODEL_TRAINING_LOSS_FILE_NAME = "training_loss_per_epoch.csv"

RUN_NAME = "run_" + str(WV_EPOCHS) + "_epoch" + ("s" if WV_EPOCHS > 1 else "")
DNS_VECTORS_FILE_NAME = "dnsvectors"
DNS_VECTOR_METADATA_FILE_NAME = "metadata"
SIMILAR_DOMAINS_FILE_NAME = "similar_domains.csv"

"""
QUERIES = ["bengals.com", "huffingtonpost.com", "elle.com", "medicinenet.com", "rent.com",
           "match.com", "hotels.com", "uber.com",  "kohls.com",
           "ancestry.com", "ups.com", "costco.com", "bankrate.com",
           "ny.gov", "samsclub.com", "groupon.com", "cnn.com", "glassdoor.com",
          "yelp.com", "ixl.com", "buffalo.edu", "230.244", "musical.ly", "imoji.io", "epicgames.com"]
"""
QUERIES = ["elle.com", "uber.com", "webmd.com", "match.com", "glassdoor.com", "ixl.com",
           "yelp.com", "food.com", "walmart.com", "foxnews.com", "pornhub.com",
           "salliemae.com", "54.207", "newmexico.gov", "outbrain.com", "norton.com", "vzw.com", "ebay.com", 
           "office.com", "apartments.com", "23andme.com", "ups.com"]
