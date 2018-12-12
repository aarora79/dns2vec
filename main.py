"""
Split the original dataset into multiple chunks and then use Python multiprocessing
to process each chunk separately. Each line in this dataset is a dnsrequest line
from a tshark/tcpdump trace. We want to group all dns queries (just query name)
for each IP address in a TBD (5 minutes typically) period and then concatenate
the query names in a space separate string to create a single string. This
summarized dataframe of strings (dns query names grouped by source IP and
time interval) is then written to a csv file after merging dataframes fromm
all the worker threads.
This created file is now ready for use by other applications for further analysis.
"""
import os
import sys
import csv
import json
import signal
import argparse
import ipaddress
import pandas as pd
import logging.config
import multiprocessing
from pathlib import Path
from itertools import groupby
from datetime import datetime
from gensim.models import Word2Vec
from gensim.models.callbacks import CallbackAny2Vec
from fsplit.filesplit import FileSplit
import globals as g
from tfidf import do_tfidf_transform_on_query_names

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s,%(module)s,%(processName)s,%(levelname)s,%(message)s', level=logging.INFO, stream=sys.stderr)


# ===============================================================================


def parse_args(args):
    parser = argparse.ArgumentParser()

    # Optional arguments
    parser.add_argument(
        '--filename', default=g.DNS_DATASET_FILE_NAME,
        help='{} dataset file. Default: {}'.format(g.APP_NAME, g.DNS_DATASET_FILE_NAME))

    parser.add_argument('--splitsizemb', default=g.DATASET_SPLIT_SIZE_IN_MB,
                        help='Chunk size: Size of each chunk in mega bytes into which the dataset is split. Default: {}'
                        .format(g.DATASET_SPLIT_SIZE_IN_MB))

    parser.add_argument('--action', default=g.ACTION_DEFAULT,
                        help='action: One of \"wrangle-only\" or \"analyze-only\" or \"run-all\". Default : {}'
                        .format(g.ACTION_DEFAULT))

    return parser.parse_args(args=args)


# ===============================================================================


def get_ip_subnet(ipver, ip):
    try:
        # sometimes the IP address has some domain name of the router? appended to it
        # so clean that before determining the subnet. For example ip could be "100.64.50.249.unisys-eportal"
        # so split the string on "." and take the part to the left
        if ipver == "IP6":
            ip = ip.split('.')[0] 
            ip = ip + g.IPV6_PREFIX_LEN
            ip = str(ipaddress.ip_network(ip, strict=False)).replace(g.IPV6_PREFIX_LEN, g.EMPTY_STRING)
        elif ipver == "IP":
            ip = ".".join(ip.split(".")[:4])
            ip = ip + g.IPV4_MASK
            ip = str(ipaddress.ip_network(ip, strict=False)).replace(g.IPV4_MASK, g.EMPTY_STRING)
        else:
            ip = "unknown"
    except Exception as e:
        logger.error("error while parsing IP address...")
        logger.error(str(e))
        ip = "unknown"
    return ip

# ===============================================================================


def count_categories(df, col_list):
    df_counts = df.groupby(col_list).size().reset_index(name="n")
    return df_counts


def wrangle_file(f, ccTLD):
    logger.info("going to wrangle {}".format(f))

    # read the data
    dns_data = pd.read_csv(f, error_bad_lines=False, engine="python")

    # assign column names
    dns_data.columns = ['ts', 'ipver', 'ip', 'qtype', 'query']

    # collect some stats about the data, useful for exploratory purposes
    # first we need to "lemmatize" the domain name so xyz.domain.name and domain.name
    # are the same thing from a domain categorization perspective. However
    # if the last token is a country identifier like say "in" then the reduced
    # form contains 3 top level tokens so page.nsit.ac.in becomes nsit.ac.in
    dns_data['query'] = dns_data['query'].map(lambda x: lemmatize_domain_name(x, ccTLD))

    # we need to do some group by using 5 minute boundaries so convert
    # the epoch into timestamp amd then a new field ts_aggr which will then be
    # used in the group_by operation later
    dns_data['ts'] = dns_data['ts'].map(lambda x: datetime.fromtimestamp(x))
    dns_data['ymd_h'] = dns_data['ts'].map(lambda x: "%04d%02d%02d %02d:00:00" % (x.year, x.month, x.day, x.hour))
    hourly_all_query_count_timeseries = count_categories(dns_data, 'ymd_h')

    # aggregate per hour counts for each query
    hourly_per_query_count_timeseries = count_categories(dns_data, ['ymd_h', 'query'])

    # hourly query count by unique IP i.e. in this hour, this domain name was queried from these many distinct IP addrs
    h_q = ['ymd_h', 'query']
    hourly_query_count_by_unique_ip = dns_data.groupby(h_q).agg({'ip': 'count', 'ip': 'nunique'}).reset_index(h_q)

    # query type stats
    qstats = count_categories(dns_data, 'qtype')

    # aggregate per hour counts for each query type
    hourly_per_query_type_count_timeseries = count_categories(dns_data, ['ymd_h', 'qtype'])

    # dns requests per source IP address
    ipstats = count_categories(dns_data, 'ip')

    # we only need A and AAAA type records
    dns_data = dns_data[(dns_data['qtype'] == "AAAA") | (dns_data['qtype'] == "A")]
    fqdn_stats = count_categories(dns_data, 'query')

    # what are the most frequent first tokens of a domain name
    # this will come in handy when deciding which domain names are
    # important (lets say occur frequently enough) when determining similarities
    dns_data['first_token'] = dns_data['query'].map(lambda x: str(x).split('.')[0])
    first_token_counts = count_categories(dns_data, ['first_token'])

    # a separate one with just the domains with no periods (these are all dummy domains
    # that chrome generates)
    # keep only rows with more than 1 entry in the query field
    dns_data['domain_len_in_tokens'] = dns_data['query'].map(lambda x: len(str(x).split('.')))
    hourly_domain_len_in_tokens_timeseries = count_categories(dns_data, ['ymd_h', 'domain_len_in_tokens'])

    # sometimes it is useful just to see single token queries separately
    hourly_per_single_token_query_timeseries = count_categories(dns_data[dns_data['domain_len_in_tokens'] == 1],
                                                                ['ymd_h', 'query'])

    # aggregate things on a per 20 minute basis
    dns_data['ts_aggr'] = dns_data['ts'].map(lambda x: "%04d%02d%02d%02d%02d" %(x.year, x.month, x.day, x.hour, x.minute/20))

    # handle IP address, we assume /29 for IPv4 and /64 for IPv6
    dns_data['subnet'] = dns_data.apply(lambda x: get_ip_subnet(ipver=x['ipver'], ip=x['ip']), axis=1)

    logger.info(dns_data[['ts_aggr', 'subnet']].head())

    # group by IP address and ts_aggr files and join all dns lookups together
    # sometimes the domain name could just be a number (anything is possible) so the join
    # will fail because it only works with a string so typecast query to string
    dns_data['query'] = dns_data['query'].map(lambda x: str(x))
    dns_data_grouped = dns_data.groupby(['ts_aggr', 'subnet'])['query'].apply(' '.join).reset_index()

    # convert to regular dataframe
    dns_data = pd.DataFrame(dns_data_grouped)

    # also, there are consecutive duplicates in this string, we want to replace them
    # with unique entries. For example "a,a,b,b,a,c,c,b" should just be "a,b,a,c,b" this
    # preserves the temporal ordering (remember this string was creating by concatenating
    # entries in a given M minute interval for a given source IP)
    dns_data['query2'] = dns_data['query'].map(lambda x: ' '.join([e[0] for e in groupby(x.split(' '))]))
    dns_data['query_token_count'] = dns_data['query'].map(lambda x: len([e[0] for e in groupby(x.split(' '))]))

    # drop the query column, what we need is in query2, then we will rename query2 to query
    dns_data = dns_data.drop(['query'], axis=1)
    dns_data = dns_data.rename(index=str, columns={"query2": "query"})

    # keep only rows with more than 1 entry in the query field
    dns_data = dns_data[dns_data['query_token_count'] > 1]

    # all done, ready to return the processed data frame, ready for next stage of the analysis pipeline
    return (dns_data, qstats, fqdn_stats, hourly_all_query_count_timeseries, hourly_per_query_count_timeseries,
            hourly_domain_len_in_tokens_timeseries, hourly_per_single_token_query_timeseries, first_token_counts,
            ipstats, hourly_per_query_type_count_timeseries, hourly_query_count_by_unique_ip)


# ===============================================================================

def lemmatize_domain_name(domain, ccTLD):
    domain = str(domain)
    tokens = domain.split('.')
    if tokens[-1] in ccTLD['tld'] and len(tokens) > 3:
        domain_minus_ccTLD = '.'.join(tokens[-3:])
        return domain_minus_ccTLD
    return '.'.join(tokens[-2:])

def post_process_dns_data(dns_data, low_tfidf_domains, ccTLD):

    # convert to list for lookup
    low_tfidf_domains = list(low_tfidf_domains)

    # create another list of last n i.e. n smallest tfidf domains
    # this is needed because sometimes after removing the country code TLD
    # (see lemmatize_domain_name) we end up with a domain name that is
    # one of the stop domains for example www.google.com.it may not be
    # in the stop domain list but www.google.com that we get after removing .it
    # is in the stop list..we only need to do for the last N (typically 10)
    # most frequent (lowest tfidf domains) i.e. only for the googles and amazons of
    # the world that have multiple country specific domains
    lowest_n_tfidf_domains = low_tfidf_domains[-g.LOWEST_N_TFIDF_DOMAINS:]

    # remove any low tfidf domains and single word domains (like some random xqsdfhh that chrome creates
    # see https://support.umbrella.com/hc/en-us/articles/115005876643-Unusual-DNS-queries-showing-in-reports)
    # for the rest of the domains keep only the most significant piece
    dns_data['query'] = dns_data['query'].map(lambda x: ' '.join([d for d in x.split() if d not in low_tfidf_domains and "." in d]))

    # this seems like a drag but now what happens is that there are consecutive repeated domain names
    # because www.something.com and www.something.edu both translate into www.something and they are consecutive
    # so we need to only keep one occurrence
    dns_data['query'] = dns_data['query'].map(lambda x: ' '.join([e[0] for e in groupby(x.split(' '))]))

    # all done, finally
    return dns_data


def concat_and_write_df(df_list, category, filename, sort_col=None, group_col=None,
                        summarization_fn=None, summarization_col=None):
    logger.info("length of individual dataframes for {}...{}".format(category, [len(e) for e in df_list]))
    concactenated_df = pd.concat(df_list)
    logger.info("length of the combined dns dataframe is {}".format(len(concactenated_df)))

    # group by using the grouping column
    if group_col is not None and summarization_fn is not None:
        logger.info("going to perform {} to aggregate".format(summarization_fn))
        if summarization_fn == "sum":
            concactenated_df = concactenated_df.groupby(group_col).sum().reset_index()
            if sort_col is not None:
                concactenated_df = concactenated_df.sort_values(by=sort_col)
        elif summarization_fn == "concat":
            concactenated_df = concactenated_df.groupby(group_col)[summarization_col].apply(' '.join).reset_index()
        else:
            logger.error("summarization_fn %s is not supported...not grouping by..", summarization_fn)

    # save the combined dataframe to a csv file, this is what the analysis code is going to consume
    combined_file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, filename)
    concactenated_df.to_csv(combined_file_path, index=False)
    return concactenated_df

# ===============================================================================


def wrangle_data(file_list, ccTLD):
    """
    Creates a pool of processes based on configuration and splits the list
    of files between these processes.
    """

    logger.info("going to start multiprocessing and divide file splits between processes")
    num_workers = g.NUM_WORKER_PROCESSES  # for 4 vCPUs, but you can increase it to more than number of vCPUs as well
    logger.info("number of worker processes {}".format(num_workers))

    pool = multiprocessing.Pool(processes=num_workers)

    # start the processes in the pool and split the files between these processes
    start_time = datetime.now()
    results = [pool.apply_async(wrangle_file, args=(f, ccTLD)) for f in file_list]

    # wait for all worker processes to be done
    output_pool = [p.get() for p in results]
    logger.info("all worker processes completed in {} seconds ...".format((datetime.now()-start_time).total_seconds()))
    logger.info("number of dataframes returned after wrangling {}".format(len(output_pool)))

    # extract individual dataframes from the returned values
    combined_dns_data = [e[0] for e in output_pool]
    combined_qtype_stats = [e[1] for e in output_pool]
    combined_fqdn_stats = [e[2] for e in output_pool]
    combined_hourly_query_counts = [e[3] for e in output_pool]
    combined_hourly_per_query_count_timeseries = [e[4] for e in output_pool]
    combined_hourly_domain_len_in_tokens_timeseries = [e[5] for e in output_pool]
    combined_hourly_per_single_token_query_timeseries = [e[6] for e in output_pool]
    combined_first_token_counts = [e[7] for e in output_pool]
    combined_src_ip_stats = [e[8] for e in output_pool]
    combined_hourly_qtype_stats = [e[9] for e in output_pool]
    combined_hourly_query_count_by_unique_ip = [e[10] for e in output_pool]

    # write each combined dataframe to file
    dns_data = concat_and_write_df(combined_dns_data, "dnsdata", g.WRANGLED_DATASET_FILE_NAME, None,
                                   ["ts_aggr", "subnet"], "concat", "query")
    qtype_stats = concat_and_write_df(combined_qtype_stats, "query type stats", g.QUERY_TYPE_STATS_FILE_NAME, None,
                                      "qtype", "sum")
    fqdn_stats = concat_and_write_df(combined_fqdn_stats, "fqdn stats", g.FQDN_STATS_FILE_NAME, "n",
                                     "query", "sum")
    hourly_query_counts = concat_and_write_df(combined_hourly_query_counts, "hourly all query counts",
                                              g.HOURLY_TOTAL_QUERY_COUNT_TIMESERIES_FILE_NAME, None, "ymd_h", "sum")

    hourly_per_query_counts = concat_and_write_df(combined_hourly_per_query_count_timeseries,
                                                  "hourly per query counts",
                                                  g.HOURLY_PER_QUERY_COUNT_TIMESERIES_FILE_NAME, None,
                                                  ["ymd_h", "query"], "sum")

    hourly_per_single_token_query_timeseries = concat_and_write_df(combined_hourly_per_single_token_query_timeseries,
                                                                   "hourly per single tokenn query counts",
                                                                   g.HOURLY_PER_SINGLE_TOKEN_QUERY_COUNT_TIMESERIES_FILE_NAME,
                                                                   None, ["ymd_h", "query"], "sum")

    hourly_domain_len_in_tokens = concat_and_write_df(combined_hourly_domain_len_in_tokens_timeseries,
                                                      "hourly domain len in tokens counts",
                                                      g.HOURLY_DOMAIN_LEN_IN_TOKENS_TIMESERIES_FILE_NAME, None,
                                                      ["ymd_h", "domain_len_in_tokens"], "sum")

    first_token_counts = concat_and_write_df(combined_first_token_counts,
                                             "first token counts",
                                             g.FIRST_TOKEN_COUNTS_FILE_NAME, "n",
                                             ["first_token"], "sum")

    src_ip_stats = concat_and_write_df(combined_src_ip_stats, "source IP stats", g.SRC_IP_STATS_FILE_NAME, None,
                                       "ip", "sum")

    hourly_qtype_stats = concat_and_write_df(combined_hourly_qtype_stats, "per hour query type stats",
                                             g.HOURLY_QUERY_TYPE_STATS_FILE_NAME, "n",
                                             ["ymd_h", "qtype"], "sum")

    hourly_unique_src_ip_count_per_query_stats = concat_and_write_df(combined_hourly_query_count_by_unique_ip,
                                                                     "hourly query count by unique ip",
                                                                     g.HOURLY_UNIQUE_SRC_IP_COUNT_PER_QUERY, None,
                                                                     ["ymd_h", "query"], "sum")

    logger.info("results..all done in {} seconds ...".format((datetime.now()-start_time).total_seconds()))
    return dns_data, qtype_stats, fqdn_stats, hourly_query_counts, \
    hourly_per_query_counts, hourly_domain_len_in_tokens, \
    hourly_per_single_token_query_timeseries, first_token_counts, src_ip_stats, hourly_qtype_stats,\
    hourly_unique_src_ip_count_per_query_stats


# ===============================================================================

class EpochLogger(CallbackAny2Vec):
    '''Callback to log information about training'''
    def __init__(self):
        self.epoch = 0

    def on_epoch_begin(self, model):
        print("Epoch #{} start".format(self.epoch))

    def on_epoch_end(self, model):
        # Upto Gensim 3.5.0 there is a bug which prevents loss from
        # being reported correctly. See https://github.com/RaRe-Technologies/gensim/pull/2135
        # This is currently (11/18/2018) labeled as almost complete on the github issue.
        # Until a new version of Gensim is available which has the fix, we would
        # need to use the delta between the loss values of consecutive epochs to convince
        # ourselves that training is proceeding in the right direction (i.e. loss is
        # actually reducing). See this SO https://stackoverflow.com/questions/52038651/loss-does-not-decrease-during-training-word2vec-gensim
        print("Epoch #{} end".format(self.epoch))
        print("latest training loss is {}".format(model.get_latest_training_loss()))

        # also write to file, useful while plotting in a notebook
        file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME, g.MODEL_TRAINING_LOSS_FILE_NAME)
        mode = "w" if self.epoch == 0 else "a"
        with open(file_path, mode) as f:
            f.write("{}.{}\n".format(self.epoch, model.get_latest_training_loss()))

        self.epoch += 1

def save_dns_vectors_for_tensorboard(model):
    tensor_file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME, g.DNS_VECTORS_FILE_NAME)
    metadata_file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME, g.DNS_VECTOR_METADATA_FILE_NAME)

    with open(tensor_file_path, 'w+') as tensors:
        with open(metadata_file_path, 'w+') as metadata:
            for word in model.wv.index2word:
                encoded=word #.encode('utf-8')
                metadata.write(encoded + '\n')
                vector_row = '\t'.join(map(str, model.wv[word]))
                tensors.write(vector_row + '\n')

def run_dns2vec_tests(model):
    logger.info("finding most similar domains for the following domains...")

    df = pd.DataFrame([(q,', '.join([d for d,_ in model.wv.most_similar(q, topn=g.TOP_N_SIMILAR_WORDS)])) for q in g.QUERIES])
    df.columns = ['Query Name', 'Similar Domains']

    file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME, g.SIMILAR_DOMAINS_FILE_NAME) 
    df.to_csv(file_path, index=False)
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        logger.info(df)

def app_main(config):
    """
    Main loop of the program
    1. Split the input file into chunks
    2. Create a pool of worker processes and distribute the chunks between the processes
    3. Write the combined dataframe to a file
    """
    logger.info("in app_main")

    # initialize some variables that we need
    dns_data = None

    logger.info("configured action is {}".format(config.action))

    run_dir = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME)
    os.makedirs(run_dir, exist_ok=True)

    if config.action == g.ACTION_WRANGLE_ONLY or config.action == g.ACTION_RUN_ALL:
        logger.info("running data wrangling operations...")

        # Step 0: read data needed by all worker threads
        file_path = os.path.join(g.RAW_DATA_DIR, g.DATASET_VER, g.CCTLD_FILE_NAME)
        ccTLD = pd.read_csv(file_path)
        logger.info("read country code top level domains...")
        logger.info(ccTLD.head())

        # step 1, split the file into chunks
        # we expect the file to be within the current project, soon this will be replaced
        # with download from a dataset repo if not present so the file is downloaded one time
        # and then available for use as long as the version number does not change (DATASET_VER)
        src_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(src_dir, g.RAW_DATA_DIR, g.DATASET_VER, config.filename)
        output_dir = os.path.join(src_dir, g.DATA_DIR, g.DATASET_VER, g.SPLITS_DIR)

        p = Path(file_path)
        if p.exists() is False:
            logger.error("%s does not exist, existing %s", file_path, g.APP_NAME)
            sys.exit()
        else:
            logger.info("%s found, going to split it into %sMB sized chunks now", file_path, config.splitsizemb)
            os.makedirs(output_dir, exist_ok=True)
            split_size = g.MB*int(config.splitsizemb)

            # the split will create a malformed last line because it is size based and not line based
            # but that is ok..we have millions of lines so a few do not matterHOURLY_UNIQUE_SRC_IP_COUNT_PER_LOW_TFIDF_QUERY
            fs = FileSplit(file_path, split_size, output_dir)
            fs.split()

        logger.info("file split complete..moving to wrangling stage now")

        file_list = [os.path.join(output_dir, f) for f in os.listdir(output_dir)
                     if os.path.isfile(os.path.join(output_dir, f))]
        logger.info("file names for the splits are {}".format(file_list))

        # step 2: wrangle data
        dns_data, _, fqdn_stats, _, hourly_per_query_counts, _, _, _, _, _, hourly_unique_src_ip_counts = wrangle_data(file_list, ccTLD)
        logger.info("done wrangling data...")

        # step 3: get tfidf values for each domain so we can identify stop domains like stop words
        logger.info("going to do tfidf on domain names to figure out stop domains now..")
        fqdn_tfidf, fqdn_tfidf_subset = do_tfidf_transform_on_query_names()

        # step 3.1, create file with per hour query count most non-informative domains (from our perspective of
        # figuring out similarities between domain names)
        low_tfidf_domains = fqdn_tfidf_subset['fqdn']
        hourly_per_query_counts_low_tfidf = hourly_per_query_counts[hourly_per_query_counts['query'].isin(low_tfidf_domains)]
        file_path = os.path.join(src_dir, g.DATA_DIR, g.DATASET_VER,
                                 g.HOURLY_PER_QUERY_COUNT_LOW_TFIDF_TIMESERIES_FILE_NAME)
        hourly_per_query_counts_low_tfidf.to_csv(file_path, index=False)

        # step 3.2, create file with per hour unique src ip counts most non-informative domains
        # (from our perspective of figuring out similarities between domain names)
        hourly_unique_src_ip_counts_low_tfidf = hourly_unique_src_ip_counts[hourly_unique_src_ip_counts['query'].isin(low_tfidf_domains)]
        file_path = os.path.join(src_dir, g.DATA_DIR, g.DATASET_VER,
                                 g.HOURLY_UNIQUE_SRC_IP_COUNT_PER_LOW_TFIDF_QUERY)
        hourly_unique_src_ip_counts_low_tfidf.to_csv(file_path, index=False)

        # step 3.3, create file with per hour unique src ip counts for top 100 most frequently accessed domains
        hourly_unique_src_ip_counts_for_most_freq = hourly_unique_src_ip_counts[hourly_unique_src_ip_counts['query'].isin(fqdn_stats.tail(g.N_FOR_FQDNS_W_LOWEST_TFIDF)['query'])]
        file_path = os.path.join(src_dir, g.DATA_DIR, g.DATASET_VER,
                                 g.HOURLY_UNIQUE_SRC_IP_COUNT_MOST_FREQ_FQDNS)
        hourly_unique_src_ip_counts_for_most_freq.to_csv(file_path, index=False)

        # going to do some post processing on dns data
        # 1. remove the low tfidf domains i.e. treat them like stopwords in a sentence
        # 2. shorten the domain names to only keep the most significant part of it
        # 3. write to dnsdata file
        logger.info("going to post process dns data from previous step to remove stop domain names")
        dns_data = post_process_dns_data(dns_data, low_tfidf_domains, ccTLD)
        file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.WRANGLED_DATASET_FILE_NAME)
        dns_data.to_csv(file_path, index=False)
        logger.info("wrote the final dns dataset to {}".format(file_path))

    if config.action == g.ACTION_ANALYZE_ONLY or config.action == g.ACTION_RUN_ALL:
        logger.info("running analysis...")
        if dns_data is None:
            # read the dns dataset created as part of the analysis phase, either in this run
            # or the previous one
            file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.WRANGLED_DATASET_FILE_NAME)
            dns_data = pd.read_csv(file_path)

        # we have the data, either from the previous step or reading from the file
        logger.info(dns_data['query'].head())

        # read each line from the dataframe, split it to convert it into an array
        #  because word2vec needs an array of arrays (sentences)..
        # but before we do that we also need to typecast each
        # individual domain name in the "sentence" to a string because some domain names like
        # 169.254 make Python think this is a float..
        # queries_as_sentences = [[q for q in str(queries).split() if q.startswith("www")] for queries in dns_data['query']]
        queries_as_sentences = [str(queries).split() for queries in dns_data['query']]

        # write this list of lists to a file, we would use this as input to an LSTM model
        # to predict what domain name comes after a sequence of domains
        file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.FINAL_INPUT_TO_W2V_MODEL_FILE_NAME) 
        with open(file_path,"w") as f:
            wr = csv.writer(f)
            wr.writerows(queries_as_sentences)

        # logger.info([len(q) for q in queries_as_sentences])

        # run word2vec
        # log all the word2vec config to a file for record purposes
        file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME, g.W2V_PARAMS_FILE_NAME)
        with open(file_path, "w") as w2v_params_file:
            w2v_parms = { 'run_name': g.RUN_NAME,
                          'num_sentences': len(queries_as_sentences),
                          'embedding_size': g.W2V_EMBEDDING_SIZE,
                          'window_size': g.W2V_WINDOW,
                          'min_count': g.W2V_MIN_COUNT,
                          'negative': g.W2V_NEGATIVE_SAMPLING,
                          'max_vocab_size': g.W2V_MAX_VOCAB_SIZE,
                          'sample': g.W2V_SAMPLE,
                          'ns_exponent': g.W2V_NS_EXPONENT,
                          'num_workers': g.W2V_WORKERS,
                          'sg': g.W2V_USE_SG,
                          'epochs': g.WV_EPOCHS,
                          'seed': g.WV_SEED }
            w2v_params_file.write(json.dumps(w2v_parms, indent=2))
        model_dns = Word2Vec(sentences=queries_as_sentences, size=g.W2V_EMBEDDING_SIZE, window=g.W2V_WINDOW,
                             min_count=g.W2V_MIN_COUNT, workers=g.W2V_WORKERS, sg=g.W2V_USE_SG, iter=g.WV_EPOCHS,
                             negative = g.W2V_NEGATIVE_SAMPLING, max_vocab_size=g.W2V_MAX_VOCAB_SIZE,
                             sample = g.W2V_SAMPLE, ns_exponent = g.W2V_NS_EXPONENT, 
                             seed=g.WV_SEED, compute_loss=True, callbacks=[EpochLogger()])


        file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.RUN_NAME,
                                 g.DNS_DATASET_FILE_NAME.split('.')[0] + g.MODEL_FILE_SUFFIX)
        logger.info("saving Dns2Vc model to {}".format(file_path))
        model_dns.save(file_path)

        logger.info("going to save dns vectors...")
        save_dns_vectors_for_tensorboard(model_dns)

        logger.info("going to run tests to predict similar domains...")
        run_dns2vec_tests(model_dns)

    logger.info("nothing more to do..")


def main(args=None):
    """
    The args option allows for dnswrangler to be run in-process from a test
    adapter, such as when running it from the integration test runner.
    Normally, when running standalone, args and None and the argparser
    will fetch them from sys.argv as its default behavior
    """
    opts = parse_args(args)

    logger.info('Starting %s', g.APP_NAME)
    # Dump the full config being used to the log file for reference
    logger.info(repr(opts))

    try:
        logger.info('PID={}'.format(os.getpid()))
        # config and logging set, time to start the main app
        app_main(opts)
    except KeyboardInterrupt:
        """                                                                                
        Trap any CTRL+C interrupts from a commandline run and issue a SIGTERM              
        so that we catch it a fall into our normal signal handing and shut                 
        down logic                                                                         
        """
        pid = os.getpid()
        logger.warning('KeyboardInterrupt, sending SIGTERM to pid={}'.format(pid))
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        # Dump stack trace for any exception that gets this far
        logger.exception(e)

    logger.info('Exiting process')

###########################################################
# MAIN
###########################################################


if __name__ == '__main__':
    main()
