import os
import logging
import pandas as pd
import globals as g
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer

logger = logging.getLogger(__name__)


# some handy utility functions
# remove html entities from docs and
# set everything to lowercase
def my_preprocessor(doc):
    return(doc.lower())


# tokenize the doc and lemmatize its tokens
def my_tokenizer(doc):
    return doc.split()


def do_tfidf_transform_on_query_names():
    # our corpus
    file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.WRANGLED_DATASET_FILE_NAME)
    logger.info("going to read {} for tfidf transform".format(file_path))
    df = pd.read_csv(file_path)

    # we only need the query field since we are doing tf-idf on the query names
    data = list(df['query'])

    logger.info("initializing vectorizer..")
    cv = CountVectorizer(preprocessor=my_preprocessor, tokenizer=my_tokenizer)

    # convert text data into term-frequency matrix
    logger.info("convert text to term-frequency matrix..")
    data = cv.fit_transform(data)

    logger.info("initialize tfidf transformer")
    tfidf_transformer = TfidfTransformer()

    # convert term-frequency matrix into tf-idf
    logger.info("going to convert term frequency to tf-idf ...")
    tfidf_transformer.fit_transform(data)

    # create dictionary to find a tfidf word each word
    logger.info("creating dictionary of feature names and tfidf results")
    word_to_tfidf = dict(zip(cv.get_feature_names(), tfidf_transformer.idf_))

    # sort the results
    logger.info("sorting the results..")
    s = sorted([item for item in word_to_tfidf.items()], key=lambda item: item[1], reverse=True)

    # create a dataframe so that we can conveniently write to csv
    df = pd.DataFrame(s)
    df.columns = ['fqdn', 'tfidf']
    logger.info(df)

    # write to file
    file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.FQDN_TFIDF_FILE_NAME)
    logger.info("writing tfidf results {}".format(file_path))
    df.to_csv(file_path, index=False)

    # write last N to file, these are query names that are very frequent
    # across all documents (in this case collection of domains queried across subscribers)
    file_path = os.path.join(g.DATA_DIR, g.DATASET_VER, g.FQDN_TFIDF_SUBSET_FILE_NAME)
    logger.info("writing subset (i.e. {}) of tfidf results {}".format(g.N_FOR_FQDNS_W_LOWEST_TFIDF, file_path))
    df.tail(g.N_FOR_FQDNS_W_LOWEST_TFIDF).to_csv(file_path, index=False)

    # return results to the caller, both datafrmaes would be nice
    return df, df.tail(g.N_FOR_FQDNS_W_LOWEST_TFIDF)
