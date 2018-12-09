**DNS2Vec**

A Python based application multiprocessing application that consumes a large dns query trace file, and performs various analysis on it such as determining hourly query count, which types of queries, how many tokens per query and so on but the primary purpose is to do Dns2Vec.

The entire data cleaning/wrangling pipeline and Dns2Vec implementation is in the main.py file. The Dns2Vec.ipynb notebook provides a way of playing with an already created Dns2Vec model which contains the word (domain name) vectors.

The final set of hyper parameters and results from running the model are available in the data/1.0.0.0/run_150_epochs folder.
