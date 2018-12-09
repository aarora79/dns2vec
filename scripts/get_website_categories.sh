#!/usr/bin/env bash

# script to get categorization for all websites/domain names.
# this script invokes a python program which in turn invokes a Symantec K9
# REST API (which is currently free, probably will remain so) for each
# domain name. Because this is a very slow process especially when we 
# have upwards of 100,000 domain names so this scripts splits the
# input file into 7,000 lines files (number choosen trial and error
# because we cannot feed the entire file as a command line argument
# to the python program, this number works) and then creates another
# script which needs to be run manually which would launch multiple python
# programs, one for each split of the original file.

echo input file name is $1

# create a folder called categories, we will do all our business
# in this folder and not change anything in this current folder
WORK_FOLDER="categories"
mkdir ${WORK_FOLDER}

# copy input file to the new folder
cp $1 ${WORK_FOLDER}

# copy code to the new folder
cp k9.py ${WORK_FOLDER}

# change to the new folder
cd ./${WORK_FOLDER}

# delete any malformed domains that begin with "-", they mess up
# the command line handling when passed to the python program
grep -v "^-" $1 > websites1.txt

# delete any lines with ":" could be due to IPv6 address
# or hostname:port number, bottom line is that it causes the python
# program to crash so we dont need it
grep -v ":" websites1.txt > websites.txt

# splt into multiple files
split -l 700 websites.txt

# delete any previously existing version of the script
GENERATED_SCRIPT="cmd.sh"
rm -f ${GENERATED_SCRIPT}

# the split command splits the file into fixed names like xaa, xab and so on
filelist=`ls x??`

# for each split create a command line
for f in `ls x??`
do
  # cant put the exact command with "`" because the shell tried to
  # execute it right here, we just want to echo the command so instead of
  # ` just put a __ as placeholder which we will later replace
  cmd="/bin/python k9.py __cat ${f}__ > website_categories_${f}.csv &"
  echo ${cmd} >> ${GENERATED_SCRIPT}
done

# the generated script is now ready, give it execute permissions
sed -i 's/__/`/g' ${GENERATED_SCRIPT}
chmod +x ${GENERATED_SCRIPT}
echo ./${WORK_FOLDER}/${GENERATED_SCRIPT} is ready....
echo you would need to run ./${WORK_FOLDER}/${GENERATED_SCRIPT} manually and then
echo once all domain categories have been retrieved i.e. website_categories_x??.csv
echo files have stopped updating and there is no python program running for k9.py
echo then join the generated website_categories_x??.csv files as
echo "cat website_categories_x??.csv > website_categories_k9.csv"

# all done back to the original dir
cd -
