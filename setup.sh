!/usr/bin/env bash
set -ex
bucket_name_prefix=$1
TERRAFORM_BUCKET=$bucket_name_prefix

mkdir -p cache
rm -f cache/*.zip

Field_Separator=$IFS
# set comma as internal field separator for the string list
IFS=,

aws s3api create-bucket --bucket $TERRAFORM_BUCKET
aws s3api put-bucket-tagging --bucket $TERRAFORM_BUCKET --tagging 'TagSet=[{Key=App,Value=remediator}]'

# Install libraries
pip3 install --target resources/remediator/module_cache/ -r requirements.txt --upgrade
