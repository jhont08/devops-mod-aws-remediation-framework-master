resource "aws_s3_bucket" "s3_bucket_lambda_remediation" {
  count  = length(split(",", var.regions))
  bucket = "${var.lambda_bucket}-${element(split(",", var.regions), count.index)}"
  tags   = var.tags


}

resource "aws_s3_bucket_public_access_block" "lambda_remediation_access_block" {
  count               = length(aws_s3_bucket.s3_bucket_lambda_remediation)
  bucket              = aws_s3_bucket.s3_bucket_lambda_remediation[count.index].bucket
  block_public_acls   = true
  block_public_policy = true
}
