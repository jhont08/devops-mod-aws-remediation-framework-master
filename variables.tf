variable "tags" {
    type = "map"

    default = {
        team = "DevSecOps"
        system = "Engineering"
  }
}

variable "master_region" {
  description = "master region where remediation function will live"
  default = "us-east-2"
}

variable "accounts" {
  description = "list of aws accounts to watch for misconfigurations"
  default = "489774021742"
}

variable "regions" {
  description = "list of aws regions to watch for misconfigurations"
  type = string
  default = "us-east-1,us-east-2"
}

variable "dev_accounts" {
  description = "list of dev aws accounts to watch for additional checks"
  default = ""
}

variable "org_account" {
  description = "account id of Organization account"
  default = "o-gy9mj9v2v8"
}

variable "remediate" {
  description = "toggle remediation on and off"
  default = "True"
}

variable "guardduty_master_account" {
  description = "account id of guardduty master"
  default = "123456789012"
}

variable "required_tags" {
  description = "list of tags expected on resources"
  default = ""
}

variable "ec2_ignore_list" {
  description = "list of ec2 instance ids to be marked as exception from remediation"
  default = ""
}

variable "s3_bucket_ignore_list" {
  description = "list of s3 buckets to be marked as exception from remediation"
  default = ""
}

variable "remediation_resource_exception" {
  description = "list of resources to be marked as exception from remediation"
  default = ""
}

variable "remediation_module_exception" {
    type=map
    description = "exception for disabling specific modules for accounts"
    default = {
        "123456789012":["ami"]
        "random-account": ["ami","ec2"]
  }
}
