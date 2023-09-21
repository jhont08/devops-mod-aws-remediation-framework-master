resource "aws_cloudwatch_log_group" "notification" {
  name              = "/aws/lambda/notification"
  retention_in_days = 14
  tags = {
    App         = "Notification"
    department  = "security"
    application = "remediation-framework"
  }
}

resource "aws_iam_role" "notification" {
  name = "notification"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    App         = "Notification"
    department  = "security"
    application = "remediation-framework"
  }
}

data "aws_iam_policy_document" "notification_policy_document" {
  statement {
    actions = [
      "logs:CreateLogGroup",
    ]
    resources = [
      "*",
    ]
  }
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/notification",
      "arn:aws:logs:${var.master_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/notification:*",
    ]
  }
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      "arn:aws:iam::*:role/member-remediator"
    ]
  }
}

resource "aws_iam_policy" "notification" {
  name   = "notification"
  path   = "/"
  policy = data.aws_iam_policy_document.notification_policy_document.json
}

resource "aws_iam_role_policy_attachment" "notificacion" {
  role       = aws_iam_role.notification.name
  policy_arn = aws_iam_policy.notification.arn
}

resource "aws_lambda_function" "notification" {
  function_name    = "notification-remediation-framework"
  description      = "notification"
  s3_bucket        = var.lambda_bucket
  s3_key           = "notification.zip"
  role             = aws_iam_role.notification.arn
  handler          = "main.handler"
  runtime          = "python3.7"
  timeout          = 60 # 1 minute
  source_code_hash = filebase64sha256("cache/notification.zip")

  environment {
    variables = {
      URL_WEB_HOOK = var.url_web_hook
      CHANNEL      = var.channel_notification
      USERNAME     = var.username_notification
    }
  }

  tags = {
    App         = "Notification"
    department  = "security"
    application = "remediation-framework"
  }
}

resource "aws_sns_topic_subscription" "sns_topic_lambda_notification" {
  topic_arn = aws_sns_topic.remediator_notifications.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.notification.arn
}
