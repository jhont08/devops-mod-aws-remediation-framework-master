output "output_variable" {
  value       = "${aws_ecr_repository.foo.arn}"
  description = "The ARN or Identifier of a resource"
}
