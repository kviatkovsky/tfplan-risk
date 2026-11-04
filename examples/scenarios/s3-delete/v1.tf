resource "aws_s3_bucket" "logs" {
  bucket = "demo-logs-123456789012"
}

resource "aws_s3_bucket" "app" {
  bucket = "demo-app-123456789012"
}
