# aws_s3_bucket.logs was removed from configuration.

resource "aws_s3_bucket" "app" {
  bucket = "demo-app-123456789012"
  tags = {
    Owner = "platform"
  }
}
