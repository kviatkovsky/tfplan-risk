resource "aws_iam_policy" "ci" {
  name = "demo-ci"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "Deploy"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::demo-artifacts-123456789012/*"
    }]
  })
}
