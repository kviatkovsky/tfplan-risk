resource "aws_iam_policy" "ci" {
  name = "demo-ci"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Deploy"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::demo-artifacts-123456789012/*"
      },
      {
        Sid      = "Everything"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ci_admin" {
  role       = "demo-ci"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "launcher" {
  name = "launcher"
  role = "demo-ci"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PassRole", "ec2:RunInstances"], Resource = "*" }]
  })
}

# The document depends on a value known only after apply, so the plan shows
# policy as unknown.
resource "aws_iam_role_policy" "generated" {
  name = "generated"
  role = "demo-ci"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.jobs.arn }]
  })
}

resource "aws_sqs_queue" "jobs" {
  name = "demo-jobs"
}
