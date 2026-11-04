resource "aws_security_group" "db" {
  name   = "demo-db"
  vpc_id = "vpc-0a1b2c3d4e5f60718"

  ingress {
    description = "postgres from vpc"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
