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

  ingress {
    description = "temporary debug access"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = "sg-0f1e2d3c4b5a69788"
  description       = "ssh"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = "sg-0f1e2d3c4b5a69788"
  description       = "https"
  cidr_ipv6         = "::/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
