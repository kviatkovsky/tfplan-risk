resource "aws_db_subnet_group" "main" {
  name       = "demo-db"
  subnet_ids = ["subnet-0a1b2c3d", "subnet-0e1f2a3b"]
}

resource "aws_db_instance" "main" {
  identifier          = "demo-db"
  engine              = "postgres"
  engine_version      = "16.4"
  instance_class      = "db.t4g.medium"
  allocated_storage   = 50
  username            = "app"
  password            = var.db_password
  storage_encrypted   = true # forces replacement
  skip_final_snapshot = false
}

variable "db_password" {
  type      = string
  sensitive = true
}
