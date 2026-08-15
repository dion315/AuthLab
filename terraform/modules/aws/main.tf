terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

locals {
  name = var.name_prefix

  # App Runner's default domain is generated at creation, so the same two-pass
  # problem as the other clouds applies. See terraform/README.md.
  base_url = var.base_url_override != "" ? var.base_url_override : (
    var.custom_domain != "" ? "https://${var.custom_domain}" : "http://localhost:8000"
  )
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "random_password" "db" {
  length  = 32
  special = false
}

# --- database ----------------------------------------------------------------

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "Postgres access for AuthLab"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    # App Runner services without VPC egress configuration connect from public
    # AWS address space, so the database is reachable publicly. Narrow this,
    # or attach a VPC connector, for anything beyond a lab.
    cidr_blocks = var.database_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "db" {
  name       = "${local.name}-subnets"
  subnet_ids = data.aws_subnets.default.ids
}

resource "aws_db_instance" "db" {
  identifier     = "${local.name}-pg"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.database_instance_class

  allocated_storage = 20
  storage_encrypted = true

  db_name  = "authlab"
  username = "authlab"
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = true

  skip_final_snapshot = true
  apply_immediately   = true
}

# --- secrets -----------------------------------------------------------------

resource "aws_secretsmanager_secret" "app" {
  name                    = "${local.name}/app-config"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    APP_SECRET_KEY = var.app_secret_key
    DATABASE_URL = format(
      "postgresql+psycopg://authlab:%s@%s/authlab?sslmode=require",
      urlencode(random_password.db.result),
      aws_db_instance.db.endpoint,
    )
    BOOTSTRAP_ADMIN_PASSWORD = var.bootstrap_admin_password
  })
}

# --- IAM ---------------------------------------------------------------------

data "aws_iam_policy_document" "apprunner_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["tasks.apprunner.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${local.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.apprunner_assume.json
}

data "aws_iam_policy_document" "secrets_read" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.app.arn]
  }
}

resource "aws_iam_role_policy" "secrets_read" {
  name   = "${local.name}-secrets"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.secrets_read.json
}

data "aws_iam_policy_document" "ecr_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["build.apprunner.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecr_access" {
  count              = var.image_is_ecr ? 1 : 0
  name               = "${local.name}-ecr-access"
  assume_role_policy = data.aws_iam_policy_document.ecr_assume.json
}

resource "aws_iam_role_policy_attachment" "ecr_access" {
  count      = var.image_is_ecr ? 1 : 0
  role       = aws_iam_role.ecr_access[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

# --- compute -----------------------------------------------------------------

resource "aws_apprunner_service" "app" {
  service_name = "${local.name}-app"

  source_configuration {
    auto_deployments_enabled = false

    dynamic "authentication_configuration" {
      for_each = var.image_is_ecr ? [1] : []
      content {
        access_role_arn = aws_iam_role.ecr_access[0].arn
      }
    }

    image_repository {
      image_identifier      = var.image
      image_repository_type = var.image_is_ecr ? "ECR" : "ECR_PUBLIC"

      image_configuration {
        port = "8000"

        runtime_environment_variables = {
          BASE_URL              = local.base_url
          PORT                  = "8000"
          TRUST_PROXY_HEADERS   = "true"
          BOOTSTRAP_ADMIN_EMAIL = var.bootstrap_admin_email
        }

        # Pulled from Secrets Manager at start, never rendered into the service
        # definition. Each key is addressed individually out of the JSON secret.
        runtime_environment_secrets = {
          APP_SECRET_KEY           = "${aws_secretsmanager_secret.app.arn}:APP_SECRET_KEY::"
          DATABASE_URL             = "${aws_secretsmanager_secret.app.arn}:DATABASE_URL::"
          BOOTSTRAP_ADMIN_PASSWORD = "${aws_secretsmanager_secret.app.arn}:BOOTSTRAP_ADMIN_PASSWORD::"
        }
      }
    }
  }

  instance_configuration {
    cpu               = var.cpu
    memory            = var.memory
    instance_role_arn = aws_iam_role.instance.arn
  }

  health_check_configuration {
    protocol            = "HTTP"
    path                = "/healthz"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 1
    unhealthy_threshold = 5
  }

  depends_on = [
    aws_secretsmanager_secret_version.app,
    aws_iam_role_policy.secrets_read,
  ]
}
