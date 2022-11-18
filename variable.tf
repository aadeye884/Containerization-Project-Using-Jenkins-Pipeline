variable "VPC_cidr_block" {
  default     = "10.0.0.0/16"
  description = "custom VPC cidr block"
}
variable "VPC_tag_name" {
  default     = "PAPUST_VPC"
  description = "custom VPC tag name"
}
variable "public_subnet1_cidr_block" {
  default     = "10.0.1.0/24"
  description = "public subnet1 cidr block"
}
variable "public_subnet1_availabilityzone" {
  default     = "us-east-1a"
  description = "public subnet1 availability zone"
}
variable "public_subnet2_cidr_block" {
  default     = "10.0.3.0/24"
  description = "public subnet2 cidr block"
}
variable "public_subnet2_availabilityzone" {
  default     = "us-east-1b"
  description = "public subnet2 availability zone"
}
variable "private_subnet1_cidr_block" {
  default     = "10.0.2.0/24"
  description = "private subnet1 cidr block"
}
variable "private_subnet1_availabilityzone" {
  default     = "us-east-1a"
  description = "private subnet1 availability zone"
}
variable "private_subnet2_cidr_block" {
  default     = "10.0.4.0/24"
  description = "private subnet2 cidr block"
}
variable "private_subnet2_availabilityzone" {
  default     = "us-east-1b"
  description = "private subnet2 availability zone"
}
variable "public_routetable_cidr_block" {
  default     = "0.0.0.0/0"
  description = "public route table cidr block"
}
variable "private_routetable_cidr_block" {
  default     = "0.0.0.0/0"
  description = "private route table cidr block"
}
variable "ami" {
  default = "ami-06640050dc3f556bb"
}
variable "instance_type_Jenkins" {
  default = "t2.medium"
}
variable "instance_type_Docker" {
  default = "t2.micro"
}
variable "path_to_public_key" {
  default     = "~/Keypairs/UST-apC.pub"
  description = "This is the path to our public key"
}
variable "keypair_name" {
  default = "UST-apC"
}
variable "region" {
  default     = "us-east-1"
  description = "provider region"
}
variable "identifier" {
  default = "papust-db"
}
variable "db_username" {
  default = "admin"
}
variable "db_passwd" {
  default = "Admin123"
}
variable "db_name" {
  default     = "papustdb"
  description = "database name"
}
variable "domain_name" {
  default = "www.elizabethfolzgroup.com"
}