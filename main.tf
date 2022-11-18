#1 Create a VPC
resource "aws_vpc" "PAPUST_VPC" {
  cidr_block       = var.VPC_cidr_block
  instance_tenancy = "default"

  tags = {
    Name = "var.VPC_tag_name"
  }
}

#2 Create Public Subnet 01
resource "aws_subnet" "PAPUST_Public_SN1" {
  vpc_id            = aws_vpc.PAPUST_VPC.id
  cidr_block        = var.public_subnet1_cidr_block
  availability_zone = var.public_subnet1_availabilityzone

  tags = {
    Name = "PAPUST_Public_SN1"
  }
}

#3 Create Public Subnet 02
resource "aws_subnet" "PAPUST_Public_SN2" {
  vpc_id            = aws_vpc.PAPUST_VPC.id
  cidr_block        = var.public_subnet2_cidr_block
  availability_zone = var.public_subnet2_availabilityzone

  tags = {
    Name = "PAPUST_Public_SN2"
  }
}

#4 Create Private Subnet 01
resource "aws_subnet" "PAPUST_PrvSN1" {
  vpc_id            = aws_vpc.PAPUST_VPC.id
  cidr_block        = var.private_subnet1_cidr_block
  availability_zone = var.private_subnet1_availabilityzone
 
  tags = {
    Name = "PAPUST_Private_SN1"
  }
}

#5 Create Private Subnet 02
resource "aws_subnet" "PAPUST_Private_SN2" {
  vpc_id            = aws_vpc.PAPUST_VPC.id
  cidr_block        = var.private_subnet2_cidr_block
  availability_zone = var.private_subnet2_availabilityzone
  
  tags = {
    Name = "PAPUST_Private_SN2"
  }
}

#6 Create Internet Gateway
resource "aws_internet_gateway" "PAPUST_IGW" {
  vpc_id = aws_vpc.PAPUST_VPC.id

  tags = {
    Name = "PAPUST_IGW"
  }
}

#7 Create Public Route Table
resource "aws_route_table" "PAPUST_PubRT" {
  vpc_id = aws_vpc.PAPUST_VPC.id

  route {
    cidr_block = var.public_routetable_cidr_block
    gateway_id = aws_internet_gateway.PAPUST_IGW.id
  }

  tags = {
    Name = "PAPUST_PubRT"
  }
}

#8 Create Route Table Association for Public Subnet 01
resource "aws_route_table_association" "PAPUST_RTAssoc1" {
  subnet_id      = aws_subnet.PAPUST_Public_SN1.id
  route_table_id = aws_route_table.PAPUST_PubRT.id
}

#9 Create Route Table Association for Public Subnet 02
resource "aws_route_table_association" "PAPUST_RTAssoc2" {
  subnet_id      = aws_subnet.PAPUST_Public_SN2.id
  route_table_id = aws_route_table.PAPUST_PubRT.id
}

#10 Create NAT Gateway
resource "aws_nat_gateway" "PAPUST_NAT" {
  allocation_id = aws_eip.PAPUST_EIP.id
  subnet_id     = aws_subnet.PAPUST_Public_SN1.id

  tags = {
    Name = "PAPUST_NAT"
  }
}

#11 Create Elastic IP Address for NAT Gateway
resource "aws_eip" "PAPUST_EIP" {
  vpc = true
}

#12 Create Private_Route Table
resource "aws_route_table" "PAPUST_PrvSNRT" {
  vpc_id = aws_vpc.PAPUST_VPC.id

  route {
    cidr_block     = var.private_routetable_cidr_block
    nat_gateway_id = aws_nat_gateway.PAPUST_NAT.id
  }

  tags = {
    Name = "PAPUST_PrvSNRT"
  }
}

#13 Create Private Subnet 01 Association
resource "aws_route_table_association" "PAPUST_PrvSN1RTAss" {
  subnet_id      = aws_subnet.PAPUST_PrvSN1.id
  route_table_id = aws_route_table.PAPUST_PrvSNRT.id
}

#14 Create Private Subnet 02 Association
resource "aws_route_table_association" "PAPUST_PrvSN2RTAss" {
  subnet_id      = aws_subnet.PAPUST_Private_SN2.id
  route_table_id = aws_route_table.PAPUST_PrvSNRT.id
}

#15 Create Jenkins Security Group
resource "aws_security_group" "PAPUST_Jenkins_SG" {
  name        = "PAPUST_Jenkins_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAPUST_VPC.id

  ingress {
    description = "ssh from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "jenkins port from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "PAPUST_Jenkins_SG"
  }
}

# 16 Declare Key Pair
resource "aws_key_pair" "UST-apC" {
  key_name   = "UST-apC"
  public_key = file(var.path_to_public_key)
}

#17 Create Jenkins Server  (using Red Hat for ami and t2.medium for instance type)
resource "aws_instance" "PAPUST_Jenkins_Server" {
  ami                         = var.ami
  instance_type               = var.instance_type_Jenkins
  vpc_security_group_ids      = ["${aws_security_group.PAPUST_Jenkins_SG.id}"]
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.PAPUST_Public_SN1.id
  availability_zone           = var.public_subnet1_availabilityzone
  key_name                    = aws_key_pair.UST-apC.key_name

  user_data = <<-EOF
  #!bin/bash
  sudo yum update -y
  sudo yum install wget -y
  sudo yum install git -y
  sudo yum install maven -y
  sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
  sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
  sudo yum update -y
  sudo yum upgrade -y
  sudo yum install jenkins java-1.8.0-openjdk-devel -y --nobest
  sudo systemctl start jenkins
  sudo systemctl enable jenkins
  echo "license_key: 984fd9395376105d6273106ec42913a399a2NRAL" | sudo tee -a /etc/newrelic-infra.yml
  sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
  sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
  sudo yum install newrelic-infra -y
  sudo yum install sshpass -y
  sudo su
  echo Admin123@ | passwd ec2-user --stdin
  echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
  sudo sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sudo service sshd reload
  su - ec2-user -c "ssh-keygen -f ~/.ssh/PAPUSTjenkey_rsa -t rsa -b 4096 -m PEM -N ''"
  sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
  sudo su - ec2-user -c 'sshpass -p "Admin123@" ssh-copy-id -i /home/ec2-user/.ssh/PAPUSTjenkey_rsa.pub ec2-user@${data.aws_instance.PAPUST_Ansible_IP.public_ip} -p 22'
  EOF

  tags = {
    Name = "PAPUST_Jenkins_Server"
  }
}

#18 Create Data Resource for for Ansible-IP
data "aws_instance" "PAPUST_Ansible_IP" {
  filter {
    name   = "tag:Name"
    values = ["PAPUST_Ansible"]
  }
  depends_on = [
    aws_instance.PAPUST_Ansible_host,
  ]
}

#19 Create FrontEnd Security Group for Docker
resource "aws_security_group" "PAPUST_Docker_SG" {
  name        = "PAPUST_Docker_SG"
  description = "Allow inbound Traffic"
  vpc_id      = aws_vpc.PAPUST_VPC.id
  ingress {
    description = "Allow SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Proxy from VPC"
    from_port   = 8085
    to_port     = 8085
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "PAPUST_Docker_SG"
  }
}

#20 Create EC2 Instance for Docker host using a t2.micro RedHat ami
resource "aws_instance" "PAPUST_Docker_host" {
  ami                         = var.ami
  instance_type               = var.instance_type_Docker
  subnet_id                   = aws_subnet.PAPUST_Public_SN1.id
  vpc_security_group_ids      = ["${aws_security_group.PAPUST_Docker_SG.id}"]
  associate_public_ip_address = true
  availability_zone           = var.public_subnet1_availabilityzone
  key_name                    = aws_key_pair.UST-apC.key_name

  user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker 
sudo systemctl enable docker
echo Admin123@ | passwd ec2-user --stdin
echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
su - ec2-user
# sudo chmod -R 700 .ssh/
# sudo chmod 600 .ssh/authorized_keys
echo "license_key: 2321a849d57e69fe9b28378de6b0c5ebb3ceNRAL" | sudo tee -a /etc/newrelic-infra.yml 
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo usermod -aG docker ec2-user
docker run hello-world
EOF

  tags = {
    Name = "PAPUST_Docker_host"
  }
}

#21 Create Data Resource for for Docker-IP
data "aws_instance" "PAPUST_Docker_IP" {
  filter {
    name   = "tag:Name"
    values = ["PAPUST_Docker_host"]
  }
  depends_on = [
    aws_instance.PAPUST_Docker_host,
  ]
}

#22 Create Ansible Security Group
resource "aws_security_group" "PAPUST_Ansible_SG" {
  name        = "PAPUST_Ansible_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAPUST_VPC.id

  ingress {
    description = "ssh from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "PAPUST_Ansible_SG"
  }
}

#23 Create Ansible Instance Host
resource "aws_instance" "PAPUST_Ansible_host" {
  ami                         = var.ami
  instance_type               = var.instance_type_Docker
  subnet_id                   = aws_subnet.PAPUST_Public_SN1.id
  vpc_security_group_ids      = ["${aws_security_group.PAPUST_Ansible_SG.id}"]
  associate_public_ip_address = true
  availability_zone           = var.public_subnet1_availabilityzone
  key_name                    = aws_key_pair.UST-apC.key_name
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3.8 -y
sudo alternatives --set python /usr/bin/python3.8
sudo yum -y install python3-pip
sudo yum install ansible -y
pip3 install ansible --user
sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
sudo yum install sshpass -y
sudo su
echo Admin123@ | passwd ec2-user --stdin
echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
su - ec2-user
# sudo chown -R ec2-user:ec2-user/.ssh/authorized_keys
# sudo chmod 600 /home/ec2-user/.ssh/authorized_keys
# sudo chown ec2-user:ec2-user/etc/ansible
su - ec2-user -c "ssh-keygen -f ~/.ssh/PAPUSTanskey_rsa -t rsa -N ''"
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sudo su - ec2-user -c 'sshpass -p "Admin123@" ssh-copy-id -i /home/ec2-user/.ssh/PAPUSTanskey_rsa.pub ec2-user@${data.aws_instance.PAPUST_Docker_IP.public_ip} -p 22'
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
cd /etc
sudo chown ec2-user:ec2-user hosts
cat <<EOT>> /etc/ansible/hosts
localhost ansible_connection=local
[docker_host]
${data.aws_instance.PAPUST_Docker_IP.public_ip}  ansible_ssh_private_key_file=/home/ec2-user/.ssh/PAPUSTanskey_rsa
EOT
sudo mkdir /opt/docker
sudo chown -R ec2-user:ec2-user /opt/
sudo chown -R ec2-user:ec2-user docker/
sudo chmod 700 home/ec2-user/opt/docker
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
# pull tomcat image from docker hub
FROM tomcat
FROM openjdk
LABEL MAINTAINER PAPUST
#copy war file on the container
COPY ./spring-petclinic-2.4.2.war app/
WORKDIR app/
ENTRYPOINT [ "java", "-jar", "spring-petclinic-2.4.2.war", "--server.port=8085" ]
EOT
touch /opt/docker/docker-image.yml
cat <<EOT>> /opt/docker/docker-image.yml
---
 - hosts: localhost
  #root access to user
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Create docker image from Pet Adoption war file
     command: docker build -t pet-adoption-image .
     args:
       chdir: /opt/docker
   - name: Add tag to image
     command: docker tag pet-adoption-image cloudhight/pet-adoption-image
   - name: Push image to docker hub
     command: docker push cloudhight/pet-adoption-image
   - name: Remove docker image from Ansible node
     command: docker rmi pet-adoption-image cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/docker-container.yml
cat <<EOT>> /opt/docker/docker-container.yml
---
 - hosts: docker_host
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Stop any container running
     command: docker stop pet-adoption-container
     ignore_errors: yes
   - name: Remove stopped container
     command: docker rm pet-adoption-container
     ignore_errors: yes
   - name: Remove docker image
     command: docker rmi cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Pull docker image from dockerhub
     command: docker pull cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Create container from pet adoption image
     command: docker run -it -d --name pet-adoption-container -p 8080:8080 cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/newrelic.yml
cat <<EOT>> /opt/docker/newrelic.yml
---
 - hosts: docker_host
   become: true
   tasks:
   - name: install newrelic agent
     command: docker run \
                     -d \
                     --name newrelic-infra \
                     --network=host \
                     --cap-add=SYS_PTRACE \
                     --privileged \
                     --pid=host \
                     -v "/:/host:ro" \
                     -v "/var/run/docker.sock:/var/run/docker.sock" \
                     -e NRIA_LICENSE_KEY=984fd9395376105d6273106ec42913a399a2NRAL \ 
                     newrelic/infrastructure:latest
EOT
EOF 
  tags = {
    Name = "PAPUST_Ansible"
  }
}

# 2 Create a Target Group for load balancer
resource "aws_lb_target_group" "PAPUST-tglb" {
  name        = "PAPUST-tglb"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.PAPUST_VPC.id
  target_type = "instance"
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 10
    interval            = 90
    timeout             = 60
  }
}

resource "aws_lb_target_group_attachment" "PAPUST-tg-attachment" {
  target_group_arn = aws_lb_target_group.PAPUST-tglb.arn
  target_id        = aws_instance.PAPUST_Docker_host.id
  port             = 8080
}

# 3 Create a load balancer lisener 
resource "aws_lb_listener" "PAPUST-lb-listener" {
  load_balancer_arn = aws_lb.PAPUST-alb.arn
  port              = "8080"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.PAPUST-tglb.arn
  }
}

#create a application load balancer 
resource "aws_lb" "PAPUST-alb" {
  name                       = "PAPUST-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.PAPUST_Docker_SG.id]
  subnets                    = [aws_subnet.PAPUST_Public_SN1.id, aws_subnet.PAPUST_Public_SN2.id]
  enable_deletion_protection = false
  tags = {
    Enviroment = "production"
  }
}

# Create AMI from docker instance
resource "aws_ami_from_instance" "PAPUST_Docker_ami" {
  name                    = "PAPUST-ami"
  source_instance_id      = aws_instance.PAPUST_Docker_host.id
  snapshot_without_reboot = true
  depends_on = [
    aws_instance.PAPUST_Docker_host
  ]
}
# Launch Configuration for autoscaling group = PAPUST-lc
resource "aws_launch_configuration" "PAPUST-lc" {
  name_prefix                 = "PAPUST-acplc"
  image_id                    = aws_ami_from_instance.PAPUST_Docker_ami.id
  instance_type               = "t2.micro"
  security_groups             = [aws_security_group.PAPUST_Docker_SG.id]
  associate_public_ip_address = true
  key_name                    = var.keypair_name
}

# 6 Autoscaling Group = PAPUST-asg
resource "aws_autoscaling_group" "PAPUST-asg" {
  name                      = "PAPUST-asg"
  desired_capacity          = 3
  max_size                  = 4
  min_size                  = 2
  health_check_grace_period = 300
  default_cooldown          = 60
  health_check_type         = "ELB"
  force_delete              = true
  launch_configuration      = aws_launch_configuration.PAPUST-lc.name
  vpc_zone_identifier       = [aws_subnet.PAPUST_Public_SN1.id, aws_subnet.PAPUST_Public_SN2.id]
  target_group_arns         = ["${aws_lb_target_group.PAPUST-tglb.arn}"]
  tag {
    key                 = "Name"
    value               = "PAPUST-asg"
    propagate_at_launch = true
  }
}

# Autoscaling Group Policy = PAPUST-asgpol
resource "aws_autoscaling_policy" "PAPUST-asgpol" {
  name                   = "PAPUST-asgpol"
  policy_type            = "TargetTrackingScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.PAPUST-asg.name
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}

# Backend Security group = PAPUST-Backend-sg
resource "aws_security_group" "PAPUST_Backend_SG" {
  name        = "PAPUST_Backend_SG"
  description = "Enables SSH & MYSQL access"
  vpc_id      = aws_vpc.PAPUST_VPC.id
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.3.0/24"]
  }
  ingress {
    description = "MYSQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.3.0/24"]
  }
  egress {
    description = "HTTP"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "PAPUST_Backend_SG"
  }
}

# Create a multi AZ RDS database
# DB subnet group = "PAPUST-db-sng
resource "aws_db_subnet_group" "papust-db-sng" {
  name       = "papust-db-sng"
  subnet_ids = [aws_subnet.PAPUST_PrvSN1.id, aws_subnet.PAPUST_Private_SN2.id]
  tags = {
    Name = "papust-db-sng"
  }
}

# RDS database =papust-db
resource "aws_db_instance" "papust-db" {
  allocated_storage      = 20
  identifier             = var.identifier
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  multi_az               = true
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_passwd
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.papust-db-sng.id
  vpc_security_group_ids = [aws_security_group.PAPUST_Backend_SG.id]
  publicly_accessible    = false
}

# Route 53 Hosted Zone
resource "aws_route53_zone" "papust_zone" {
  name          = var.domain_name
  force_destroy = true
}

# Route 53 A Record
resource "aws_route53_record" "PAPUST_Website" {
  zone_id = aws_route53_zone.papust_zone.zone_id
  name    = var.domain_name
  type    = "A"
  # ttl     = "300" - (Use when not associating route53 to a load balancer)
  # records = [aws_instance.PAP_Docker_Host.public_ip]
  alias {
    name                   = aws_lb.PAPUST-alb.dns_name
    zone_id                = aws_lb.PAPUST-alb.zone_id
    evaluate_target_health = false
  }
}