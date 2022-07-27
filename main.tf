# Custom VPC
resource "aws_vpc" "PAP_VPC" {
  cidr_block       = var.VPC_cidr_block
  instance_tenancy = "default"

  tags = {
    Name = "PAP_VPC"
  }
}

# Two Public & Two Private Subnets in Diff AZ
resource "aws_subnet" "PAP_Public_SN1" {
  vpc_id            = aws_vpc.PAP_VPC.id
  cidr_block        = var.public_subnet1_cidr_block
  availability_zone = var.public_subnet1_availabilityzone

  tags = {
    Name = "PAP_Public_SN1"
  }
}

resource "aws_subnet" "PAP_Public_SN2" {
  vpc_id            = aws_vpc.PAP_VPC.id
  cidr_block        = var.public_subnet2_cidr_block
  availability_zone = var.public_subnet2_availabilityzone

  tags = {
    Name = "PAP_Public_SN2"
  }
}

resource "aws_subnet" "PAP_Private_SN1" {
  vpc_id            = aws_vpc.PAP_VPC.id
  cidr_block        = var.private_subnet1_cidr_block
  availability_zone = var.private_subnet1_availabilityzone

  tags = {
    Name = "PAP_Private_SN1"
  }
}

resource "aws_subnet" "PAP_Private_SN2" {
  vpc_id            = aws_vpc.PAP_VPC.id
  cidr_block        = var.private_subnet2_cidr_block
  availability_zone = var.private_subnet2_availabilityzone

  tags = {
    Name = "PAP_Private_SN2"
  }
}

# Custom Internet Gateway
resource "aws_internet_gateway" "PAP_IGW" {
  vpc_id = aws_vpc.PAP_VPC.id

  tags = {
    Name = "PAP_IGW"
  }
}

# Create a public route table
resource "aws_route_table" "PAP_Public_RT" {
  vpc_id = aws_vpc.PAP_VPC.id

  route {
    cidr_block = var.public_routetable_cidr_block
    gateway_id = aws_internet_gateway.PAP_IGW.id
  }

  tags = {
    Name = "PAP_Public_RT"
  }
}

# Public subnet1 attached to public route table
resource "aws_route_table_association" "PAP_Public_RTA1" {
  subnet_id      = aws_subnet.PAP_Public_SN1.id
  route_table_id = aws_route_table.PAP_Public_RT.id
}

# Public subnet2 attached to public route table
resource "aws_route_table_association" "PAP_Public_RTA2" {
  subnet_id      = aws_subnet.PAP_Public_SN2.id
  route_table_id = aws_route_table.PAP_Public_RT.id
}

# EIP for NAT Gateway
resource "aws_eip" "PAP_EIP" {
  vpc        = true
  depends_on = [aws_internet_gateway.PAP_IGW]

  tags = {
    Name = "PAP_EIP"
  }
}

#Custom NAT Gateway
resource "aws_nat_gateway" "PAP_NGW" {
  allocation_id = aws_eip.PAP_EIP.id
  subnet_id     = aws_subnet.PAP_Public_SN1.id

  tags = {
    Name = "PAP_NGW"
  }
}

# Create a private route table
resource "aws_route_table" "PAP_Private_RT" {
  vpc_id = aws_vpc.PAP_VPC.id

  route {
    cidr_block     = var.private_routetable_cidr_block
    nat_gateway_id = aws_nat_gateway.PAP_NGW.id
  }

  tags = {
    Name = "PAP_Private_RT"
  }
}

# Private subnet1 attached to private route table
resource "aws_route_table_association" "PAP_Private_RTA1" {
  subnet_id      = aws_subnet.PAP_Private_SN1.id
  route_table_id = aws_route_table.PAP_Private_RT.id
}

# Private subnet2 attached to private route table
resource "aws_route_table_association" "PAP_Private_RTA2" {
  subnet_id      = aws_subnet.PAP_Private_SN2.id
  route_table_id = aws_route_table.PAP_Private_RT.id
}

# security groups Jenkins
resource "aws_security_group" "PAP_Jenkins_SG" {
  name        = "PAP_Jenkins_Access"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP_VPC.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "JenkinsPort"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PAP_Jenkins_SG"
  }
}

# security groups Docker
resource "aws_security_group" "PAP_Docker_SG" {
  name        = "PAP_Docker_Access"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP_VPC.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DockerPort"
    from_port   = 8085
    to_port     = 8085
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PAP_Docker_SG"
  }
}
# security groups Jenkins
resource "aws_security_group" "PAP_Ansible_SG" {
  name        = "PAP_Ansibles_Access"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP_VPC.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "JenkinsPort"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PAP_Ansible_SG"
  }
}
resource "aws_security_group" "PAP_DB_SG" {
  name        = "PAP_DB_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP_VPC.id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
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
    Name = "PAP_DB_SG"
  }
}

# Instance Keypair
resource "aws_key_pair" "server_keypair" {
  key_name   = var.keypair_name
  public_key = file(var.public_key)
}

# Jenkins Server
resource "aws_instance" "PAP_Jenkins_Host" {
  ami                         = var.PAP-ami
  instance_type               = var.instance_type_Jenkins
  vpc_security_group_ids      = [aws_security_group.PAP_Jenkins_SG.id]
  subnet_id                   = aws_subnet.PAP_Public_SN1.id
  key_name                    = aws_key_pair.server_keypair.key_name
  associate_public_ip_address = true
  user_data                   = <<-EOF
  #!/bin/bash
  sudo yum update -y
  sudo yum upgrade -y
  sudo yum install wget -y
  sudo yum install git -y
  sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
  sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
  sudo yum install jenkins java-1.8.0-openjdk-devel -y --nobest
  sudo systemctl daemon-reload
  sudo systemctl start jenkins
#  sudo yum install -y yum-utils
#  sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
#  sudo yum install docker-ce -y
#  sudo systemctl start docker
  echo "license_key:c32625464fc4f6eae500b09fa88fe0c93434NRAL" | sudo tee -a /etc/newrelic-infra.yml
  sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
  sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
  sudo yum install newrelic-infra -y
#  sudo usermod -aG docker jenkins
#  sudo usermod -aG docker jenkins ec2-user
  sudo yum install maven -y
  sudo service sshd restart
EOF

  tags = {
    Name = "PAP_Jenkins_Host"
  }
}

# Docker Server 
resource "aws_instance" "PAP_Docker_Host" {
  ami                         = var.PAP-ami
  instance_type               = var.instance_type_Docker
  subnet_id                   = aws_subnet.PAP_Public_SN1.id
  vpc_security_group_ids      = [aws_security_group.PAP_Docker_SG.id]
  key_name                    = aws_key_pair.server_keypair.key_name
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo systemctl enable docker
echo Admin123@ | passwd ec2-user --stdin
echo "ansible_admin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
su - ec2-user
echo "license_key: c32625464fc4f6eae500b09fa88fe0c93434NRAL" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo usermod -aG docker ec2-user
sudo hostnamectl set-hostname docker  
EOF

  tags = {
    Name = "PAP_Docker_Host"
  }
}

# Ansible Host
resource "aws_instance" "PAP_Ansible_Host" {
  ami                         = var.PAP-ami
  instance_type               = var.instance_type_Ansible
  subnet_id                   = aws_subnet.PAP_Public_SN1.id
  vpc_security_group_ids      = [aws_security_group.PAP_Ansible_SG.id]
  key_name                    = aws_key_pair.server_keypair.key_name
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3.8 -y
sudo alternatives --set python /usr/bin/python3.8
sudo yum -y install python3-pip
sudo yum install ansible -y
pip3 install ansible --user
sudo chown ec2-user:ec2-user /etc/ansible
sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
sudo yum install sshpass -y
echo "license_key: eu01xxc875439fe02e1835e440a064914a51NRAL" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo su
echo Admin123@ | passwd ec2-user --stdin
echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
sudo chmod -R 700 .ssh/
sudo chown -R ec2-user:ec2-user .ssh/
sudo su - ec2-user -c "ssh-keygen -f ~/.ssh/ansiblekeypair_rsa -t rsa -N ''"
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sudo su - ec2-user -c 'sshpass -p "Admin123@" ssh-copy-id -i /home/ec2-user/.ssh/ansiblekeypair_rsa.pub ec2-user@${data.aws_instance.PAP_Docker_Host.public_ip} -p 22'
ssh-copy-id -i /home/ec2-user/.ssh/ansiblekeypair_rsa.pub ec2-user@localhost -p 22
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo usermod -aG docker ec2-user
cd /etc
sudo chown ec2-user:ec2-user hosts
cat <<EOT>> /etc/ansible/hosts
localhost ansible_connection=local
[docker_host]
${data.aws_instance.PAP_Docker_Host.public_ip}  ansible_ssh_private_key_file=/home/ec2-user/.ssh/ansiblekeypair_rsa
EOT
sudo mkdir /opt/docker
sudo chown -R ec2-user:ec2-user /opt/docker
sudo chmod -R 700 /opt/docker
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
# pull tomcat image from docker hub
FROM tomcat
FROM openjdk:8-jre-slim
#copy war file on the container
COPY spring-petclinic-2.4.2.war app/
WORKDIR app/
RUN pwd
RUN ls -al
ENTRYPOINT [ "java", "-jar", "spring-petclinic-2.4.2.war", "--server.port=8085"]
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
     command: docker run -it -d --name pet-adoption-container -p 8080:8085 cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
cat << EOT > /opt/docker/newrelic.yml
---
 - hosts: docker
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
                     -e NRIA_LICENSE_KEY=eu01xxc875439fe02e1835e440a064914a51NRAL \
                     newrelic/infrastructure:latest
EOT
  EOF
  tags = {
    Name = "PAP_Ansible_Host"
  }
}

# Route 53 Hosted Zone
resource "aws_route53_zone" "PAP_zone" {
  name          = var.domain_name
  force_destroy = true
}

# Route 53 A Record
resource "aws_route53_record" "PAP_domain" {
  zone_id = aws_route53_zone.PAP_zone.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = "300" # (Use when not associating route53 to a load balancer)
  records = [aws_instance.PAP_Jenkins.public_ip]
  # alias {
  #   name                   = aws_lb.PAP-alb.dns_name
  #    zone_id                = aws_lb.PAP-alb.zone_id
  #    evaluate_target_health = false
  #  }
}