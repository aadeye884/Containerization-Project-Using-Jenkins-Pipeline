output "Jenkins_public_ip" {
  value = aws_instance.PAP_Jenkins_Host.public_ip
}

output "Docker_public_ip" {
  value = aws_instance.PAP_Docker_Host.public_ip
}

output "Ansible_public_ip" {
  value = aws_instance.PAP_Ansible_Host.public_ip
}

output "name_servers" {
  value = aws_route53_record.PAP_domain.name
}

output "ns_records" {
  value = aws_route53_zone.PAP_zone.name_servers
}