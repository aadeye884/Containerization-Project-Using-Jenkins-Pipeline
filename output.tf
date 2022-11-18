output "Jenkins_public_ip" {
  value = aws_instance.PAPUST_Jenkins_Server.public_ip
}
output "Docker_public_ip" {
  value = aws_instance.PAPUST_Docker_host.public_ip
}
output "Ansible_public_ip" {
  value = aws_instance.PAPUST_Ansible_host.public_ip
}
output "name_servers" {
  value = aws_route53_record.PAPUST_Website.name
}
output "ns_records" {
  value = aws_route53_zone.papust_zone.name_servers
}