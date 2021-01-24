output "instance_ip" {
    description = "The ephmeral IP address assigned to the launched GCE Instance."
    value       = google_compute_instance.test.network_interface[0].access_config[0].nat_ip
}
