/*
  # Create admin keys for testing

  1. New Data
    - Insert test admin keys for development
    - These keys can be used to grant admin access to users

  2. Security
    - Keys are marked as unused initially
    - Once used, they cannot be reused
*/

-- Insert some test admin keys
INSERT INTO admin_keys (key_code, is_used) VALUES 
('ADMIN-2024-001', false),
('ADMIN-2024-002', false),
('ADMIN-2024-003', false),
('AGDA-DJ32-636T', false),
('SUPER-ADMIN-KEY', false)
ON CONFLICT (key_code) DO NOTHING;