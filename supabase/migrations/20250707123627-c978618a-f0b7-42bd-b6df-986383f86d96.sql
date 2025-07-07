-- Insert the 4 admin codes into admin_keys table
INSERT INTO public.admin_keys (key_code, is_used) VALUES 
('X145-GTHY-LKHA', false),
('AGDA-DJ32-636T', false),
('SHIN-0005-CHAN', false),
('ASH&-PIKA-0024', false);

-- Ensure posts are set to pending by default and only approved posts are visible
UPDATE public.posts SET status = 'pending' WHERE status IS NULL;