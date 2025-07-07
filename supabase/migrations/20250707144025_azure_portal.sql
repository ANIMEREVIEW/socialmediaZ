/*
  # Complete RLS Policy Fix for Posts Table

  1. Security Changes
    - Drop all existing problematic RLS policies
    - Create simplified, working RLS policies
    - Fix user context handling
    - Ensure proper permissions for all operations

  2. Performance Improvements
    - Add missing indexes
    - Optimize policy queries
*/

-- Disable RLS temporarily to fix policies
ALTER TABLE posts DISABLE ROW LEVEL SECURITY;

-- Drop all existing policies
DROP POLICY IF EXISTS "Users can create posts" ON posts;
DROP POLICY IF EXISTS "Users can update their own posts" ON posts;
DROP POLICY IF EXISTS "Users can view their own posts" ON posts;
DROP POLICY IF EXISTS "Anyone can view approved posts" ON posts;
DROP POLICY IF EXISTS "Admins can view all posts" ON posts;
DROP POLICY IF EXISTS "Admins can update all posts" ON posts;
DROP POLICY IF EXISTS "Admins can delete all posts" ON posts;

-- Create a simple function to get current user ID
CREATE OR REPLACE FUNCTION auth.uid() RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::json->>'sub',
    current_setting('app.current_user_id', true)
  )::text;
$$ LANGUAGE sql STABLE;

-- Create a function to check if user is admin
CREATE OR REPLACE FUNCTION is_admin(user_id_param text DEFAULT NULL) 
RETURNS boolean AS $$
  SELECT COALESCE(
    (SELECT is_admin FROM user_profiles 
     WHERE user_profiles.user_id = COALESCE(user_id_param, auth.uid())),
    false
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Re-enable RLS
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

-- Create new, simplified policies
CREATE POLICY "Enable read for approved posts" ON posts
  FOR SELECT USING (status = 'approved');

CREATE POLICY "Enable read for own posts" ON posts
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Enable read for admins" ON posts
  FOR SELECT USING (is_admin());

CREATE POLICY "Enable insert for authenticated users" ON posts
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "Enable update for own posts" ON posts
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "Enable update for admins" ON posts
  FOR UPDATE USING (is_admin());

CREATE POLICY "Enable delete for admins" ON posts
  FOR DELETE USING (is_admin());

-- Fix user_profiles policies
ALTER TABLE user_profiles DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view all profiles" ON user_profiles;
DROP POLICY IF EXISTS "Users can insert their own profile" ON user_profiles;
DROP POLICY IF EXISTS "Users can update their own profile" ON user_profiles;

ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read for all profiles" ON user_profiles
  FOR SELECT USING (true);

CREATE POLICY "Enable insert for own profile" ON user_profiles
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "Enable update for own profile" ON user_profiles
  FOR UPDATE USING (user_id = auth.uid());

-- Fix admin_keys policies
ALTER TABLE admin_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anyone can view unused admin keys" ON admin_keys;
DROP POLICY IF EXISTS "Anyone can update admin keys for redemption" ON admin_keys;

ALTER TABLE admin_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read for unused keys" ON admin_keys
  FOR SELECT USING (is_used = false);

CREATE POLICY "Enable update for key redemption" ON admin_keys
  FOR UPDATE USING (true);

-- Update the user context function
CREATE OR REPLACE FUNCTION set_user_context(user_id_param text)
RETURNS void AS $$
BEGIN
  PERFORM set_config('app.current_user_id', user_id_param, true);
  PERFORM set_config('request.jwt.claims', json_build_object('sub', user_id_param)::text, true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Update the admin key redemption function
CREATE OR REPLACE FUNCTION redeem_admin_key(key_code_param text, user_id_param text)
RETURNS boolean AS $$
DECLARE
  key_record admin_keys%ROWTYPE;
BEGIN
  -- Set user context
  PERFORM set_user_context(user_id_param);
  
  -- Get the key record
  SELECT * INTO key_record FROM admin_keys 
  WHERE key_code = key_code_param AND is_used = false;
  
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  
  -- Mark key as used
  UPDATE admin_keys 
  SET is_used = true, used_by = user_id_param, used_at = now()
  WHERE id = key_record.id;
  
  -- Make user admin
  UPDATE user_profiles 
  SET is_admin = true 
  WHERE user_id = user_id_param;
  
  -- Insert profile if it doesn't exist
  INSERT INTO user_profiles (user_id, username, is_admin)
  VALUES (user_id_param, 'Admin User', true)
  ON CONFLICT (user_id) DO UPDATE SET is_admin = true;
  
  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions
GRANT EXECUTE ON FUNCTION auth.uid() TO public;
GRANT EXECUTE ON FUNCTION is_admin(text) TO public;
GRANT EXECUTE ON FUNCTION set_user_context(text) TO public;
GRANT EXECUTE ON FUNCTION redeem_admin_key(text, text) TO public;

-- Add performance indexes
CREATE INDEX IF NOT EXISTS idx_posts_user_status ON posts(user_id, status);
CREATE INDEX IF NOT EXISTS idx_posts_status_created ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_profiles_admin ON user_profiles(user_id, is_admin);
CREATE INDEX IF NOT EXISTS idx_admin_keys_code_used ON admin_keys(key_code, is_used);

-- Ensure admin keys exist
INSERT INTO admin_keys (key_code, is_used) VALUES 
  ('ADMIN-2025-001', false),
  ('ADMIN-2025-002', false),
  ('ADMIN-2025-003', false),
  ('X145-GTHY-LKHA', false),
  ('SUPER-ADMIN-KEY', false),
  ('TEST-ADMIN-123', false)
ON CONFLICT (key_code) DO NOTHING;